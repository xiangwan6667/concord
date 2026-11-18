use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use concord_common::intercept::{ConnInterceptor, InterceptFlow, Offer, UpstreamDialer};
use concord_common::sync::lock;
use concord_common::{BoxStream, PeekedStream};
use concord_tls::{ClientConfig, TlsError, TrustStore};
use rustls::AlertDescription;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::time::{timeout, timeout_at};
use tokio_rustls::TlsAcceptor;

use crate::ca::{Authority, Ca};
use crate::capture::CaptureStore;
use crate::clienthello::{ClientHello, Peeker, RECORD_TYPE_HANDSHAKE, peek_client_hello};
use crate::config::Config;
use crate::cron::LocalClock;
use crate::limits::{PRESSURE_RELAY, Pressure, ScriptGate};
use crate::script::{Script, ScriptDial, ScriptError, ScriptHost, ScriptInvocation, ScriptResult};
use crate::session::{Scheme, Session};
use crate::target::{HTTP_PORT, HTTPS_PORT};
use crate::task::Tasks;

/// mihomo's sniffer waits this long for a connection's first byte, then gives the rest of
/// its reads one fresh window as long.
pub(crate) const SNIFF_WINDOW: Duration = Duration::from_secs(1);
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const QUIC_MEMORY: Duration = Duration::from_secs(60);
const QUIC_CACHE_SIZE: usize = 4096;
const TASK_CONCURRENCY: usize = 2;
const HTTP_METHODS: [&[u8]; 8] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
];

pub(crate) const ALPN_HTTP1: &str = "http/1.1";
pub(crate) const ALPN_H2: &str = "h2";

/// What every engine of a process shares: the CA, the captures and the host's
/// services. It outlives the configs.
pub(crate) struct Shared {
    pub authority: Arc<Authority>,
    pub captures: Arc<CaptureStore>,
    pub pressure: Arc<Pressure>,
    pub trust: Arc<ArcSwap<TrustStore>>,
    pub dialer: Arc<dyn UpstreamDialer>,
    pub scripts: Arc<ScriptHost>,
    pub clock: Arc<dyn LocalClock>,
}

#[derive(Default)]
struct QuicCache {
    drops: HashMap<(IpAddr, u16), (bool, Instant)>,
}

impl QuicCache {
    fn get(&self, key: &(IpAddr, u16)) -> Option<bool> {
        self.drops
            .get(key)
            .filter(|(_, at)| at.elapsed() < QUIC_MEMORY)
            .map(|(drop, _)| *drop)
    }

    fn set(&mut self, key: (IpAddr, u16), drop: bool) {
        if self.drops.len() >= QUIC_CACHE_SIZE {
            self.drops.retain(|_, (_, at)| at.elapsed() < QUIC_MEMORY);
            if self.drops.len() >= QUIC_CACHE_SIZE {
                self.drops.clear();
            }
        }
        self.drops.insert(key, (drop, Instant::now()));
    }
}

pub(crate) struct Core {
    pub config: Config,
    pub shared: Arc<Shared>,
    pub bodies: Arc<Semaphore>,
    pub session_gate: ScriptGate,
    pub task_gate: ScriptGate,
    pub handle: Handle,
    sessions: AtomicUsize,
    quic: Mutex<QuicCache>,
    trust: Arc<TrustStore>,
    client_h2: OnceLock<Result<Arc<ClientConfig>, Arc<TlsError>>>,
    client_h1: OnceLock<Result<Arc<ClientConfig>, Arc<TlsError>>>,
    unverified_h2: OnceLock<Result<Arc<ClientConfig>, Arc<TlsError>>>,
    unverified_h1: OnceLock<Result<Arc<ClientConfig>, Arc<TlsError>>>,
}

pub(crate) struct SessionSlot {
    core: Arc<Core>,
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        self.core.sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn domain_of(flow: &InterceptFlow) -> &str {
    flow.host.as_deref().unwrap_or_default()
}

pub(crate) fn host_of(flow: &InterceptFlow) -> String {
    match (domain_of(flow), flow.dst_ip) {
        ("", Some(ip)) => ip.to_string(),
        (domain, _) => domain.to_string(),
    }
}

fn looks_like_http(data: &[u8]) -> bool {
    HTTP_METHODS.iter().any(|method| data.starts_with(method))
}

fn refused_certificate(err: &io::Error) -> bool {
    let Some(rustls::Error::AlertReceived(alert)) = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return false;
    };
    matches!(
        alert,
        AlertDescription::BadCertificate
            | AlertDescription::UnsupportedCertificate
            | AlertDescription::CertificateRevoked
            | AlertDescription::CertificateExpired
            | AlertDescription::CertificateUnknown
            | AlertDescription::UnknownCA
    )
}

impl Core {
    pub fn client_protocols(&self) -> &'static [&'static str] {
        if self.config.h2 {
            &[ALPN_H2, ALPN_HTTP1]
        } else {
            &[ALPN_HTTP1]
        }
    }

    /// The TLS client for a server, which checks its certificate unless the switch or the
    /// list of hosts it is skipped for says otherwise.
    pub fn client_config(
        &self,
        protocols: &[&str],
        host: &str,
        port: u16,
    ) -> io::Result<Arc<ClientConfig>> {
        let skip = self.config.skip_server_cert_verify
            || self.config.skip_verify_hosts.matches(host, port);
        let slot = match (protocols.contains(&ALPN_H2), skip) {
            (true, false) => &self.client_h2,
            (false, false) => &self.client_h1,
            (true, true) => &self.unverified_h2,
            (false, true) => &self.unverified_h1,
        };
        slot.get_or_init(|| {
            concord_tls::http_client_config(self.trust.clone(), skip, protocols).map_err(Arc::new)
        })
        .clone()
        .map_err(io::Error::other)
    }

    /// The CA decrypted connections are signed with, `None` while TLS is not to be decrypted.
    pub fn authority(&self) -> Option<Arc<Ca>> {
        if !self.config.decrypt_tls {
            return None;
        }
        let ca = self.shared.authority.available()?;
        if !self.config.ca_fingerprint.is_empty() && ca.fingerprint() != self.config.ca_fingerprint
        {
            return None;
        }
        ca.set_cache_size(self.config.limits.certificate_cache);
        Some(ca)
    }

    /// Runs for every TCP connection, so it has to be cheap. Without TLS
    /// decryption only plain HTTP is offered, which never runs on 443.
    pub fn match_tcp(&self, flow: &InterceptFlow) -> bool {
        if flow.is_inner()
            || self.shared.pressure.level() >= PRESSURE_RELAY
            || !self.config.sources.allows(flow.meta.src.ip())
        {
            return false;
        }
        let hosts = &self.config.hosts;
        let port = flow.port;
        let domain = domain_of(flow);
        if port == HTTP_PORT && self.config.plain_http {
            return match (domain, flow.dst_ip) {
                ("", Some(ip)) => !hosts.excludes(&ip.to_string(), port),
                (domain, _) => !hosts.excludes(domain, port),
            };
        }
        if port == HTTPS_PORT && self.authority().is_none() {
            return false;
        }
        if !domain.is_empty() {
            return if flow.sniffed {
                hosts.matches_sniffed(domain, port)
            } else {
                hosts.matches(domain, port)
            };
        }
        let Some(ip) = flow.dst_ip else {
            return false;
        };
        port == HTTPS_PORT && hosts.includes_any() || hosts.matches(&ip.to_string(), port)
    }

    pub fn drop_quic(&self, flow: &InterceptFlow) -> bool {
        if !self.config.auto_quic_block
            || self.shared.pressure.level() >= PRESSURE_RELAY
            || self.authority().is_none()
            || !self.config.sources.allows(flow.meta.src.ip())
        {
            return false;
        }
        if flow.host.is_some() || flow.dst_ip.is_none() {
            return self.config.hosts.matches(domain_of(flow), flow.port);
        }
        let Some(ip) = flow.dst_ip else {
            return false;
        };
        let key = (ip, flow.port);
        let cached = lock(&self.quic).get(&key);
        if let Some(drop) = cached {
            return drop;
        }
        let host = host_of(flow);
        let drop = self.config.hosts.matches(&host, flow.port);
        {
            let mut cache = lock(&self.quic);
            cache.set(key, drop);
        }
        if drop {
            tracing::debug!(
                "[MITM] drop UDP to {host}:{}, its client falls back to TCP",
                flow.port
            );
        }
        drop
    }

    #[cfg(test)]
    pub(crate) fn open_sessions(&self) -> usize {
        self.sessions.load(Ordering::Relaxed)
    }

    /// Leaves a connection past the session limit to the tunnel.
    pub fn enter_session(self: &Arc<Self>) -> Option<SessionSlot> {
        let limit = self.config.limits.max_sessions;
        if self.sessions.fetch_add(1, Ordering::Relaxed) + 1 > limit && limit > 0 {
            self.sessions.fetch_sub(1, Ordering::Relaxed);
            tracing::debug!("[MITM] {limit} sessions are open, a new one is relayed as is");
            return None;
        }
        Some(SessionSlot { core: self.clone() })
    }

    pub async fn invoke(
        &self,
        gate: &ScriptGate,
        script: &Script,
        mut invocation: ScriptInvocation,
        dial: Arc<dyn ScriptDial>,
    ) -> Result<ScriptResult, ScriptError> {
        let deadline = tokio::time::Instant::now() + script.timeout;
        let Some(_slot) = gate.enter(script.timeout).await else {
            return Err(ScriptError("every script slot stayed taken".to_string()));
        };
        invocation.name.clone_from(&script.name);
        invocation.path.clone_from(&script.path);
        invocation.kind = script.kind.name().to_string();
        invocation.argument.clone_from(&script.argument);
        invocation.binary_body = script.binary_body;
        invocation.max_body_size = self.config.limits.max_body_size;
        invocation.memory_limit = self.config.limits.script_memory;
        invocation.dial = dial;
        match timeout_at(deadline, script.program.run(invocation)).await {
            Ok(result) => result,
            Err(_) => Err(ScriptError("the script ran out of time".to_string())),
        }
    }
}

/// The engine of one `mitm` section. The host keeps it while the section stays the same.
pub struct MitmEngine {
    pub(crate) core: Arc<Core>,
    pub(crate) tasks: Arc<Tasks>,
}

impl MitmEngine {
    pub(crate) fn new(config: Config, shared: Arc<Shared>, handle: Handle) -> MitmEngine {
        if config.enable && config.decrypt_tls && !config.ca_fingerprint.is_empty() {
            let stale = shared
                .authority
                .available()
                .is_none_or(|ca| ca.fingerprint() != config.ca_fingerprint);
            if stale && let Err(err) = shared.authority.reload() {
                tracing::warn!("[MITM] reading the CA again: {err}");
            }
        }
        shared
            .authority
            .set_cache_size(config.limits.certificate_cache);
        shared.captures.limit(
            config.limits.capture_entries,
            config.limits.capture_bytes,
            config.limits.max_body_size,
        );
        let limits = config.limits;
        let trust = shared.trust.load_full();
        let core = Arc::new(Core {
            config,
            shared,
            trust,
            bodies: Arc::new(Semaphore::new(
                usize::try_from(limits.body_buffer).unwrap_or(1),
            )),
            session_gate: ScriptGate::new(limits.script_concurrency),
            task_gate: ScriptGate::new(TASK_CONCURRENCY),
            handle,
            sessions: AtomicUsize::new(0),
            quic: Mutex::default(),
            client_h2: OnceLock::new(),
            client_h1: OnceLock::new(),
            unverified_h2: OnceLock::new(),
            unverified_h1: OnceLock::new(),
        });
        MitmEngine {
            core,
            tasks: Arc::default(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.core.config
    }

    pub(crate) fn trusts(&self, store: &Arc<TrustStore>) -> bool {
        Arc::ptr_eq(&self.core.trust, store)
    }

    pub fn match_tcp(&self, flow: &InterceptFlow) -> bool {
        self.core.match_tcp(flow)
    }

    async fn offer_tls(
        &self,
        flow: &InterceptFlow,
        peeker: Peeker,
        hello: ClientHello,
        ca: Arc<Ca>,
    ) -> Offer {
        let core = &self.core;
        let mut flow = flow.clone();
        let server_name = if hello.server_name.is_empty() {
            host_of(&flow)
        } else {
            if domain_of(&flow).is_empty() {
                flow.host = Some(hello.server_name.as_str().into());
                flow.sniffed = true;
            }
            hello.server_name.clone()
        };
        if !core.config.hosts.matches_sniffed(&server_name, flow.port) {
            return declined(peeker);
        }
        let protocols = core.client_protocols();
        if !hello.protocols.is_empty()
            && !hello
                .protocols
                .iter()
                .any(|offered| protocols.contains(&offered.as_str()))
        {
            tracing::debug!(
                "[MITM] {server_name} offers {:?} only, relayed as is",
                hello.protocols
            );
            return declined(peeker);
        }
        let Some(_slot) = core.enter_session() else {
            return declined(peeker);
        };
        let session = Session::new(
            core.clone(),
            Scheme::Https,
            server_name.clone(),
            flow.clone(),
        );
        if let Err(err) = session.connect().await {
            tracing::debug!(
                "[MITM] {} --> {server_name} is relayed as is: {err}",
                flow.meta.src
            );
            return declined(peeker);
        }
        let config = match ca.server_config(&server_name, protocols) {
            Ok(config) => config,
            Err(err) => {
                tracing::debug!("[MITM] no certificate for {server_name}: {err}");
                session.release();
                return Offer::Taken;
            }
        };
        let io = PeekedStream::new(peeker.buf, peeker.stream);
        let accepted =
            tokio::time::timeout(ACCEPT_TIMEOUT, TlsAcceptor::from(config).accept(io)).await;
        match accepted {
            Ok(Ok(tls)) => {
                session.decrypted();
                let h2 = tls.get_ref().1.alpn_protocol() == Some(ALPN_H2.as_bytes());
                session.serve(tls, h2, Some(ca.retired().clone())).await;
            }
            Ok(Err(err)) if refused_certificate(&err) => {
                session.refused();
                tracing::warn!(
                    "[MITM] {} refused the certificate for {server_name}: install the CA, or exclude the host if the app pins its certificate",
                    flow.meta.src
                );
                session.release();
            }
            Ok(Err(err)) => {
                tracing::debug!(
                    "[MITM] handshake with {} for {server_name} failed: {err}",
                    flow.meta.src
                );
                session.release();
            }
            Err(_) => {
                tracing::debug!(
                    "[MITM] handshake with {} for {server_name} timed out",
                    flow.meta.src
                );
                session.release();
            }
        }
        Offer::Taken
    }
}

fn declined(peeker: Peeker) -> Offer {
    Offer::Declined {
        stream: peeker.stream,
        head: peeker.buf,
    }
}

#[async_trait]
impl ConnInterceptor for MitmEngine {
    async fn offer(&self, flow: &InterceptFlow, stream: BoxStream, head: Vec<u8>) -> Offer {
        let core = &self.core;
        let mut peeker = Peeker::new(stream, head);
        if !core.match_tcp(flow) {
            return declined(peeker);
        }
        if !matches!(timeout(SNIFF_WINDOW, peeker.fill(1)).await, Ok(Ok(()))) {
            return declined(peeker);
        }
        let deadline = tokio::time::Instant::now() + SNIFF_WINDOW;
        if peeker.buf.first() == Some(&RECORD_TYPE_HANDSHAKE) {
            let Some(ca) = core.authority() else {
                return declined(peeker);
            };
            return match timeout_at(deadline, peek_client_hello(&mut peeker)).await {
                Ok(Ok(hello)) => self.offer_tls(flow, peeker, hello, ca).await,
                Ok(Err(err)) => {
                    tracing::debug!(
                        "[MITM] {} --> {} is relayed as is: {err}",
                        flow.meta.src,
                        flow.meta.dst
                    );
                    declined(peeker)
                }
                Err(_) => declined(peeker),
            };
        }
        let _ = timeout_at(deadline, peeker.fill_up_to(8)).await;
        if !looks_like_http(&peeker.buf) {
            return declined(peeker);
        }
        let Some(_slot) = core.enter_session() else {
            return declined(peeker);
        };
        let session = Session::new(core.clone(), Scheme::Http, host_of(flow), flow.clone());
        session
            .serve(PeekedStream::new(peeker.buf, peeker.stream), false, None)
            .await;
        Offer::Taken
    }

    fn drop_quic(&self, flow: &InterceptFlow) -> bool {
        self.core.drop_quic(flow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_methods_are_told_by_their_first_bytes() {
        assert!(looks_like_http(b"GET / HTTP/1.1"));
        assert!(looks_like_http(b"OPTIONS *"));
        assert!(!looks_like_http(b"SSH-2.0-OpenSSH_9.9\r\n"));
        assert!(!looks_like_http(b"GE"));
    }

    #[test]
    fn the_quic_cache_forgets_and_stays_bounded() {
        let mut cache = QuicCache::default();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(cache.get(&(ip, 443)), None);
        cache.set((ip, 443), true);
        assert_eq!(cache.get(&(ip, 443)), Some(true));
        for port in 0..(QUIC_CACHE_SIZE as u16 + 10) {
            cache.set((ip, port), false);
        }
        assert!(cache.drops.len() <= QUIC_CACHE_SIZE);
    }
}
