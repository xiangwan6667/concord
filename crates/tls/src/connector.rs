use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

use concord_common::BoxStream;
use concord_common::sync::lock;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;

use crate::boring_backend::BoringConnector;
use crate::client_auth::load_client_auth;
use crate::conn::TlsConn;
use crate::ech::{ByList, retry_list};
use crate::fingerprints::ClientFingerprint;
use crate::policy::CertPolicy;
use crate::reality::{RealityClient, SessionIdSealer};
use crate::rustls_backend;
use crate::{EchLookup, TlsError, TlsOptions, TrustStore};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reads {
    Aligned,
    Buffered,
    Whole,
}

/// Connectors are built per node, and a profile can give thousands of nodes the same value.
fn warn_once(requested: ClientFingerprint, warning: &str) {
    static WARNED: Mutex<Vec<ClientFingerprint>> = Mutex::new(Vec::new());
    let mut warned = lock(&WARNED);
    if !warned.contains(&requested) {
        warned.push(requested);
        tracing::warn!("client-fingerprint {requested}: {warning}");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Rustls,
    Boring,
    Reality,
    Jls,
}

enum Engine {
    Rustls(Arc<ClientConfig>),
    Boring(BoringConnector),
    Reality(RealityClient),
    Jls(RealityClient),
}

/// Built once per node; `connect` is the only per-connection work.
pub struct TlsConnector {
    server_name: Option<String>,
    engine: Engine,
    fingerprint: Option<ClientFingerprint>,
    ech: Option<Box<LazyEch>>,
    retry: EchRetry,
}

/// What a connector with an `ECHConfigList` needs to be rebuilt with the list a server answers
/// a rejection with, and the connector built from the last such answer; a rejection of that
/// one replaces it, as each sing-box rejection replaces the list. A looked-up list is
/// built into its own connector (`ByList`), so a changed lookup answer drops the retry list
/// with it; a configured list keeps it until the node is rebuilt.
#[derive(Default)]
struct EchRetry {
    source: Option<Box<(TlsOptions, Arc<TrustStore>)>>,
    adopted: Mutex<Option<Arc<TlsConnector>>>,
}

/// A rejected ECH offer whose answer is now this connector's list: the error to dial again on.
struct Retrying(io::Error);

impl fmt::Debug for Retrying {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Retrying {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for Retrying {}

/// A node with no `config` in its `ech-opts`: each handshake asks for the list, and the
/// connector for it is built once per distinct answer.
struct LazyEch {
    lookup: Arc<dyn EchLookup>,
    options: TlsOptions,
    trust: Arc<TrustStore>,
    built: ByList<TlsConnector>,
}

impl TlsConnector {
    pub fn new(options: TlsOptions, trust: Arc<TrustStore>) -> Result<Self, TlsError> {
        match options.ech_lookup.clone().filter(|_| options.jls.is_none()) {
            Some(lookup) if options.ech_config_list.is_none() => {
                let options = TlsOptions {
                    ech_lookup: None,
                    ..options
                };
                let mut connector = Self::new(options.clone(), trust.clone())?;
                connector.ech = Some(Box::new(LazyEch {
                    lookup,
                    options,
                    trust,
                    built: ByList::new(),
                }));
                Ok(connector)
            }
            _ => Self::fixed(options, trust),
        }
    }

    fn fixed(options: TlsOptions, trust: Arc<TrustStore>) -> Result<Self, TlsError> {
        let retry = EchRetry {
            source: options
                .ech_config_list
                .is_some()
                .then(|| Box::new((options.clone(), trust.clone()))),
            adopted: Mutex::new(None),
        };
        let server_name = options.server_name.clone().filter(|name| !name.is_empty());

        if options.jls.is_some() {
            if options.reality.is_some() {
                return Err(TlsError::Config(
                    "security modes are mutually exclusive: JLS, REALITY".into(),
                ));
            }
            return Ok(Self {
                server_name,
                engine: Engine::Jls(RealityClient::jls(&options, trust)?),
                fingerprint: options.client_fingerprint,
                ech: None,
                retry: EchRetry::default(),
            });
        }

        let policy = Arc::new(CertPolicy::new(&options, trust.clone())?);
        let client_auth = load_client_auth(&options)?;

        if let Some(reality) = options.reality.clone() {
            if client_auth.is_some() {
                return Err(TlsError::Config(
                    "REALITY does not support client certificates".into(),
                ));
            }
            // mihomo's REALITY hello carries the uTLS preset's ALPN whatever the node or
            // its network asks for.
            let client = RealityClient::new(
                reality,
                options.client_fingerprint,
                Vec::new(),
                trust,
                &options.tasks,
            )?;
            return Ok(Self {
                server_name,
                engine: Engine::Reality(client),
                fingerprint: options.client_fingerprint,
                ech: None,
                retry: EchRetry::default(),
            });
        }

        let requested = options
            .client_fingerprint
            .map(ClientFingerprint::resolve_random)
            .filter(|fp| *fp != ClientFingerprint::None);
        if let Some(requested) = requested {
            let (used, warning) = requested.effective();
            if let Some(warning) = warning {
                warn_once(requested, warning);
            }
            let spec = used
                .spec()
                .ok_or_else(|| TlsError::Config(format!("no hello for fingerprint {used}")))?;
            let connector = BoringConnector::new(
                spec,
                policy,
                &options.alpn,
                client_auth,
                options.ech_config_list.clone(),
            )?;
            return Ok(Self {
                server_name,
                engine: Engine::Boring(connector),
                fingerprint: Some(used),
                ech: None,
                retry,
            });
        }

        let alpn = options
            .alpn
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect();
        let config = rustls_backend::client_config(
            policy,
            alpn,
            client_auth,
            false,
            options.ech_config_list.as_deref(),
        )?;
        Ok(Self {
            server_name,
            engine: Engine::Rustls(config),
            fingerprint: None,
            ech: None,
            retry,
        })
    }

    pub fn tls12_only(options: TlsOptions, trust: Arc<TrustStore>) -> Result<Self, TlsError> {
        let policy = Arc::new(CertPolicy::new(&options, trust)?);
        let client_auth = load_client_auth(&options)?;
        let alpn = options
            .alpn
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect();
        let config = rustls_backend::client_config_versions(
            policy,
            alpn,
            client_auth,
            &[&rustls::version::TLS12],
            None,
        )?;
        Ok(Self {
            server_name: options.server_name.filter(|name| !name.is_empty()),
            engine: Engine::Rustls(config),
            fingerprint: None,
            ech: None,
            retry: EchRetry::default(),
        })
    }

    pub fn backend(&self) -> Backend {
        match self.engine {
            Engine::Rustls(_) => Backend::Rustls,
            Engine::Boring(_) => Backend::Boring,
            Engine::Reality(_) => Backend::Reality,
            Engine::Jls(_) => Backend::Jls,
        }
    }

    /// The fingerprint the hello follows, `None` for the plain rustls hello.
    pub fn fingerprint(&self) -> Option<ClientFingerprint> {
        self.fingerprint
    }

    fn name_text<'a>(&'a self, sni_fallback: &'a str) -> &'a str {
        self.server_name
            .as_deref()
            .unwrap_or(sni_fallback)
            .trim_matches(['[', ']'])
    }

    fn resolve_name(&self, sni_fallback: &str) -> Result<ServerName<'static>, TlsError> {
        let text = self.name_text(sni_fallback);
        ServerName::try_from(text.to_owned())
            .map_err(|_| TlsError::Config(format!("invalid TLS server name {text:?}")))
    }

    /// `sni_fallback` is the dial target's host, used when the node sets no
    /// server name; an IP literal sends no SNI and is checked against the
    /// certificate's IP addresses.
    pub async fn connect(&self, io: BoxStream, sni_fallback: &str) -> io::Result<TlsConn> {
        self.connect_as(io, sni_fallback, Reads::Aligned).await
    }

    /// Like `connect`, for a caller that never takes the transport back: the
    /// TLS layer reads as much as it wants from it per call.
    pub async fn connect_unaligned(
        &self,
        io: BoxStream,
        sni_fallback: &str,
    ) -> io::Result<TlsConn> {
        self.connect_as(io, sni_fallback, Reads::Buffered).await
    }

    /// Like `connect_unaligned`, with rustls on the native record engine from the start: for
    /// a caller that keeps the connection as its data path, whole like an HTTP/2 client or
    /// split, where each half then owns its direction's records and what was read ahead.
    pub async fn connect_whole(&self, io: BoxStream, sni_fallback: &str) -> io::Result<TlsConn> {
        self.connect_as(io, sni_fallback, Reads::Whole).await
    }

    /// Dials a transport connection and secures it. A server that rejects ECH and answers with a
    /// list to retry gets one more connection from `dial` with that list, which stays the
    /// connector's list for later connections; a second rejection is the error.
    pub async fn connect_dialing<D, F>(&self, dial: D, sni_fallback: &str) -> io::Result<TlsConn>
    where
        D: FnMut() -> F,
        F: Future<Output = io::Result<BoxStream>>,
    {
        self.dialing_as(dial, sni_fallback, Reads::Aligned).await
    }

    /// `connect_dialing` for a caller that keeps the connection whole, like `connect_whole`.
    pub async fn connect_whole_dialing<D, F>(
        &self,
        dial: D,
        sni_fallback: &str,
    ) -> io::Result<TlsConn>
    where
        D: FnMut() -> F,
        F: Future<Output = io::Result<BoxStream>>,
    {
        self.dialing_as(dial, sni_fallback, Reads::Whole).await
    }

    async fn dialing_as<D, F>(
        &self,
        mut dial: D,
        sni_fallback: &str,
        reads: Reads,
    ) -> io::Result<TlsConn>
    where
        D: FnMut() -> F,
        F: Future<Output = io::Result<BoxStream>>,
    {
        let mut retried = false;
        loop {
            match self.connect_as(dial().await?, sni_fallback, reads).await {
                Err(err) if !retried && is_retrying(&err) => retried = true,
                result => return result,
            }
        }
    }

    async fn connect_as(
        &self,
        io: BoxStream,
        sni_fallback: &str,
        reads: Reads,
    ) -> io::Result<TlsConn> {
        let name = self.resolve_name(sni_fallback)?;
        if let Some(lazy) = &self.ech {
            let inner = lazy
                .built
                .get(&*lazy.lookup, self.name_text(sni_fallback), |list| {
                    Self::fixed(
                        TlsOptions {
                            ech_config_list: Some(list.to_vec()),
                            ..lazy.options.clone()
                        },
                        lazy.trust.clone(),
                    )
                    .map(Arc::new)
                })
                .await?;
            return inner.connect_with(io, name, reads).await;
        }
        self.connect_with(io, name, reads).await
    }

    async fn connect_with(
        &self,
        io: BoxStream,
        name: ServerName<'static>,
        reads: Reads,
    ) -> io::Result<TlsConn> {
        let adopted = lock(&self.retry.adopted).clone();
        let connector = adopted.as_deref().unwrap_or(self);
        connector
            .connect_engine(io, name, reads)
            .await
            .map_err(|err| self.adopt_retry_list(err))
    }

    fn adopt_retry_list(&self, err: io::Error) -> io::Error {
        let Some(source) = &self.retry.source else {
            return err;
        };
        let Some(list) = retry_list(&err) else {
            return err;
        };
        let (options, trust) = source.as_ref();
        let options = TlsOptions {
            ech_config_list: Some(list),
            ..options.clone()
        };
        match Self::fixed(options, trust.clone()) {
            Ok(mut connector) => {
                connector.retry = EchRetry::default();
                *lock(&self.retry.adopted) = Some(Arc::new(connector));
                io::Error::new(err.kind(), Retrying(err))
            }
            Err(_) => err,
        }
    }

    async fn connect_engine(
        &self,
        io: BoxStream,
        name: ServerName<'static>,
        reads: Reads,
    ) -> io::Result<TlsConn> {
        let aligned = reads == Reads::Aligned;
        let mut conn = match &self.engine {
            Engine::Rustls(config) if reads != Reads::Buffered => TlsConn::Record(Box::new(
                rustls_backend::connect(config, name, io, aligned).await?,
            )),
            Engine::Rustls(config) => TlsConn::Buffered(crate::buffered::BufferedTls::rustls(
                rustls_backend::connect_buffered(config, name, io).await?,
            )),
            Engine::Boring(connector) if aligned => connector.connect(name, io).await?,
            Engine::Boring(connector) => connector.connect_buffered(name, io).await?,
            Engine::Reality(client) | Engine::Jls(client) => {
                TlsConn::Reality(Box::new(client.connect(io, &name).await?))
            }
        };
        if !aligned {
            conn.set_unaligned();
        }
        Ok(conn)
    }
}

fn is_retrying(err: &io::Error) -> bool {
    err.get_ref().is_some_and(|source| source.is::<Retrying>())
}

/// A verified TLS 1.3 handshake with a caller-chosen session id that returns the raw transport.
pub struct DecoyHandshake {
    server_name: Option<String>,
    client: RealityClient,
}

impl DecoyHandshake {
    /// `hybrid` offers X25519MLKEM768 when the fingerprint does.
    pub fn new(
        options: &TlsOptions,
        trust: Arc<TrustStore>,
        hybrid: bool,
    ) -> Result<Self, TlsError> {
        Ok(Self {
            server_name: options.server_name.clone().filter(|name| !name.is_empty()),
            client: RealityClient::decoy(options, trust, hybrid)?,
        })
    }

    /// `sealer` gets the ClientHello message with a zeroed 32-byte session id at offset 39.
    pub async fn run(
        &self,
        io: BoxStream,
        sni_fallback: &str,
        sealer: SessionIdSealer<'_>,
    ) -> io::Result<(BoxStream, Option<Vec<u8>>)> {
        let text = self.server_name.as_deref().unwrap_or(sni_fallback);
        let text = text.trim_matches(['[', ']']);
        let name = ServerName::try_from(text.to_owned())
            .map_err(|_| TlsError::Config(format!("invalid TLS server name {text:?}")))?;
        self.client
            .connect_decoy(io, &name, sealer)
            .await
            .map_err(|err| match err.to_string().strip_prefix("REALITY: ") {
                Some(rest) => io::Error::new(err.kind(), format!("shadow-tls: {rest}")),
                None => err,
            })
    }
}
