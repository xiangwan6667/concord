mod build;
mod delays;
mod dialing;
mod groups;
mod providers;
mod views;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, CoreEvent, DialCx, DialEnv, EventSink, FlowMeta, HostResolver, InboundInfo,
    InboundKind, Initiator, IpVersion, LookupIps, Network, Outbound, OutboundInfo, OutboundKind,
    PacketSession, ResourcePhase, SockOpts, SocketFactory,
};
use concord_config::proxy::{Capabilities, ProxyDef, ProxyParse, parse_proxy};
use concord_config::{LoadOptions, Profile, load_str};
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    BuildFailure, Built, Builtin, FetchError, FetchRequest, FetchResponse, Fetcher, GroupDeps,
    NodeFactory, Outbounds, Resolved, RouteMoved, SelectionStore, TestDefaults, Touch,
};

pub struct Behavior {
    pub delay: Mutex<Duration>,
    pub fail: AtomicBool,
    pub status: AtomicU16,
    pub connects: AtomicUsize,
    pub requests: AtomicUsize,
    pub last_request: Mutex<String>,
    pub dialer: Mutex<Option<String>>,
}

impl Default for Behavior {
    fn default() -> Self {
        Behavior {
            delay: Mutex::new(Duration::from_millis(10)),
            fail: AtomicBool::new(false),
            status: AtomicU16::new(204),
            connects: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            last_request: Mutex::new(String::new()),
            dialer: Mutex::new(None),
        }
    }
}

impl Behavior {
    pub fn set_delay(&self, millis: u64) {
        *lock(&self.delay) = Duration::from_millis(millis);
    }
}

#[derive(Default)]
pub struct Book(Mutex<HashMap<String, Arc<Behavior>>>);

impl Book {
    pub fn get(&self, name: &str) -> Arc<Behavior> {
        lock(&self.0).entry(name.to_string()).or_default().clone()
    }
}

pub struct FakeNode {
    info: OutboundInfo,
    behavior: Arc<Behavior>,
}

impl FakeNode {
    pub fn outbound(
        name: &str,
        kind: OutboundKind,
        udp: bool,
        behavior: Arc<Behavior>,
    ) -> Arc<dyn Outbound> {
        Arc::new(FakeNode {
            info: OutboundInfo {
                name: Arc::from(name),
                kind,
                addr: Arc::from(format!("{name}.test:443")),
                udp,
                provider: None,
                ip_version: concord_common::IpVersion::Dual,
            },
            behavior,
        })
    }
}

#[async_trait]
impl Outbound for FakeNode {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        self.behavior.connects.fetch_add(1, Ordering::SeqCst);
        let nested = lock(&self.behavior.dialer).clone();
        if let Some(via) = nested {
            let inner = cx.enter(&self.info.name)?;
            return inner.env.nodes.dial_via(&via, &inner, dst).await;
        }
        let delay = *lock(&self.behavior.delay);
        tokio::time::sleep(delay).await;
        if self.behavior.fail.load(Ordering::SeqCst)
            || matches!(self.info.kind, OutboundKind::Reject)
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "fake failure",
            ));
        }
        let (client, mut server) = tokio::io::duplex(4096);
        let behavior = self.behavior.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut seen = Vec::new();
            loop {
                match server.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
                while let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                    *lock(&behavior.last_request) =
                        String::from_utf8_lossy(&seen[..end + 4]).into_owned();
                    seen.drain(..end + 4);
                    behavior.requests.fetch_add(1, Ordering::SeqCst);
                    let status = behavior.status.load(Ordering::SeqCst);
                    let reply = format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n");
                    if server.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            }
        });
        Ok(Box::new(client))
    }

    async fn associate(
        &self,
        _cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

pub struct FakeFactory {
    pub book: Arc<Book>,
}

impl FakeFactory {
    fn node(&self, name: &str) -> Arc<dyn Outbound> {
        FakeNode::outbound(name, OutboundKind::Shadowsocks, true, self.book.get(name))
    }
}

impl NodeFactory for FakeFactory {
    fn builtin(&self, which: Builtin) -> Arc<dyn Outbound> {
        let (name, kind) = match which {
            Builtin::Direct => ("DIRECT", OutboundKind::Direct),
            Builtin::Reject => ("REJECT", OutboundKind::Reject),
            Builtin::RejectDrop => ("REJECT-DROP", OutboundKind::RejectDrop),
            Builtin::Compatible => ("COMPATIBLE", OutboundKind::Compatible),
            Builtin::Pass => ("PASS", OutboundKind::Pass),
            Builtin::PassRule => ("PASS-RULE", OutboundKind::PassRule),
        };
        FakeNode::outbound(name, kind, true, self.book.get(name))
    }

    fn build_def(&self, def: &ProxyDef) -> Result<Arc<dyn Outbound>, BuildFailure> {
        let outbound = self.node(&def.name);
        if !def.common.dialer_proxy.is_empty() {
            *lock(&self.book.get(&def.name).dialer) = Some(def.common.dialer_proxy.clone());
        }
        Ok(outbound)
    }

    fn build_map(&self, map: &Map<String, Value>) -> Result<Built, String> {
        match parse_proxy(map, &Capabilities::full()).map_err(|err| err.message)? {
            ProxyParse::Quarantined { name, kind, reason } => {
                Ok(Built::Quarantined { name, kind, reason })
            }
            ProxyParse::Ok(def) => Ok(Built::Node(
                self.build_def(&def).map_err(|err| err.message)?,
            )),
        }
    }
}

#[derive(Default)]
pub struct Events(pub Mutex<Vec<CoreEvent>>);

impl EventSink for Events {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        lock(&self.0).push(event);
    }
}

impl Events {
    pub fn delays(&self) -> Vec<(String, String, i32)> {
        lock(&self.0)
            .iter()
            .filter_map(|event| match event {
                CoreEvent::Delay(d) => Some((d.name.clone(), d.url.clone(), d.value)),
                _ => None,
            })
            .collect()
    }

    pub fn resources(&self) -> Vec<(String, ResourcePhase)> {
        lock(&self.0)
            .iter()
            .filter_map(|event| match event {
                CoreEvent::Resource(update) => {
                    Some((update.name.to_string(), update.phase.clone()))
                }
                _ => None,
            })
            .collect()
    }

    pub fn loops(&self) -> Vec<String> {
        lock(&self.0)
            .iter()
            .filter_map(|event| match event {
                CoreEvent::DialerLoop(name) => Some(name.to_string()),
                _ => None,
            })
            .collect()
    }
}

#[derive(Default)]
pub struct Moves(pub AtomicUsize);

impl RouteMoved for Moves {
    fn moved(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Moves {
    pub fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
pub struct Defaults {
    pub unified: AtomicBool,
}

impl TestDefaults for Defaults {
    fn unified_delay(&self) -> bool {
        self.unified.load(Ordering::SeqCst)
    }
}

type Reply = Result<(u16, Vec<(String, String)>, Vec<u8>), FetchError>;

#[derive(Default)]
pub struct FakeFetcher {
    pub replies: Mutex<HashMap<String, Reply>>,
    pub requests: Mutex<Vec<(String, Option<String>)>>,
}

impl FakeFetcher {
    pub fn serve_with(&self, url: &str, status: u16, headers: &[(&str, &str)], body: &str) {
        let headers = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        lock(&self.replies).insert(
            url.to_string(),
            Ok((status, headers, body.as_bytes().to_vec())),
        );
    }
}

#[async_trait]
impl Fetcher for FakeFetcher {
    async fn get(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        lock(&self.requests).push((request.url.clone(), request.via_proxy.clone()));
        match lock(&self.replies).get(&request.url).cloned() {
            Some(Ok((status, headers, body))) => Ok(FetchResponse {
                status,
                headers,
                body,
            }),
            Some(Err(err)) => Err(err),
            None => Err(FetchError::new(
                crate::FetchErrorKind::Connection,
                "connection refused",
            )),
        }
    }
}

struct NoSockets;

#[async_trait]
impl SocketFactory for NoSockets {
    async fn connect_tcp(
        &self,
        _target: SocketAddr,
        _opts: &SockOpts,
    ) -> io::Result<tokio::net::TcpStream> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn bind_udp(
        &self,
        _peer: std::net::IpAddr,
        _opts: &SockOpts,
    ) -> io::Result<tokio::net::UdpSocket> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

struct NoResolver;

#[async_trait]
impl HostResolver for NoResolver {
    async fn lookup(
        &self,
        _host: &str,
        _version: IpVersion,
        _initiator: Initiator,
    ) -> io::Result<LookupIps> {
        Ok(LookupIps::default())
    }
}

pub struct Rig {
    pub out: Arc<Outbounds>,
    pub moved: Arc<Moves>,
    pub events: Arc<Events>,
    pub book: Arc<Book>,
    pub store: Arc<SelectionStore>,
    pub fetcher: Arc<FakeFetcher>,
    pub defaults: Arc<Defaults>,
    pub _dir: tempfile::TempDir,
}

pub const TEST_URL: &str = "http://probe.test/generate_204";

pub fn profile(yaml: &str) -> Profile {
    load_str(yaml, &LoadOptions::default()).unwrap_or_else(|err| panic!("config: {err}"))
}

impl Rig {
    pub fn new(yaml: &str) -> Rig {
        Rig::with(&profile(yaml), Arc::new(SelectionStore::new()), None)
    }

    pub fn with(profile: &Profile, store: Arc<SelectionStore>, keep: Option<&Rig>) -> Rig {
        Rig::try_with(profile, store, keep).unwrap_or_else(|err| panic!("build: {err}"))
    }

    pub fn try_with(
        profile: &Profile,
        store: Arc<SelectionStore>,
        keep: Option<&Rig>,
    ) -> Result<Rig, crate::GroupError> {
        let dir = tempfile::tempdir().unwrap();
        let home = Arc::new(HomeDir::new(dir.path()));
        let book = keep.map_or_else(|| Arc::new(Book::default()), |rig| rig.book.clone());
        let moved = Arc::new(Moves::default());
        let events = Arc::new(Events::default());
        let fetcher = Arc::new(FakeFetcher::default());
        let defaults = Arc::new(Defaults::default());
        let env_events = events.clone();
        let deps = GroupDeps {
            selections: store.clone(),
            env: Arc::new(move |nodes| DialEnv {
                sockets: Arc::new(NoSockets),
                resolver: Arc::new(NoResolver),
                nodes,
                events: env_events.clone(),
                sock_opts: SockOpts::default(),
                tcp_concurrent: false,
                ipv6: true,
            }),
            fetcher: fetcher.clone(),
            events: events.clone(),
            route: moved.clone(),
            options: defaults.clone(),
            home: home.clone(),
            trust: TrustStore::new(b"", Vec::new()),
            factory: Arc::new(FakeFactory { book: book.clone() }),
        };
        let out = Outbounds::build(&mut profile.clone(), deps)?;
        Ok(Rig {
            out,
            moved,
            events,
            book,
            store,
            fetcher,
            defaults,
            _dir: dir,
        })
    }

    pub fn flow(host: &str) -> FlowMeta {
        FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound: InboundInfo::new(InboundKind::Socks5),
            src: SocketAddr::from(([127, 0, 0, 1], 5000)),
            dst: Address::new(host, 443),
        }
    }

    pub fn resolve(&self, name: &str) -> Resolved {
        self.out
            .resolve(name, &Rig::flow("example.com"), None, Touch::Yes)
    }

    pub fn leaf(&self, name: &str) -> String {
        match self.resolve(name) {
            Resolved::Route { leaf, .. } | Resolved::Rematch(leaf) => leaf.info().name.to_string(),
            Resolved::Pass => "<pass>".into(),
            Resolved::PassRule => "<pass-rule>".into(),
            Resolved::Rejected(_) => "<rejected>".into(),
            Resolved::Unknown => "<unknown>".into(),
        }
    }

    pub fn chain(&self, name: &str) -> Vec<String> {
        match self.resolve(name) {
            Resolved::Route { chain, .. } => chain.iter().map(|name| name.to_string()).collect(),
            _ => Vec::new(),
        }
    }

    pub async fn test(&self, name: &str) -> i32 {
        self.out
            .test_delay(name, TEST_URL, Duration::from_secs(5))
            .await
            .value
    }
}
