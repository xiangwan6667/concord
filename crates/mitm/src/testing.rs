use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use concord_common::intercept::{
    ConnInterceptor, ConnMark, DialFailure, HeldConn, InterceptFlow, Offer, RuleLabel, Upstream,
    UpstreamDialer, UpstreamRequest,
};
use concord_common::sync::lock;
use concord_common::{Address, FlowMeta, InboundInfo, InboundKind, Network};
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::{http1 as client1, http2 as client2};
use hyper::server::conn::{http1 as server1, http2 as server2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::RawConfig;
use crate::cron::UtcClock;
use crate::facade::{Mitm, MitmEnv};
use crate::script::ScriptRuntime;

#[derive(Clone, Debug)]
pub(crate) struct Seen {
    #[cfg_attr(
        not(feature = "script"),
        expect(dead_code, reason = "only the QuickJS tests read it")
    )]
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub version: Version,
}

pub(crate) struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn ok(body: &str) -> Reply {
        Reply {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn with(mut self, name: &str, value: &str) -> Reply {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

pub(crate) type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

pub(crate) struct TestServer {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    pub fn requests(&self) -> Vec<Seen> {
        lock(&self.seen).clone()
    }
}

fn server_tls(alpn: &[&str]) -> TlsAcceptor {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let key = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
    TlsAcceptor::from(Arc::new(config))
}

async fn answer(
    mut request: Request<Incoming>,
    seen: Arc<Mutex<Vec<Seen>>>,
    handler: Handler,
) -> Result<http::Response<Full<Bytes>>, io::Error> {
    let upgrading = request.headers().contains_key(http::header::UPGRADE);
    let upgrade = upgrading.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map_err(io::Error::other)?
        .to_bytes()
        .to_vec();
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .or_else(|| parts.uri.authority().map(|authority| authority.to_string()))
        .unwrap_or_default();
    let record = Seen {
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), ToString::to_string),
        host,
        headers: parts.headers.clone(),
        body,
        version: parts.version,
    };
    lock(&seen).push(record.clone());
    if let Some(upgrade) = upgrade {
        tokio::spawn(async move {
            if let Ok(upgraded) = upgrade.await {
                let mut io = TokioIo::new(upgraded);
                let mut buf = [0u8; 1024];
                while let Ok(read) = io.read(&mut buf).await {
                    if read == 0 || io.write_all(&buf[..read]).await.is_err() {
                        break;
                    }
                }
            }
        });
        return Ok(http::Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    let reply = handler(&record);
    let mut response = http::Response::builder().status(reply.status);
    for (name, value) in &reply.headers {
        response = response.header(name, value);
    }
    Ok(response.body(Full::new(Bytes::from(reply.body))).unwrap())
}

#[allow(
    clippy::disallowed_methods,
    reason = "a loopback server for the tests, not a proxied socket"
)]
pub(crate) async fn start_server(tls: bool, alpn: &[&str], handler: Handler) -> TestServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let acceptor = tls.then(|| server_tls(alpn));
    let task = tokio::spawn({
        let (seen, connections) = (seen.clone(), connections.clone());
        async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                let (seen, handler, acceptor) = (seen.clone(), handler.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let service = |seen: Arc<Mutex<Vec<Seen>>>, handler: Handler| {
                        service_fn(move |request| answer(request, seen.clone(), handler.clone()))
                    };
                    match acceptor {
                        Some(acceptor) => {
                            let Ok(tls) = acceptor.accept(stream).await else {
                                return;
                            };
                            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                            if h2 {
                                let _ = server2::Builder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(tls), service(seen, handler))
                                    .await;
                            } else {
                                let _ = server1::Builder::new()
                                    .serve_connection(TokioIo::new(tls), service(seen, handler))
                                    .with_upgrades()
                                    .await;
                            }
                        }
                        None => {
                            let _ = server1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service(seen, handler))
                                .with_upgrades()
                                .await;
                        }
                    }
                });
            }
        }
    });
    TestServer {
        addr,
        seen,
        connections,
        task,
    }
}

pub(crate) type ServiceBody = http_body_util::combinators::BoxBody<Bytes, io::Error>;

pub(crate) type Service = Arc<
    dyn Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = http::Response<ServiceBody>> + Send>>
        + Send
        + Sync,
>;

pub(crate) fn full_body(data: impl Into<Bytes>) -> ServiceBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

/// A TLS server whose answers the test writes itself: streamed, held open or
/// with trailers.
#[allow(
    clippy::disallowed_methods,
    reason = "a loopback server for the tests, not a proxied socket"
)]
pub(crate) async fn start_service(alpn: &[&str], service: Service) -> TestServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let acceptor = server_tls(alpn);
    let task = tokio::spawn({
        let connections = connections.clone();
        async move {
            while let Ok((stream, _)) = listener.accept().await {
                connections.fetch_add(1, Ordering::SeqCst);
                let (service, acceptor) = (service.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    let serve = service_fn(move |request| {
                        let answer = service(request);
                        async move { Ok::<_, io::Error>(answer.await) }
                    });
                    if h2 {
                        let _ = server2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), serve)
                            .await;
                    } else {
                        let _ = server1::Builder::new()
                            .serve_connection(TokioIo::new(tls), serve)
                            .with_upgrades()
                            .await;
                    }
                });
            }
        }
    });
    TestServer {
        addr,
        seen: Arc::default(),
        connections,
        task,
    }
}

pub(crate) struct TestHeld {
    id: String,
    pub mark: Mutex<Option<ConnMark>>,
}

impl HeldConn for TestHeld {
    fn id(&self) -> &str {
        &self.id
    }

    fn release(&self, mark: ConnMark) {
        *lock(&self.mark) = Some(mark);
    }
}

pub(crate) struct TestDialer {
    target: SocketAddr,
    pub flows: Mutex<Vec<(InterceptFlow, bool)>>,
    pub closed: Mutex<Vec<(String, Vec<String>)>>,
    pub closed_ids: Mutex<Vec<String>>,
    rejected: Mutex<HashSet<String>>,
    routes: Mutex<HashMap<String, SocketAddr>>,
    pub held: Mutex<Vec<Arc<TestHeld>>>,
    next: AtomicUsize,
}

impl TestDialer {
    pub fn new(target: SocketAddr) -> Arc<TestDialer> {
        Arc::new(TestDialer {
            target,
            flows: Mutex::default(),
            closed: Mutex::default(),
            closed_ids: Mutex::default(),
            rejected: Mutex::default(),
            routes: Mutex::default(),
            held: Mutex::default(),
            next: AtomicUsize::new(1),
        })
    }

    pub fn reject(&self, host: &str) {
        lock(&self.rejected).insert(host.to_string());
    }

    pub fn route(&self, host: &str, target: SocketAddr) {
        lock(&self.routes).insert(host.to_string(), target);
    }

    pub fn dialed(&self) -> Vec<(String, u16)> {
        lock(&self.flows)
            .iter()
            .map(|(flow, _)| (crate::engine::host_of(flow), flow.port))
            .collect()
    }

    pub fn marks(&self) -> Vec<Option<ConnMark>> {
        lock(&self.held)
            .iter()
            .map(|held| *lock(&held.mark))
            .collect()
    }
}

#[async_trait]
impl UpstreamDialer for TestDialer {
    #[allow(
        clippy::disallowed_methods,
        reason = "the test dialer reaches a loopback server"
    )]
    async fn dial(&self, request: UpstreamRequest) -> Result<Upstream, DialFailure> {
        let host = crate::engine::host_of(&request.flow);
        lock(&self.flows).push((request.flow.clone(), request.hold));
        if lock(&self.rejected).contains(&host) {
            return Err(DialFailure {
                chain: vec![Arc::from("REJECT")],
                rule: Some(RuleLabel {
                    name: Arc::from("DOMAIN"),
                    payload: Arc::from(host.as_str()),
                }),
                error: io::Error::other("rejected by the rules"),
            });
        }
        let target = lock(&self.routes)
            .get(&host)
            .copied()
            .unwrap_or(self.target);
        let stream = tokio::net::TcpStream::connect(target).await?;
        let id = format!("conn-{}", self.next.fetch_add(1, Ordering::SeqCst));
        let held = request.hold.then(|| {
            let held = Arc::new(TestHeld {
                id: id.clone(),
                mark: Mutex::new(None),
            });
            lock(&self.held).push(held.clone());
            held as Arc<dyn HeldConn>
        });
        Ok(Upstream {
            stream: Box::new(stream),
            id: Some(Arc::from(id.as_str())),
            held,
        })
    }

    fn record_closed(
        &self,
        flow: &InterceptFlow,
        chain: &[Arc<str>],
        _rule: Option<&RuleLabel>,
    ) -> Option<Arc<str>> {
        let id = format!("closed-{}", self.next.fetch_add(1, Ordering::SeqCst));
        lock(&self.closed).push((
            crate::engine::host_of(flow),
            chain.iter().map(ToString::to_string).collect(),
        ));
        lock(&self.closed_ids).push(id.clone());
        Some(Arc::from(id.as_str()))
    }
}

static SOURCE_PORT: AtomicU16 = AtomicU16::new(40000);

pub(crate) fn flow(host: &str, port: u16) -> InterceptFlow {
    flow_of(InboundKind::Tun, Address::new(host, port))
}

pub(crate) fn flow_of(kind: InboundKind, dst: Address) -> InterceptFlow {
    let (host, dst_ip) = match &dst {
        Address::Socket(addr) => (None, Some(addr.ip())),
        Address::Domain(name, _) => (Some(name.clone()), None),
    };
    let port = dst.port();
    InterceptFlow {
        meta: FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound: InboundInfo::new(kind),
            src: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SOURCE_PORT.fetch_add(1, Ordering::SeqCst),
            ),
            dst,
        },
        host,
        sniffed: false,
        dst_ip,
        port,
    }
}

pub(crate) struct Rig {
    pub mitm: Mitm,
    pub dialer: Arc<TestDialer>,
    _home: tempfile::TempDir,
    pub root: CertificateDer<'static>,
}

impl Rig {
    pub fn config(&self, value: serde_json::Value) -> Vec<String> {
        let raw: RawConfig = serde_json::from_value(value).unwrap();
        self.mitm.apply(Some(raw))
    }

    pub fn resources(&self) -> std::path::PathBuf {
        self.mitm.authority().resources_dir()
    }
}

pub(crate) fn rig_for(server: &TestServer, runtime: Option<Arc<dyn ScriptRuntime>>) -> Rig {
    let mut rig = rig_without_ca(server, runtime);
    let info = rig.mitm.generate_certificate().unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(info.pem.as_bytes()).unwrap();
    rig.root = CertificateDer::from(pem.contents);
    rig
}

pub(crate) fn rig_without_ca(server: &TestServer, runtime: Option<Arc<dyn ScriptRuntime>>) -> Rig {
    let home = tempfile::tempdir().unwrap();
    let dialer = TestDialer::new(server.addr);
    let mitm = Mitm::new(MitmEnv {
        home: Arc::new(HomeDir::new(home.path())),
        trust: TrustStore::new(&[], Vec::new()),
        dialer: dialer.clone(),
        clock: Arc::new(UtcClock),
        runtime,
    });
    Rig {
        mitm,
        dialer,
        _home: home,
        root: CertificateDer::from(Vec::new()),
    }
}

pub(crate) enum Wire {
    H1(client1::SendRequest<Full<Bytes>>),
    H2(client2::SendRequest<Full<Bytes>>),
}

pub(crate) struct Answer {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }
}

pub(crate) struct Client {
    pub wire: Wire,
    _offer: JoinHandle<Offer>,
    pub alpn: Option<Vec<u8>>,
    host: String,
}

pub(crate) fn client_config(
    root: &CertificateDer<'static>,
    alpn: &[&str],
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
    Arc::new(config)
}

pub(crate) fn offer_on(
    interceptor: Arc<dyn ConnInterceptor>,
    flow: InterceptFlow,
) -> (tokio::io::DuplexStream, JoinHandle<Offer>) {
    let (near, far) = tokio::io::duplex(1 << 20);
    let offer =
        tokio::spawn(async move { interceptor.offer(&flow, Box::new(far), Vec::new()).await });
    (near, offer)
}

impl Client {
    pub async fn tls(rig: &Rig, host: &str, port: u16, alpn: &[&str]) -> io::Result<Client> {
        Self::tls_flow(rig, flow(host, port), host, alpn).await
    }

    pub async fn tls_flow(
        rig: &Rig,
        flow: InterceptFlow,
        server_name: &str,
        alpn: &[&str],
    ) -> io::Result<Client> {
        let (near, offer) = offer_on(rig.mitm.interceptor(), flow);
        let name = ServerName::try_from(server_name.to_string()).unwrap();
        let connector = TlsConnector::from(client_config(&rig.root, alpn));
        let tls = connector.connect(name, near).await?;
        let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let wire = if negotiated.as_deref() == Some(b"h2") {
            let (sender, conn) = client2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(tls))
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(conn);
            Wire::H2(sender)
        } else {
            let (sender, conn) = client1::handshake(TokioIo::new(tls))
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(conn.with_upgrades());
            Wire::H1(sender)
        };
        Ok(Client {
            wire,
            _offer: offer,
            alpn: negotiated,
            host: server_name.to_string(),
        })
    }

    pub async fn plain(rig: &Rig, host: &str, port: u16) -> Client {
        let (near, offer) = offer_on(rig.mitm.interceptor(), flow(host, port));
        let (sender, conn) = client1::handshake(TokioIo::new(near)).await.unwrap();
        tokio::spawn(conn.with_upgrades());
        Client {
            wire: Wire::H1(sender),
            _offer: offer,
            alpn: None,
            host: host.to_string(),
        }
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Request<Full<Bytes>> {
        let h2 = matches!(self.wire, Wire::H2(_));
        let mut request = Request::builder().method(method);
        request = if h2 {
            request.uri(format!("https://{}{path}", self.host))
        } else {
            request.uri(path).header("Host", &self.host)
        };
        for (name, value) in headers {
            request = request.header(
                HeaderName::try_from(*name).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        request
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }

    pub async fn send(&mut self, request: Request<Full<Bytes>>) -> io::Result<Answer> {
        let response = match &mut self.wire {
            Wire::H1(sender) => sender.send_request(request).await,
            Wire::H2(sender) => sender.send_request(request).await,
        }
        .map_err(io::Error::other)?;
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .map_err(io::Error::other)?
            .to_bytes()
            .to_vec();
        Ok(Answer {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }

    pub async fn get(&mut self, path: &str) -> Answer {
        let request = self.request("GET", path, &[], "");
        self.send(request).await.unwrap()
    }
}

pub(crate) async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..200 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the condition never held");
}
