#![allow(
    clippy::disallowed_methods,
    reason = "loopback DNS servers for the tests"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{
    CoreEvent, DnsRecord, EventSink, HostResolver, Initiator, IpVersion, SockOpts,
};
use concord_config::dns::{DnsConfig, Upstream, parse_upstream};
use concord_config::hosts::HostsConfig;
use concord_net::Sockets;
use concord_platform::NativePlatform;
use concord_tls::TrustStore;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::{NoRules, Resolver, ResolverDeps, UpstreamDialer, msg};

pub type Handler = Arc<dyn Fn(&Message) -> Option<Message> + Send + Sync>;

pub struct Server {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
}

impl Server {
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub fn udp_url(&self) -> String {
        format!("udp://{}", self.addr)
    }

    pub fn tcp_url(&self) -> String {
        format!("tcp://{}", self.addr)
    }
}

/// Answers A with `ip`, everything else with an empty NOERROR.
pub fn answer_with(ip: Ipv4Addr) -> Handler {
    Arc::new(move |req| {
        let query = req.queries.first()?;
        let mut resp = msg::empty_answer(req);
        if query.query_type == RecordType::A {
            resp.answers.push(msg::a_record(&query.name, 60, ip));
        }
        Some(resp)
    })
}

pub fn silent() -> Handler {
    Arc::new(|_| None)
}

pub async fn serve_udp(handler: Handler, delay: Duration) -> Server {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(req) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let (handler, socket) = (Arc::clone(&handler), Arc::clone(&socket));
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if let Some(resp) = handler(&req) {
                    let _ = socket.send_to(&resp.to_vec().unwrap(), from).await;
                }
            });
        }
    });
    Server { addr, hits }
}

pub type Sequence = Arc<dyn Fn(&Message) -> Vec<Message> + Send + Sync>;

/// Sends every message the handler returns, in order, for one query.
pub async fn serve_udp_sequence(handler: Sequence) -> Server {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            for resp in handler(&req) {
                let _ = socket.send_to(&resp.to_vec().unwrap(), from).await;
            }
        }
    });
    Server { addr, hits }
}

async fn serve_framed<S>(mut stream: S, handler: Handler, hits: Arc<AtomicUsize>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let mut head = [0u8; 2];
        if stream.read_exact(&mut head).await.is_err() {
            return;
        }
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(head))];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }
        let Ok(req) = Message::from_vec(&body) else {
            return;
        };
        hits.fetch_add(1, Ordering::SeqCst);
        if let Some(resp) = handler(&req) {
            let bytes = resp.to_vec().unwrap();
            let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&bytes);
            if stream.write_all(&frame).await.is_err() {
                return;
            }
        }
    }
}

pub async fn serve_tcp(handler: Handler) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve_framed(
                stream,
                Arc::clone(&handler),
                Arc::clone(&counter),
            ));
        }
    });
    Server { addr, hits }
}

pub async fn serve_tls(handler: Handler) -> Server {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let chain = vec![key.cert.der().clone()];
    let private = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()),
    );
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (acceptor, handler, counter) =
                (acceptor.clone(), Arc::clone(&handler), Arc::clone(&counter));
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    serve_framed(tls, handler, counter).await;
                }
            });
        }
    });
    Server { addr, hits }
}

/// A DoH server speaking HTTP/1.1 over plain TCP.
pub async fn serve_doh(handler: Handler) -> Server {
    use base64::Engine;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (handler, counter) = (Arc::clone(&handler), Arc::clone(&counter));
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                let line = text.lines().next().unwrap_or_default();
                let Some(encoded) = line.split("dns=").nth(1).and_then(|s| s.split(' ').next())
                else {
                    return;
                };
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded)
                    .unwrap();
                let req = Message::from_vec(&bytes).unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let body = handler(&req).unwrap().to_vec().unwrap();
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
    Server { addr, hits }
}

#[derive(Default)]
pub struct Sink {
    pub records: Mutex<Vec<DnsRecord>>,
}

impl Sink {
    pub fn records(&self) -> Vec<DnsRecord> {
        lock(&self.records).clone()
    }
}

impl EventSink for Sink {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        if let CoreEvent::Dns(record) = event {
            lock(&self.records).push(record);
        }
    }
}

pub fn up(text: &str) -> Upstream {
    parse_upstream(text).unwrap()
}

pub fn config(nameservers: &[String]) -> DnsConfig {
    DnsConfig {
        enable: true,
        nameserver: nameservers.iter().map(|text| up(text)).collect(),
        default_nameserver: vec![up("127.0.0.1")],
        ipv6: true,
        ..DnsConfig::default()
    }
}

pub fn deps(sink: &Arc<Sink>) -> ResolverDeps {
    let platform: Arc<NativePlatform> = Arc::new(NativePlatform::new());
    let dialer: Weak<dyn UpstreamDialer> = Weak::<NoDialerImpl>::new();
    ResolverDeps {
        sockets: Arc::new(Sockets::new(platform.clone())),
        trust: TrustStore::new(b"", Vec::new()),
        events: sink.clone(),
        platform,
        rules: Arc::new(NoRules),
        dialer,
        sock_opts: SockOpts::default(),
        ipv6: true,
        store_fake_ip: false,
    }
}

/// A platform out of descriptors: every socket the resolver asks for is refused.
pub struct Pressured;

#[async_trait::async_trait]
impl concord_platform::Platform for Pressured {
    fn protect(&self, _socket: concord_common::RawSocket) -> bool {
        true
    }

    async fn find_owner(
        &self,
        _flow: &concord_common::FlowKey,
    ) -> Option<concord_common::ProcessInfo> {
        None
    }

    fn default_interface(&self) -> Option<concord_platform::InterfaceInfo> {
        None
    }

    fn system_dns(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    fn fd_pressure(&self) -> bool {
        true
    }
}

pub struct NoDialerImpl;

#[async_trait::async_trait]
impl UpstreamDialer for NoDialerImpl {
    fn knows(&self, _via: &str) -> bool {
        false
    }

    async fn connect(
        &self,
        _via: &str,
        _target: &concord_common::Address,
    ) -> std::io::Result<concord_common::BoxStream> {
        Err(std::io::Error::other("no tunnel in tests"))
    }

    async fn bind_udp(
        &self,
        _via: &str,
        _target: &concord_common::Address,
    ) -> std::io::Result<Arc<dyn concord_common::PacketSession>> {
        Err(std::io::Error::other("no tunnel in tests"))
    }
}

/// `node`, which resolves `own_server` through the resolver before it connects.
pub struct NodeDialer {
    pub server: SocketAddr,
    pub own_server: Option<&'static str>,
    pub resolver: OnceLock<Weak<Resolver>>,
}

#[async_trait::async_trait]
impl UpstreamDialer for NodeDialer {
    fn knows(&self, via: &str) -> bool {
        via == "node"
    }

    async fn connect(
        &self,
        _via: &str,
        _target: &concord_common::Address,
    ) -> std::io::Result<concord_common::BoxStream> {
        if let Some(host) = self.own_server {
            let resolver = self.resolver.get().and_then(Weak::upgrade).unwrap();
            resolver
                .lookup(host, IpVersion::Ipv4, Initiator::Proxy)
                .await?;
        }
        Ok(Box::new(TcpStream::connect(self.server).await?))
    }

    async fn bind_udp(
        &self,
        _via: &str,
        _target: &concord_common::Address,
    ) -> std::io::Result<Arc<dyn concord_common::PacketSession>> {
        Err(std::io::Error::other("no udp through the node"))
    }
}

/// Outbounds named `names` that carry UDP over a local socket, as DIRECT does; each
/// session it opens is kept as (outbound, target).
pub struct UdpDialer {
    pub names: &'static [&'static str],
    pub asked: Mutex<Vec<(String, concord_common::Address)>>,
}

impl UdpDialer {
    pub fn new(names: &'static [&'static str]) -> Arc<Self> {
        Arc::new(UdpDialer {
            names,
            asked: Mutex::new(Vec::new()),
        })
    }

    pub fn asked(&self) -> Vec<(String, concord_common::Address)> {
        lock(&self.asked).clone()
    }
}

struct NoNames;

#[async_trait::async_trait]
impl HostResolver for NoNames {
    async fn lookup(
        &self,
        host: &str,
        _version: IpVersion,
        _initiator: Initiator,
    ) -> std::io::Result<concord_common::LookupIps> {
        Err(std::io::Error::other(format!(
            "no lookup of {host} in tests"
        )))
    }
}

#[async_trait::async_trait]
impl UpstreamDialer for UdpDialer {
    fn knows(&self, via: &str) -> bool {
        self.names.contains(&via)
    }

    async fn connect(
        &self,
        via: &str,
        _target: &concord_common::Address,
    ) -> std::io::Result<concord_common::BoxStream> {
        Err(std::io::Error::other(format!("no tcp through {via}")))
    }

    async fn bind_udp(
        &self,
        via: &str,
        target: &concord_common::Address,
    ) -> std::io::Result<Arc<dyn concord_common::PacketSession>> {
        lock(&self.asked).push((via.to_string(), target.clone()));
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        Ok(Arc::new(concord_net::DirectPacketSession::new(
            socket,
            Arc::new(NoNames),
            Initiator::Other,
            IpVersion::Ipv4,
            false,
            Default::default(),
        )))
    }
}

pub fn build_over(config: &DnsConfig, dialer: &Arc<UdpDialer>) -> Arc<Resolver> {
    let sink = Arc::new(Sink::default());
    let mut deps = deps(&sink);
    deps.dialer = Arc::downgrade(dialer) as Weak<dyn UpstreamDialer>;
    Resolver::new(config, &HostsConfig::default(), deps).unwrap()
}

pub fn build_through(config: &DnsConfig, dialer: &Arc<NodeDialer>) -> Arc<Resolver> {
    let sink = Arc::new(Sink::default());
    let mut deps = deps(&sink);
    let weak: Weak<dyn UpstreamDialer> = Arc::downgrade(dialer) as Weak<dyn UpstreamDialer>;
    deps.dialer = weak;
    let resolver = Resolver::new(config, &HostsConfig::default(), deps).unwrap();
    let _ = dialer.resolver.set(Arc::downgrade(&resolver));
    resolver
}

pub fn build(config: &DnsConfig) -> (Arc<Resolver>, Arc<Sink>) {
    build_with_hosts(config, &HostsConfig::default())
}

pub fn build_with_hosts(config: &DnsConfig, hosts: &HostsConfig) -> (Arc<Resolver>, Arc<Sink>) {
    let sink = Arc::new(Sink::default());
    let resolver = Resolver::new(config, hosts, deps(&sink)).unwrap();
    (resolver, sink)
}

pub fn query_bytes(host: &str, rt: RecordType) -> Vec<u8> {
    msg::build_query(host, rt).unwrap().to_vec().unwrap()
}

pub fn parse(bytes: &[u8]) -> Message {
    Message::from_vec(bytes).unwrap()
}

fn quic_server_config(alpn: &[u8]) -> quinn::ServerConfig {
    use quinn::crypto::rustls::QuicServerConfig;
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let chain = vec![key.cert.der().clone()];
    let private = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()),
    );
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .unwrap();
    tls.alpn_protocols = vec![alpn.to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()))
}

/// DNS over HTTP/3: GET `?dns=` answered with `application/dns-message`.
pub async fn serve_h3(handler: Handler) -> Server {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let endpoint =
        quinn::Endpoint::server(quic_server_config(b"h3"), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let (handler, counter) = (Arc::clone(&handler), Arc::clone(&counter));
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else {
                    return;
                };
                let mut h3: h3::server::Connection<_, bytes::Bytes> =
                    h3::server::Connection::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();
                while let Ok(Some(resolver)) = h3.accept().await {
                    let (handler, counter) = (Arc::clone(&handler), Arc::clone(&counter));
                    tokio::spawn(async move {
                        let (request, mut stream) = resolver.resolve_request().await.unwrap();
                        let query = request.uri().query().unwrap().strip_prefix("dns=").unwrap();
                        let req =
                            Message::from_vec(&URL_SAFE_NO_PAD.decode(query).unwrap()).unwrap();
                        counter.fetch_add(1, Ordering::SeqCst);
                        let bytes = handler(&req).unwrap().to_vec().unwrap();
                        let response = http::Response::builder()
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        stream.send_response(response).await.unwrap();
                        stream.send_data(bytes.into()).await.unwrap();
                        stream.finish().await.unwrap();
                    });
                }
            });
        }
    });
    Server { addr, hits }
}

pub async fn serve_quic(handler: Handler) -> Server {
    use quinn::crypto::rustls::QuicServerConfig;
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let chain = vec![key.cert.der().clone()];
    let private = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()),
    );
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .unwrap();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let (handler, counter) = (Arc::clone(&handler), Arc::clone(&counter));
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else {
                    return;
                };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(body) = recv.read_to_end(65_535).await else {
                        return;
                    };
                    let req = Message::from_vec(&body[2..]).unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    let bytes = handler(&req).unwrap().to_vec().unwrap();
                    let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&bytes);
                    send.write_all(&frame).await.unwrap();
                    send.finish().unwrap();
                }
            });
        }
    });
    Server { addr, hits }
}
