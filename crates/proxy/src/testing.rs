#![allow(
    clippy::disallowed_methods,
    reason = "tests talk to loopback listeners and sockets directly"
)]

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, DialEnv, HostResolver, Initiator, IpVersion, LookupIps,
    NodeDialer, NullSink, PacketBuf, PacketSession, SockOpts,
};
use concord_net::Sockets;
use concord_platform::NativePlatform;
use futures_util::task::AtomicWaker;

pub(crate) struct IpOnly;

#[async_trait]
impl HostResolver for IpOnly {
    async fn lookup(
        &self,
        host: &str,
        _version: IpVersion,
        _initiator: Initiator,
    ) -> io::Result<LookupIps> {
        let ip: IpAddr = if host == "localhost" {
            IpAddr::from([127, 0, 0, 1])
        } else {
            host.parse()
                .map_err(|_| CoreError::IpNotFound(host.into()))?
        };
        let mut found = LookupIps::default();
        if ip.is_ipv4() {
            found.v4.push(ip);
        } else {
            found.v6.push(ip);
        }
        Ok(found)
    }
}

const TEST_WAIT: Duration = Duration::from_secs(10);

/// Tasks registered with a tracker the test can stop and wait on, as the engine's are.
pub(crate) struct Tracked {
    pub(crate) tasks: concord_common::Tasks,
    tracker: tokio_util::task::TaskTracker,
    stop: tokio_util::sync::CancellationToken,
}

impl Tracked {
    pub(crate) fn new() -> Tracked {
        let tracker = tokio_util::task::TaskTracker::new();
        let stop = tokio_util::sync::CancellationToken::new();
        let tasks = concord_common::Tasks::new(
            tracker.clone(),
            stop.clone(),
            tokio::runtime::Handle::current(),
        );
        Tracked {
            tasks,
            tracker,
            stop,
        }
    }

    pub(crate) fn ctx(&self) -> crate::ctx::BuildCtx {
        let mut ctx = crate::ctx::BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new()));
        ctx.tasks = self.tasks.clone();
        ctx
    }

    pub(crate) fn running(&self) -> usize {
        self.tracker.len()
    }

    pub(crate) fn stop(&self) {
        self.stop.cancel();
    }

    pub(crate) async fn ended_within(&self, bound: Duration) -> bool {
        self.tracker.close();
        let ended = tokio::time::timeout(bound, self.tracker.wait())
            .await
            .is_ok();
        self.tracker.reopen();
        ended
    }
}

/// What a spawned task returns; the test fails if it takes longer than ten seconds.
pub(crate) async fn settled<T>(task: tokio::task::JoinHandle<T>) -> T {
    match tokio::time::timeout(TEST_WAIT, task).await {
        Ok(Ok(value)) => value,
        Ok(Err(err)) => panic!("the task failed: {err}"),
        Err(_) => panic!("the task did not finish within ten seconds"),
    }
}

/// Resolves like [`IpOnly`], but holds the first lookup until [`release`](Self::release), so a
/// test can act while a dial is under way.
pub(crate) struct HeldLookup {
    armed: AtomicBool,
    entered: tokio::sync::Notify,
    released: tokio::sync::Notify,
}

impl HeldLookup {
    pub(crate) fn new() -> Arc<HeldLookup> {
        Arc::new(HeldLookup {
            armed: AtomicBool::new(true),
            entered: tokio::sync::Notify::new(),
            released: tokio::sync::Notify::new(),
        })
    }

    pub(crate) async fn entered(&self) {
        let entered = tokio::time::timeout(TEST_WAIT, self.entered.notified()).await;
        assert!(entered.is_ok(), "the dial never looked the server up");
    }

    pub(crate) fn release(&self) {
        self.released.notify_one();
    }

    pub(crate) fn env(self: &Arc<Self>) -> DialEnv {
        DialEnv {
            resolver: self.clone(),
            ..test_env()
        }
    }
}

#[async_trait]
impl HostResolver for HeldLookup {
    async fn lookup(
        &self,
        host: &str,
        version: IpVersion,
        initiator: Initiator,
    ) -> io::Result<LookupIps> {
        if self.armed.swap(false, Ordering::AcqRel) {
            self.entered.notify_one();
            self.released.notified().await;
        }
        IpOnly.lookup(host, version, initiator).await
    }
}

/// A platform that reports the process out of descriptors.
pub(crate) struct Pressured;

#[async_trait]
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

#[derive(Default)]
pub(crate) struct Nodes {
    pub(crate) dialed: Mutex<Vec<String>>,
}

#[async_trait]
impl NodeDialer for Nodes {
    async fn dial_via(&self, name: &str, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        lock(&self.dialed).push(name.to_string());
        let _ = (cx, dst);
        Err(CoreError::UnknownNode(name.to_string()).into())
    }

    async fn associate_via(
        &self,
        name: &str,
        _cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        Err(CoreError::UnknownNode(name.to_string()).into())
    }
}

/// A `dialer-proxy` named `hop` that connects straight to loopback and counts the datagrams
/// it carries.
#[derive(Default)]
pub(crate) struct LoopbackHop {
    pub(crate) datagrams: Arc<AtomicUsize>,
    pub(crate) cut: Arc<Cut>,
}

/// Once set, the hop's UDP sessions fail both ways, waking a receive parked on one.
#[derive(Default)]
pub(crate) struct Cut {
    set: AtomicBool,
    parked: AtomicWaker,
}

impl Cut {
    pub(crate) fn set(&self) {
        self.set.store(true, Ordering::SeqCst);
        self.parked.wake();
    }

    fn check(&self) -> io::Result<()> {
        if self.set.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

#[async_trait]
impl NodeDialer for LoopbackHop {
    async fn dial_via(&self, name: &str, _cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        if name != "hop" {
            return Err(CoreError::UnknownNode(name.to_string()).into());
        }
        Ok(Box::new(
            tokio::net::TcpStream::connect(socket_of(dst)?).await?,
        ))
    }

    async fn associate_via(
        &self,
        name: &str,
        _cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if name != "hop" {
            return Err(CoreError::UnknownNode(name.to_string()).into());
        }
        Ok(Arc::new(HopSession {
            socket: tokio::net::UdpSocket::bind("127.0.0.1:0").await?,
            sent: self.datagrams.clone(),
            cut: self.cut.clone(),
        }))
    }
}

fn socket_of(dst: &Address) -> io::Result<SocketAddr> {
    dst.to_string()
        .parse()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

struct HopSession {
    socket: tokio::net::UdpSocket,
    sent: Arc<AtomicUsize>,
    cut: Arc<Cut>,
}

impl PacketSession for HopSession {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if let Err(err) = self.cut.check() {
            return Poll::Ready(Err(err));
        }
        let to = match socket_of(dst) {
            Ok(to) => to,
            Err(err) => return Poll::Ready(Err(err)),
        };
        self.socket
            .poll_send_to(cx, pkt.as_slice(), to)
            .map(|sent| {
                self.sent.fetch_add(1, Ordering::Relaxed);
                sent.map(|_| ())
            })
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        self.cut.parked.register(cx.waker());
        if let Err(err) = self.cut.check() {
            return Poll::Ready(Err(err));
        }
        let mut bytes = vec![0u8; 65535];
        let mut read = tokio::io::ReadBuf::new(&mut bytes);
        match self.socket.poll_recv_from(cx, &mut read) {
            Poll::Ready(Ok(from)) => {
                buf.extend_from_slice(read.filled());
                Poll::Ready(Ok(Address::Socket(from)))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(crate) fn test_env() -> DialEnv {
    test_env_with(Arc::new(Nodes::default()))
}

pub(crate) fn test_env_with(nodes: Arc<dyn NodeDialer>) -> DialEnv {
    DialEnv {
        sockets: Arc::new(Sockets::new(Arc::new(NativePlatform::new()))),
        resolver: Arc::new(IpOnly),
        nodes,
        events: Arc::new(NullSink),
        sock_opts: SockOpts::default(),
        tcp_concurrent: false,
        ipv6: true,
    }
}

/// A QUIC server on a loopback port with a throwaway certificate; `wrap` can put
/// something between the UDP socket and quinn.
pub(crate) fn quic_server(
    alpn: &[u8],
    wrap: impl FnOnce(Arc<dyn quinn::AsyncUdpSocket>) -> Arc<dyn quinn::AsyncUdpSocket>,
) -> (quinn::Endpoint, u16) {
    use quinn::Runtime;

    #[allow(clippy::unwrap_used, reason = "test helper")]
    {
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(made.signing_key.serialize_der());
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![made.cert.der().clone()], key.into())
        .unwrap();
        tls.alpn_protocols = vec![alpn.to_vec()];
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap(),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(1 << 20));
        config.transport_config(Arc::new(transport));
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = std_socket.local_addr().unwrap().port();
        let socket = wrap(quinn::TokioRuntime.wrap_udp_socket(std_socket).unwrap());
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        (endpoint, port)
    }
}
