mod bbr;
mod congestion;
mod datagram;
mod obfs;
mod shared;
mod socket;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use concord_common::{Address, BoxRead, BoxWrite, DialCx, Initiator, SockOpts, Stream, Tasks};
use quinn::congestion::{CubicConfig, NewRenoConfig};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, RecvStream, Runtime, SendStream, TokioRuntime,
};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use concord_config::proxy::TlsOpts;
use concord_tls::{QuicTls, TlsOptions, TrustStore};
use concord_transport::SessionSocket;

use crate::ctx::{BuildCtx, BuildError};
use crate::link::EnvSlot;
use crate::tlsmap::{TlsSpec, tls_options};
use concord_net::dial_each;

use crate::node::{Egress, resolve_server};

pub(crate) use self::bbr::{BbrProfile, factory as bbr_factory};
pub(crate) use self::congestion::{Brutal, SwitchFactory};
use self::datagram::CappedFrame;
use self::obfs::{Gecko, Salamander, WeChat, XPlus};
pub(crate) use self::shared::{DatagramHub, SharedConn};
pub(crate) use self::socket::Hop;
use self::socket::Obfs;
use self::socket::WrappedSocket;

/// quic-go's starting point, which mihomo's QUIC clients share: a 100 ms initial RTT
/// (`DefaultInitialRTT`) and Cubic with a 32-packet initial window
/// (`initialCongestionWindow` of 1280-byte packets).
pub(crate) fn transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config
        .initial_rtt(Duration::from_millis(100))
        .congestion_controller_factory(Arc::new(cubic()));
    config
}

/// quic-go's `InitialPacketSize`, the datagram size its congestion controllers count in.
pub(crate) const INITIAL_PACKET_SIZE: u64 = 1280;
const INITIAL_WINDOW: u64 = 32 * INITIAL_PACKET_SIZE;
/// quic-go's `maxDatagramRcvQueueLen`: datagrams a connection holds for the reader.
const DATAGRAM_QUEUE: usize = 128;

/// quinn counts its datagram receive buffer in bytes, so quic-go's queue of datagrams
/// becomes that many frames of the size the connection advertises.
pub(crate) fn datagram_buffer(frame: u64) -> usize {
    DATAGRAM_QUEUE.saturating_mul(usize::try_from(frame).unwrap_or(usize::MAX))
}
/// quic-go's `HandshakeIdleTimeout`; quinn has no separate handshake timer, so a dial
/// without its own deadline gets this as a whole-handshake bound.
const HANDSHAKE_IDLE: Duration = Duration::from_secs(5);

pub(crate) fn cubic() -> CubicConfig {
    let mut config = CubicConfig::default();
    config.initial_window(INITIAL_WINDOW);
    config
}

pub(crate) fn new_reno() -> NewRenoConfig {
    let mut config = NewRenoConfig::default();
    config.initial_window(INITIAL_WINDOW);
    config
}

pub(crate) fn io_error(err: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(err)
}

pub(crate) enum Crypto {
    Rustls(Arc<rustls::ClientConfig>),
    /// The config follows the ECH record looked up through the environment the link was dialed with.
    EchLookup(Arc<QuicTls>, EnvSlot),
    Custom(Arc<dyn quinn::crypto::ClientConfig>),
}

pub(crate) struct QuicLink {
    pub(crate) egress: Egress,
    pub(crate) server: Address,
    /// `None` sends no SNI and names the server by its address.
    pub(crate) server_name: Option<String>,
    pub(crate) crypto: Crypto,
    pub(crate) transport: Arc<quinn::TransportConfig>,
    pub(crate) obfs: ObfsSpec,
    pub(crate) hop: Option<Hop>,
    /// The `max_datagram_frame_size` to advertise instead of the one quinn derives.
    pub(crate) datagram_frame: Option<u64>,
    pub(crate) tasks: Tasks,
}

/// A QUIC connection and the endpoint that carries it.
pub(crate) struct QuicConn {
    pub(crate) conn: quinn::Connection,
    endpoint: Endpoint,
    pub(crate) tasks: Tasks,
}

/// quinn spawns an endpoint's driver and each connection's through its runtime. They run until
/// the connection has drained after its close (3 PTO, RFC 9000 section 10.2), which is what
/// sends the CONNECTION_CLOSE, so they run to their end.
struct TrackedRuntime(Tasks);

impl std::fmt::Debug for TrackedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrackedRuntime")
    }
}

impl Runtime for TrackedRuntime {
    fn new_timer(&self, at: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        TokioRuntime.new_timer(at)
    }

    fn spawn(&self, future: Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        self.0.spawn_to_end(future);
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> std::time::Instant {
        TokioRuntime.now()
    }
}

impl Drop for QuicConn {
    fn drop(&mut self) {
        self.conn.close(quinn::VarInt::from_u32(0), b"");
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
    }
}

pub(crate) fn quic_crypto(
    options: &TlsOptions,
    trust: Arc<TrustStore>,
    alpn: &[&str],
    env: EnvSlot,
) -> Result<Crypto, BuildError> {
    if options.ech_lookup.is_some() && options.ech_config_list.is_none() {
        return Ok(Crypto::EchLookup(
            Arc::new(QuicTls::new(options, trust, alpn)?),
            env,
        ));
    }
    Ok(Crypto::Rustls(concord_tls::quic_client_config(
        options, trust, alpn,
    )?))
}

/// The server name and crypto of a QUIC node whose `sni` falls back to its server and whose
/// `alpn` falls back to `default_alpn`.
pub(crate) fn node_crypto(
    tls: &TlsOpts,
    server: &str,
    default_alpn: &str,
    ctx: &BuildCtx,
) -> Result<(String, Crypto), BuildError> {
    let server_name = if tls.server_name.is_empty() {
        server.to_string()
    } else {
        tls.server_name.clone()
    };
    let alpn = if tls.alpn.is_empty() {
        vec![default_alpn.to_string()]
    } else {
        tls.alpn.clone()
    };
    let env_slot: EnvSlot = Arc::new(ArcSwapOption::empty());
    let options = tls_options(
        tls,
        TlsSpec {
            sni: server_name.clone(),
            alpn: alpn.clone(),
        },
        ctx,
        Some(&env_slot),
    )?;
    let alpn: Vec<&str> = alpn.iter().map(String::as_str).collect();
    let crypto = quic_crypto(&options, ctx.trust.clone(), &alpn, env_slot)?;
    Ok((server_name, crypto))
}

pub(crate) fn client_config(
    crypto: &Crypto,
    transport: &Arc<quinn::TransportConfig>,
    datagram_frame: Option<u64>,
) -> Result<quinn::ClientConfig, BuildError> {
    let crypto: Arc<dyn quinn::crypto::ClientConfig> = match crypto {
        Crypto::Rustls(tls) => Arc::new(
            QuicClientConfig::try_from(tls.clone())
                .map_err(|err| BuildError::invalid(format!("quic tls: {err}")))?,
        ),
        Crypto::Custom(custom) => custom.clone(),
        Crypto::EchLookup(..) => {
            return Err(BuildError::invalid("the ECH lookup has not run"));
        }
    };
    let mut config = match datagram_frame {
        Some(frame) => quinn::ClientConfig::new(Arc::new(CappedFrame::new(crypto, frame))),
        None => quinn::ClientConfig::new(crypto),
    };
    config.transport_config(transport.clone());
    Ok(config)
}

impl QuicLink {
    async fn open_socket(
        &self,
        cx: &DialCx<'_>,
        remote: SocketAddr,
    ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        if let Some(via) = self.egress.via() {
            let inner = cx.enter(self.egress.name())?;
            let session = cx
                .env
                .nodes
                .associate_via(via, &inner, &Address::Socket(remote))
                .await?;
            return Ok(SessionSocket::new(session, remote, &self.tasks));
        }
        let opts = SockOpts {
            tunnel_udp_buffers: true,
            ..self.egress.sock_opts(cx.env)
        };
        let socket = cx.env.sockets.bind_udp(remote.ip(), &opts)?;
        TokioRuntime.wrap_udp_socket(socket.into_std()?)
    }

    /// `remote` with the first port the hopping schedule picked, if any.
    fn first_port(&self, mut remote: SocketAddr) -> SocketAddr {
        if let Some(hop) = &self.hop
            && !hop.ports.is_empty()
        {
            let pick = rand::rng().random_range(0..hop.ports.len());
            if let Some(port) = hop.ports.get(pick) {
                remote.set_port(*port);
            }
        }
        remote
    }

    async fn connect_to(&self, cx: &DialCx<'_>, remote: SocketAddr) -> io::Result<QuicConn> {
        let remote = self.first_port(remote);
        let raw = self.open_socket(cx, remote).await?;
        self.handshake(cx, raw, remote, EndpointConfig::default())
            .await
    }

    /// Dials the server's first address and completes the QUIC handshake, as mihomo's
    /// hysteria does. The hop schedule and the obfuscation are cloned, so one link can
    /// connect again after a drop.
    pub(crate) async fn connect(&self, cx: &DialCx<'_>) -> io::Result<QuicConn> {
        let proxy_cx = DialCx::new(cx.env, Initiator::Proxy, cx.deadline);
        let remote = resolve_server(&proxy_cx, &self.server, self.egress.version()).await?;
        self.connect_to(cx, remote).await
    }

    /// Like `connect`, but over every address of the server the way mihomo's dialer
    /// carries hysteria2, tuic and shadowquic: in order within a family, and the other
    /// family after a short head start.
    pub(crate) async fn connect_any(&self, cx: &DialCx<'_>) -> io::Result<QuicConn> {
        if self.egress.via().is_some() {
            return self.connect(cx).await;
        }
        let proxy_cx = DialCx::new(cx.env, Initiator::Proxy, cx.deadline);
        let sockets = &cx.env.sockets;
        dial_each(&proxy_cx, &self.server, self.egress.version(), |addr| {
            self.connect_to(cx, sockets.ip4p(addr))
        })
        .await
    }

    pub(crate) async fn connect_endpoint(
        &self,
        cx: &DialCx<'_>,
        endpoint: EndpointConfig,
    ) -> io::Result<QuicConn> {
        let proxy_cx = DialCx::new(cx.env, Initiator::Proxy, cx.deadline);
        let remote = resolve_server(&proxy_cx, &self.server, self.egress.version()).await?;
        let socket = self.open_socket(cx, remote).await?;
        self.handshake(cx, socket, remote, endpoint).await
    }

    /// Like `connect`, over a socket that already reaches `remote`.
    pub(crate) async fn connect_on(
        &self,
        cx: &DialCx<'_>,
        socket: std::net::UdpSocket,
        remote: SocketAddr,
    ) -> io::Result<QuicConn> {
        let raw = TokioRuntime.wrap_udp_socket(socket)?;
        self.handshake(cx, raw, remote, EndpointConfig::default())
            .await
    }

    async fn handshake(
        &self,
        cx: &DialCx<'_>,
        raw: Arc<dyn AsyncUdpSocket>,
        remote: SocketAddr,
        endpoint_config: EndpointConfig,
    ) -> io::Result<QuicConn> {
        let socket: Arc<dyn AsyncUdpSocket> = match (&self.obfs, &self.hop) {
            #[cfg(windows)]
            (ObfsSpec::None, None) => Arc::new(socket::SingleReceive(raw)),
            #[cfg(not(windows))]
            (ObfsSpec::None, None) => raw,
            (obfs, hop) => WrappedSocket::new(
                raw,
                obfs.build(),
                hop.as_ref().map(|hop| (remote.port(), hop.clone())),
                &self.tasks,
            ),
        };
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config,
            None,
            socket,
            Arc::new(TrackedRuntime(self.tasks.clone())),
        )?;
        let name = self
            .server_name
            .clone()
            .unwrap_or_else(|| remote.ip().to_string());
        let looked_up;
        let crypto = match &self.crypto {
            Crypto::EchLookup(tls, env) => {
                env.store(Some(Arc::new(cx.env.clone())));
                looked_up = Crypto::Rustls(tls.config(&name).await?);
                &looked_up
            }
            other => other,
        };
        let config = client_config(crypto, &self.transport, self.datagram_frame)
            .map_err(io::Error::other)?;
        let connecting = endpoint
            .connect_with(config, remote, &name)
            .map_err(io_error)?;
        let handshake = async { connecting.await.map_err(io_error) };
        let left = cx.remaining().unwrap_or(HANDSHAKE_IDLE);
        let conn = tokio::time::timeout(left, handshake)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        close_on_stop(&self.tasks, conn.clone());
        Ok(QuicConn {
            conn,
            endpoint,
            tasks: self.tasks.clone(),
        })
    }
}

/// The peer hears the connection close when the engine stops, as sing-box's outbounds send
/// CONNECTION_CLOSE from their `Close`.
fn close_on_stop(tasks: &Tasks, conn: quinn::Connection) {
    let stop = tasks.clone();
    tasks.spawn_to_end(async move {
        tokio::select! {
            () = stop.stopped() => conn.close(quinn::VarInt::from_u32(0), b""),
            _ = conn.closed() => {}
        }
    });
}

/// What a link keeps of its obfuscation; each connection builds its own state.
#[derive(Clone)]
pub(crate) enum ObfsSpec {
    None,
    Salamander(Vec<u8>),
    XPlus(Vec<u8>),
    WeChat(Option<Vec<u8>>),
    Gecko {
        password: Vec<u8>,
        min: usize,
        max: usize,
    },
}

impl ObfsSpec {
    fn build(&self) -> Obfs {
        match self {
            ObfsSpec::None => Obfs::None,
            ObfsSpec::Salamander(password) => Obfs::Seal(Box::new(Salamander::new(password))),
            ObfsSpec::XPlus(key) => Obfs::Seal(Box::new(XPlus::new(key))),
            ObfsSpec::WeChat(key) => Obfs::Seal(Box::new(WeChat::new(key.as_deref()))),
            ObfsSpec::Gecko { password, min, max } => match Gecko::new(password, *min, *max) {
                Ok(gecko) => Obfs::Gecko(Mutex::new(gecko)),
                Err(_) => Obfs::None,
            },
        }
    }

    pub(crate) fn check(&self) -> Result<(), String> {
        match self {
            ObfsSpec::Gecko { password, min, max } => Gecko::new(password, *min, *max).map(drop),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
pub(crate) fn obfuscated_socket(
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: &ObfsSpec,
) -> Arc<dyn AsyncUdpSocket> {
    WrappedSocket::new(inner, obfs.build(), None, &Default::default())
}

/// A bidirectional QUIC stream as a byte stream.
pub(crate) struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    _hold: Box<dyn Send + Sync>,
}

impl QuicStream {
    /// `hold` lives as long as the stream: the connection or the slot it counts against.
    pub(crate) fn new(send: SendStream, recv: RecvStream, hold: Box<dyn Send + Sync>) -> Self {
        QuicStream {
            send,
            recv,
            _hold: hold,
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, data)
            .map_err(io::Error::from)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

impl Stream for QuicStream {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let QuicStream { send, recv, _hold } = *self;
        let hold: Arc<dyn Send + Sync> = Arc::from(_hold);
        (
            Box::new(QuicRead {
                recv,
                _hold: hold.clone(),
            }),
            Box::new(QuicWrite { send, _hold: hold }),
        )
    }
}

struct QuicRead {
    recv: RecvStream,
    _hold: Arc<dyn Send + Sync>,
}

impl AsyncRead for QuicRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

struct QuicWrite {
    send: SendStream,
    _hold: Arc<dyn Send + Sync>,
}

impl AsyncWrite for QuicWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, data)
            .map_err(io::Error::from)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "loopback sockets exercise Quinn's receive-storage contract"
)]
mod receive_scratch_tests;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "the tests talk to a loopback endpoint directly"
)]
mod tests {
    use quinn::crypto::rustls::QuicClientConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::testing::quic_server;

    #[tokio::test]
    async fn the_halves_move_data_both_ways_and_the_hold_outlives_both() {
        let (server, port) = quic_server(b"h3", |socket| socket);
        let echo = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            send.write_all(b"down").await.unwrap();
            let mut got = Vec::new();
            recv.read_to_end(1024)
                .await
                .map(|bytes| got.extend(bytes))
                .unwrap();
            send.finish().unwrap();
            let _ = conn.closed().await;
            got
        });
        let options = TlsOptions {
            server_name: Some("localhost".to_string()),
            alpn: vec!["h3".to_string()],
            skip_cert_verify: true,
            ..TlsOptions::default()
        };
        let tls =
            concord_tls::quic_client_config(&options, TrustStore::new(b"", Vec::new()), &["h3"])
                .unwrap();
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(tls).unwrap(),
        )));
        let conn = endpoint
            .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();
        let witness = Arc::new(());
        let stream: concord_common::BoxStream =
            Box::new(QuicStream::new(send, recv, Box::new(witness.clone())));
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            (got, read)
        });
        write.write_all(b"up").await.unwrap();
        write.shutdown().await.unwrap();
        let (got, read) = reader.await.unwrap();
        assert_eq!(got, b"down");
        drop(write);
        assert_eq!(Arc::strong_count(&witness), 2);
        drop(read);
        assert_eq!(Arc::strong_count(&witness), 1);
        conn.close(0u32.into(), b"");
        assert_eq!(echo.await.unwrap(), b"up");
    }

    #[tokio::test]
    async fn a_stop_sends_connection_close_and_the_drivers_end_with_the_connection() {
        let (server, port) = quic_server(b"h3", |socket| socket);
        let peer = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            conn.closed().await
        });
        let tracked = crate::testing::Tracked::new();
        let options = TlsOptions {
            server_name: Some("localhost".to_string()),
            alpn: vec!["h3".to_string()],
            skip_cert_verify: true,
            ..TlsOptions::default()
        };
        let link = QuicLink {
            egress: crate::node::Egress::new("q", &Default::default()),
            server: Address::new("127.0.0.1", port),
            server_name: Some("localhost".to_string()),
            crypto: Crypto::Rustls(
                concord_tls::quic_client_config(
                    &options,
                    TrustStore::new(b"", Vec::new()),
                    &["h3"],
                )
                .unwrap(),
            ),
            transport: Arc::new(transport_config()),
            obfs: ObfsSpec::None,
            hop: None,
            datagram_frame: None,
            tasks: tracked.tasks.clone(),
        };
        let env = crate::testing::test_env();
        let conn = link
            .connect(&DialCx::new(&env, Initiator::Other, None))
            .await
            .unwrap();
        assert!(tracked.running() > 0, "the drivers are not tracked");
        tracked.stop();
        let closed = crate::testing::settled(peer).await;
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(_)),
            "{closed}"
        );
        drop(conn);
        assert!(tracked.ended_within(Duration::from_secs(5)).await);
    }
}
