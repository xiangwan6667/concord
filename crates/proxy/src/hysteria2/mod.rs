mod realm;
mod stream;
mod udp;
mod wire;

use std::io;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, DialEnv, Initiator, Outbound, OutboundInfo, OutboundKind,
    PacketSession, Tasks,
};
use concord_config::proxy::{Hysteria2Opts, ProxyDef};
use quinn::congestion::ControllerFactory;
use quinn::{IdleTimeout, TransportConfig, VarInt};
use tokio::sync::watch;

use self::realm::Realm;
use self::stream::Hy2Stream;
use self::udp::{Hub, Hy2Packets};
use crate::ctx::{BuildCtx, BuildError};
use crate::lazy::{HeadFirst, Kick};
use crate::node::{Egress, info_for};
use crate::quic::{
    BbrProfile, Brutal, Hop, ObfsSpec, QuicLink, QuicStream, SharedConn, SwitchFactory,
    bbr_factory, io_error, node_crypto,
};
use crate::session_slot::{SessionSlot, Ticket};
use crate::util::{lock, parse_bps, parse_ports};

/// quic-go's MaxDatagramSize, the `max_datagram_frame_size` a Hysteria2 server sees from
/// sing-box and mihomo; quinn would advertise its receive buffer instead.
const DATAGRAM_FRAME: u64 = 16_383;
const DEFAULT_STREAM_WINDOW: u64 = 8 * 1024 * 1024;
const DEFAULT_CONN_WINDOW: u64 = DEFAULT_STREAM_WINDOW * 5 / 2;
const MAX_IDLE: Duration = Duration::from_secs(30);
const KEEP_ALIVE: Duration = Duration::from_secs(10);
const DEFAULT_UDP_MTU: usize = 1200 - 3;
const MIN_HOP: u64 = 5;
const DEFAULT_HOP: u64 = 30;
const AUTH_OK: u16 = 233;
const DEFAULT_CWND: u32 = 32;

struct Hy2Conn {
    shared: SharedConn<Hub>,
    udp: bool,
}

impl Hy2Conn {
    fn alive(&self) -> bool {
        self.shared.alive()
    }

    fn close(&self) {
        self.shared.close();
    }
}

type Offer = Option<Result<Arc<Hy2Conn>, Arc<io::Error>>>;

/// A shared handshake's failure as each waiting caller gets it, with the error it carries
/// whole, so that one saying the process ran out of descriptors still says so.
#[derive(Debug)]
struct SharedFailure(Arc<io::Error>);

impl std::fmt::Display for SharedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SharedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

struct Hysteria2 {
    me: Weak<Hysteria2>,
    info: OutboundInfo,
    link: QuicLink,
    realm: Option<Realm>,
    password: String,
    up: u64,
    down: u64,
    udp_mtu: usize,
    handshake_timeout: Option<Duration>,
    controllers: Arc<SwitchFactory>,
    current: SessionSlot<Hy2Conn>,
    connecting: tokio::sync::Mutex<()>,
    pending: Mutex<Option<watch::Receiver<Offer>>>,
}

struct AuthReply {
    udp: bool,
    rx: u64,
    rx_auto: bool,
}

async fn authenticate(
    conn: &quinn::Connection,
    password: &str,
    rx: u64,
    tasks: &Tasks,
) -> io::Result<AuthReply> {
    let (mut driver, mut requests) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .map_err(io_error)?;
    tasks.spawn(async move {
        let _ = driver.wait_idle().await;
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", rx.to_string())
        .header("Hysteria-Padding", wire::padding(256, 2048))
        .body(())
        .map_err(io_error)?;
    let mut exchange = requests.send_request(request).await.map_err(io_error)?;
    exchange.finish().await.map_err(io_error)?;
    let response = exchange.recv_response().await.map_err(io_error)?;
    let held = conn.clone();
    tasks.spawn(async move {
        let _requests = requests;
        held.closed().await;
    });
    let status = response.status().as_u16();
    if status != AUTH_OK {
        return Err(io::Error::other(format!(
            "authentication failed, status code: {status}"
        )));
    }
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    let (rx, rx_auto) = match header("Hysteria-CC-RX") {
        Some("auto") => (0, true),
        Some(value) => (value.parse().unwrap_or(0), false),
        None => (0, false),
    };
    Ok(AuthReply {
        udp: header("Hysteria-UDP")
            .is_some_and(|value| matches!(value, "1" | "t" | "T" | "TRUE" | "true" | "True")),
        rx,
        rx_auto,
    })
}

impl Hysteria2 {
    async fn establish(&self, cx: &DialCx<'_>) -> io::Result<Arc<Hy2Conn>> {
        let quic = match &self.realm {
            Some(realm) => {
                let (socket, peer) = realm.punch(cx, &self.link.egress).await?;
                self.link.connect_on(cx, socket.into_std()?, peer).await?
            }
            None => self.link.connect_any(cx).await?,
        };
        let reply = authenticate(&quic.conn, &self.password, self.down, &quic.tasks).await?;
        let mut rate = reply.rx;
        if rate == 0 || rate > self.up {
            rate = self.up;
        }
        if !reply.rx_auto
            && rate > 0
            && let Some(switch) = self.controllers.handle()
        {
            switch.replace_brutal(Brutal::hysteria2(rate, quic.conn.rtt(), Instant::now()));
        }
        Ok(Arc::new(Hy2Conn {
            shared: SharedConn::new(quic, Hub::default()),
            udp: reply.udp,
        }))
    }

    async fn offer(&self, cx: &DialCx<'_>) -> io::Result<Arc<Hy2Conn>> {
        match self.handshake_timeout {
            None => {
                self.current
                    .offer(
                        &self.connecting,
                        Hy2Conn::alive,
                        || self.establish(cx),
                        |conn| conn.close(),
                    )
                    .await
            }
            Some(limit) => match self.current.get(Hy2Conn::alive) {
                (Some(conn), _) => Ok(conn),
                (None, _) => self.shared_offer(cx, limit).await,
            },
        }
    }

    /// sing-quic's offer with a handshake timeout: the handshake runs on its own under
    /// that limit and callers share it, so one that gives up stops waiting without
    /// cancelling a connection later dials can still use.
    async fn shared_offer(&self, cx: &DialCx<'_>, limit: Duration) -> io::Result<Arc<Hy2Conn>> {
        let mut offer = {
            let mut pending = lock(&self.pending);
            let (held, ticket) = self.current.get(Hy2Conn::alive);
            if let Some(conn) = held {
                return Ok(conn);
            }
            pending
                .get_or_insert_with(|| self.start_offer(cx.env.clone(), limit, ticket))
                .clone()
        };
        let settled = offer.wait_for(Option::is_some);
        let settled = match cx.remaining() {
            Some(left) => tokio::time::timeout(left, settled)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
            None => settled.await,
        };
        match settled
            .map_err(|_| io::Error::other("hysteria2 handshake was dropped"))?
            .clone()
        {
            Some(Ok(conn)) => Ok(conn),
            Some(Err(err)) => Err(io::Error::new(err.kind(), SharedFailure(err))),
            None => Err(io::Error::other("hysteria2 handshake was dropped")),
        }
    }

    /// A reset detaches the offer, so the callers that come after it start their own; the ones
    /// already waiting get the failure.
    fn start_offer(&self, env: DialEnv, limit: Duration, ticket: Ticket) -> watch::Receiver<Offer> {
        let (done, offer) = watch::channel(None);
        let me = self.me.clone();
        let mine = offer.clone();
        self.link.tasks.spawn(async move {
            let Some(me) = me.upgrade() else {
                return;
            };
            let cx = DialCx::new(&env, Initiator::Proxy, None);
            let result = tokio::time::timeout(limit, me.establish(&cx))
                .await
                .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)));
            let outcome = result
                .and_then(|conn| me.current.adopt(ticket, conn, |conn| conn.close()))
                .map_err(Arc::new);
            {
                let mut pending = lock(&me.pending);
                if pending
                    .as_ref()
                    .is_some_and(|held| held.same_channel(&mine))
                {
                    *pending = None;
                }
            }
            let _ = done.send(Some(outcome));
        });
        offer
    }
}

#[async_trait]
impl Outbound for Hysteria2 {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let conn = self.offer(cx).await?;
        let (send, recv) = conn.shared.quic.conn.open_bi().await.map_err(io_error)?;
        let head = wire::tcp_request(&dst.to_string());
        let stream = HeadFirst::new(QuicStream::new(send, recv, Box::new(conn)), head);
        Ok(Box::new(Kick::new(Hy2Stream::new(stream))))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let conn = self.offer(cx).await?;
        if !conn.udp {
            return Err(io::Error::other("UDP disabled by server"));
        }
        Ok(Arc::new(Hy2Packets::new(
            conn.shared.quic.conn.clone(),
            conn.shared.hub.clone(),
            self.udp_mtu,
            conn,
        )))
    }

    fn reset_sessions(&self) {
        *lock(&self.pending) = None;
        if let Some(conn) = self.current.reset() {
            conn.close();
        }
    }
}

fn hop_interval(text: &str) -> Result<(Duration, Duration), BuildError> {
    let parse = |value: &str| {
        value
            .trim()
            .parse::<u64>()
            .map_err(|_| BuildError::invalid(format!("invalid hop-interval: {text}")))
    };
    let (mut start, mut end) = match text.trim() {
        "" => (0, 0),
        other => match other.split_once('-') {
            Some((low, high)) => (parse(low)?, parse(high)?),
            None => (parse(other)?, parse(other)?),
        },
    };
    if start > end {
        (start, end) = (end, start);
    }
    start = if start == 0 {
        DEFAULT_HOP
    } else {
        start.max(MIN_HOP)
    };
    end = end.max(start);
    Ok((Duration::from_secs(start), Duration::from_secs(end)))
}

fn window(value: u64, fallback: u64) -> VarInt {
    VarInt::from_u64(if value == 0 { fallback } else { value }).unwrap_or(VarInt::MAX)
}

fn transport(opts: &Hysteria2Opts, controllers: Arc<SwitchFactory>) -> Arc<TransportConfig> {
    let mut config = crate::quic::transport_config();
    let stream_window = window(opts.max_stream_receive_window, DEFAULT_STREAM_WINDOW);
    let conn_window = window(opts.max_connection_receive_window, DEFAULT_CONN_WINDOW);
    config
        .max_idle_timeout(IdleTimeout::try_from(MAX_IDLE).ok())
        .keep_alive_interval(Some(KEEP_ALIVE))
        .stream_receive_window(stream_window)
        .receive_window(conn_window)
        .send_window(conn_window.into_inner().saturating_mul(2))
        .datagram_receive_buffer_size(Some(crate::quic::datagram_buffer(DATAGRAM_FRAME)))
        .congestion_controller_factory(controllers);
    Arc::new(config)
}

fn initial_controller(opts: &Hysteria2Opts) -> Arc<dyn ControllerFactory + Send + Sync> {
    bbr_factory(
        BbrProfile::parse(&opts.bbr_profile),
        u64::from(if opts.cwnd == 0 {
            DEFAULT_CWND
        } else {
            opts.cwnd
        }) * crate::quic::INITIAL_PACKET_SIZE,
    )
}

fn obfs_spec(opts: &Hysteria2Opts) -> Result<ObfsSpec, BuildError> {
    if opts.obfs.is_empty() {
        return Ok(ObfsSpec::None);
    }
    if opts.obfs_password.is_empty() {
        return Err(BuildError::invalid("missing obfs password"));
    }
    let password = opts.obfs_password.as_bytes().to_vec();
    let spec = match opts.obfs.as_str() {
        "salamander" => ObfsSpec::Salamander(password),
        "gecko" => ObfsSpec::Gecko {
            password,
            min: opts.obfs_min_packet_size as usize,
            max: opts.obfs_max_packet_size as usize,
        },
        other => return Err(BuildError::invalid(format!("unknown obfs type: {other}"))),
    };
    spec.check().map_err(BuildError::invalid)?;
    Ok(spec)
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &Hysteria2Opts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    Ok(build_hy2(def, opts, ctx)?)
}

fn build_hy2(
    def: &ProxyDef,
    opts: &Hysteria2Opts,
    ctx: &BuildCtx,
) -> Result<Arc<Hysteria2>, BuildError> {
    let ports = parse_ports(&opts.ports)?;
    if opts.port == 0 && ports.is_empty() {
        return Err(BuildError::invalid("invalid port"));
    }
    let realm = match opts.realm.as_ref().filter(|realm| realm.enable) {
        None => None,
        Some(_) if !ports.is_empty() => {
            return Err(BuildError::invalid(
                "realm and port hopping are mutually exclusive",
            ));
        }
        Some(_) if !def.common.dialer_proxy.is_empty() => {
            return Err(BuildError::unsupported(
                "hysteria2 realm-opts cannot be combined with dialer-proxy",
            ));
        }
        Some(realm) => Some(Realm::new(realm, ctx)?),
    };
    let hop = if ports.is_empty() {
        None
    } else {
        let (min, max) = hop_interval(&opts.hop_interval)?;
        Some(Hop { ports, min, max })
    };
    let (server_name, tls) = node_crypto(&opts.tls, &opts.server, "h3", ctx)?;
    let controllers = SwitchFactory::new(initial_controller(opts));
    let port = if opts.port == 0 {
        hop.as_ref()
            .and_then(|hop| hop.ports.first().copied())
            .unwrap_or(0)
    } else {
        opts.port
    };
    let link = QuicLink {
        egress: Egress::new(&def.name, &def.common),
        server: Address::new(&opts.server, port),
        server_name: Some(server_name),
        crypto: tls,
        transport: transport(opts, controllers.clone()),
        obfs: obfs_spec(opts)?,
        hop,
        datagram_frame: Some(DATAGRAM_FRAME),
        tasks: ctx.tasks.clone(),
    };
    Ok(Arc::new_cyclic(|me| Hysteria2 {
        me: me.clone(),
        info: info_for(def, OutboundKind::Hysteria2, &opts.server, opts.port, true),
        link,
        realm,
        password: opts.password.clone(),
        up: parse_bps(&opts.up),
        down: parse_bps(&opts.down),
        udp_mtu: if opts.udp_mtu == 0 {
            DEFAULT_UDP_MTU
        } else {
            opts.udp_mtu as usize
        },
        handshake_timeout: (opts.handshake_timeout > 0)
            .then(|| Duration::from_secs(u64::from(opts.handshake_timeout))),
        controllers,
        current: SessionSlot::default(),
        connecting: tokio::sync::Mutex::new(()),
        pending: Mutex::new(None),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hop_interval_is_clamped_like_mihomo() {
        let secs = |a: u64, b: u64| (Duration::from_secs(a), Duration::from_secs(b));
        assert_eq!(hop_interval("").unwrap(), secs(30, 30));
        assert_eq!(hop_interval("2").unwrap(), secs(5, 5));
        assert_eq!(hop_interval("10-20").unwrap(), secs(10, 20));
        assert_eq!(hop_interval("20-10").unwrap(), secs(10, 20));
        assert!(hop_interval("x").is_err());
    }

    fn build_node(extra: serde_json::Value) -> Result<Arc<dyn Outbound>, BuildError> {
        use concord_config::{Capabilities, ProxyParse, parse_proxy};
        let mut node = serde_json::json!({
            "name": "n", "type": "hysteria2", "server": "203.0.113.1", "port": 443, "password": "pw",
            "realm-opts": {
                "enable": true, "server-url": "https://realm.test", "realm-id": "r",
                "stun-servers": ["stun.test:3478"],
            },
        });
        node.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let Ok(ProxyParse::Ok(def)) = parse_proxy(node.as_object().unwrap(), &Capabilities::full())
        else {
            panic!("the node should parse");
        };
        crate::build_outbound(
            &def,
            &BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new())),
        )
    }

    #[test]
    fn a_realm_node_builds_and_rejects_what_cannot_go_with_it() {
        assert!(build_node(serde_json::json!({})).is_ok());
        let hopping = build_node(serde_json::json!({"ports": "1000-2000"}))
            .err()
            .unwrap();
        assert_eq!(
            hopping.to_string(),
            "realm and port hopping are mutually exclusive"
        );
        let chained = build_node(serde_json::json!({"dialer-proxy": "other"}))
            .err()
            .unwrap();
        assert!(chained.is_unsupported());
        let off = build_node(serde_json::json!({
            "ports": "1000-2000",
            "realm-opts": {"enable": false, "server-url": "https://realm.test"},
        }));
        assert!(off.is_ok());
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "a loopback socket that never answers"
    )]
    #[tokio::test]
    async fn a_caller_that_gives_up_leaves_the_handshake_running() {
        use concord_config::{Capabilities, ProxyParse, parse_proxy};
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let node = serde_json::json!({
            "name": "n", "type": "hysteria2", "server": "127.0.0.1",
            "port": silent.local_addr().unwrap().port(), "password": "pw",
            "handshake-timeout": 1,
        });
        let Ok(ProxyParse::Ok(def)) = parse_proxy(node.as_object().unwrap(), &Capabilities::full())
        else {
            panic!("does not parse");
        };
        let concord_config::proxy::ProxyKind::Hysteria2(opts) = &def.kind else {
            panic!("not hysteria2");
        };
        let ctx = BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new()));
        let built = build_hy2(&def, opts, &ctx).unwrap();
        let env = crate::testing::test_env();
        let soon = tokio::time::Instant::now() + Duration::from_millis(100);
        let cx = DialCx::new(&env, Initiator::Other, Some(soon));
        let err = built.offer(&cx).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(lock(&built.pending).is_some());

        let cx = DialCx::new(&env, Initiator::Other, None);
        let err = built.offer(&cx).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(lock(&built.pending).is_none());
    }

    /// A server that lets every client in and counts the connections it accepts.
    fn accepting_server(
        on_auth: impl Fn(quinn::Connection) + Clone + Send + 'static,
    ) -> (u16, Arc<std::sync::atomic::AtomicUsize>, quinn::Endpoint) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (endpoint, port) = crate::testing::quic_server(b"h3", |socket| socket);
        let accepted = Arc::new(AtomicUsize::new(0));
        let (listening, counted) = (endpoint.clone(), accepted.clone());
        tokio::spawn(async move {
            while let Some(incoming) = listening.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let on_auth = on_auth.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else {
                        return;
                    };
                    let Ok(mut server) = h3::server::Connection::<_, bytes::Bytes>::new(
                        h3_quinn::Connection::new(conn.clone()),
                    )
                    .await
                    else {
                        return;
                    };
                    if let Ok(Some(request)) = server.accept().await
                        && let Ok((_, mut stream)) = request.resolve_request().await
                    {
                        let reply = http::Response::builder()
                            .status(AUTH_OK)
                            .header("Hysteria-UDP", "false")
                            .body(())
                            .unwrap();
                        let _ = stream.send_response(reply).await;
                        let _ = stream.finish().await;
                        on_auth(conn.clone());
                    }
                    conn.closed().await;
                    drop(server);
                });
            }
        });
        (port, accepted, endpoint)
    }

    #[tokio::test]
    async fn server_udp_refusal_keeps_the_datagram_reader_running() {
        use concord_config::{Capabilities, ProxyParse, parse_proxy};
        let (authenticated, mut peers) = tokio::sync::mpsc::unbounded_channel();
        let (port, _, _server) = accepting_server(move |peer| {
            let _ = authenticated.send(peer);
        });
        let node = serde_json::json!({
            "name": "n", "type": "hysteria2", "server": "127.0.0.1", "port": port,
            "password": "pw", "sni": "localhost", "skip-cert-verify": true,
        });
        let Ok(ProxyParse::Ok(def)) = parse_proxy(node.as_object().unwrap(), &Capabilities::full())
        else {
            panic!("does not parse");
        };
        let concord_config::proxy::ProxyKind::Hysteria2(opts) = &def.kind else {
            panic!("not hysteria2");
        };
        let ctx = BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new()));
        let built = build_hy2(&def, opts, &ctx).unwrap();
        assert!(built.info().udp);
        let env = crate::testing::test_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let from = "127.0.0.1:53";
        let target = Address::parse(from).unwrap();
        let err = built.associate(&cx, &target).await.err().unwrap();
        assert_eq!(err.to_string(), "UDP disabled by server");

        let conn = built.offer(&cx).await.unwrap();
        let (session, mut packets) = conn.shared.hub.register();
        let limit = Duration::from_secs(2);
        let peer = tokio::time::timeout(limit, peers.recv())
            .await
            .unwrap()
            .unwrap();
        let mut data = Vec::new();
        wire::put_udp_header(
            &mut data,
            &wire::UdpHeader {
                session,
                packet: 0,
                fragment: 0,
                fragments: 1,
                addr: from,
            },
        );
        data.extend_from_slice(b"reader");
        peer.send_datagram(bytes::Bytes::from(data)).unwrap();

        let (addr, payload) = tokio::time::timeout(limit, packets.recv())
            .await
            .expect("the datagram reader did not dispatch")
            .unwrap();
        assert_eq!(addr, target);
        assert_eq!(payload.as_ref(), b"reader");
    }

    #[tokio::test]
    async fn a_connection_made_across_a_reset_is_not_kept() {
        use std::sync::atomic::Ordering;

        use concord_config::{Capabilities, ProxyParse, parse_proxy};
        for extra in [
            serde_json::json!({}),
            serde_json::json!({"handshake-timeout": 5}),
        ] {
            let (port, accepted, _server) = accepting_server(|_| {});
            let mut node = serde_json::json!({
                "name": "n", "type": "hysteria2", "server": "localhost", "port": port,
                "password": "pw", "sni": "localhost", "skip-cert-verify": true,
            });
            node.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let Ok(ProxyParse::Ok(def)) =
                parse_proxy(node.as_object().unwrap(), &Capabilities::full())
            else {
                panic!("does not parse");
            };
            let concord_config::proxy::ProxyKind::Hysteria2(opts) = &def.kind else {
                panic!("not hysteria2");
            };
            let ctx = BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new()));
            let built = build_hy2(&def, opts, &ctx).unwrap();
            let held = crate::testing::HeldLookup::new();
            let straddling = {
                let (built, env) = (built.clone(), held.env());
                tokio::spawn(async move {
                    let cx = DialCx::new(&env, Initiator::Other, None);
                    built.offer(&cx).await.map(drop)
                })
            };
            held.entered().await;
            built.reset_sessions();
            held.release();
            let outcome = crate::testing::settled(straddling).await;
            let env = crate::testing::test_env();
            built
                .offer(&DialCx::new(&env, Initiator::Other, None))
                .await
                .unwrap();
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                2,
                "{extra}: the next dial took the connection made before the reset"
            );
            assert!(outcome.is_err(), "{extra}");
        }
    }

    fn tracked_hy2(port: u16, tracked: &crate::testing::Tracked) -> Arc<Hysteria2> {
        use concord_config::{Capabilities, ProxyParse, parse_proxy};
        let node = serde_json::json!({
            "name": "n", "type": "hysteria2", "server": "localhost", "port": port,
            "password": "pw", "sni": "localhost", "skip-cert-verify": true,
        });
        let Ok(ProxyParse::Ok(def)) = parse_proxy(node.as_object().unwrap(), &Capabilities::full())
        else {
            panic!("does not parse");
        };
        let concord_config::proxy::ProxyKind::Hysteria2(opts) = &def.kind else {
            panic!("not hysteria2");
        };
        build_hy2(&def, opts, &tracked.ctx()).unwrap()
    }

    #[tokio::test]
    async fn a_stop_ends_a_connection_s_tasks_once_the_outbound_is_gone() {
        let (authenticated, mut peers) = tokio::sync::mpsc::unbounded_channel();
        let (port, _, _server) = accepting_server(move |peer| {
            let _ = authenticated.send(peer);
        });
        let tracked = crate::testing::Tracked::new();
        let built = tracked_hy2(port, &tracked);
        let env = crate::testing::test_env();
        built
            .offer(&DialCx::new(&env, Initiator::Other, None))
            .await
            .unwrap();
        let peer = peers.recv().await.unwrap();
        assert!(tracked.running() > 0, "the connection is not tracked");
        tracked.stop();
        tokio::time::timeout(Duration::from_secs(5), peer.closed())
            .await
            .expect("the server never learned the connection closed");
        drop(built);
        assert!(tracked.ended_within(Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn a_connection_s_tasks_end_when_its_outbound_is_dropped() {
        let (port, _, _server) = accepting_server(|_| {});
        let tracked = crate::testing::Tracked::new();
        let built = tracked_hy2(port, &tracked);
        let env = crate::testing::test_env();
        built
            .offer(&DialCx::new(&env, Initiator::Other, None))
            .await
            .unwrap();
        assert!(tracked.running() > 0, "the connection is not tracked");
        drop(built);
        assert!(tracked.ended_within(Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn running_out_of_descriptors_reaches_the_callers_of_a_shared_handshake() {
        use concord_config::{Capabilities, ProxyParse, parse_proxy};
        let node = serde_json::json!({
            "name": "n", "type": "hysteria2", "server": "127.0.0.1", "port": 9,
            "password": "pw", "handshake-timeout": 5,
        });
        let Ok(ProxyParse::Ok(def)) = parse_proxy(node.as_object().unwrap(), &Capabilities::full())
        else {
            panic!("does not parse");
        };
        let concord_config::proxy::ProxyKind::Hysteria2(opts) = &def.kind else {
            panic!("not hysteria2");
        };
        let ctx = BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new()));
        let built = build_hy2(&def, opts, &ctx).unwrap();
        let env = DialEnv {
            sockets: Arc::new(concord_net::Sockets::new(Arc::new(
                crate::testing::Pressured,
            ))),
            ..crate::testing::test_env()
        };
        let cx = DialCx::new(&env, Initiator::Other, None);
        let err = built.offer(&cx).await.err().unwrap();
        assert!(concord_platform::is_local_exhaustion(&err), "{err}");
    }
}
