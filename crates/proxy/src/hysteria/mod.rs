mod stream;
mod udp;
mod wire;

#[cfg(test)]
mod tests;

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{HysteriaOpts, ProxyDef};
use quinn::congestion::ControllerFactory;
use quinn::{IdleTimeout, SendStream, TransportConfig, VarInt};
use tokio::io::AsyncWriteExt;

use self::stream::FastOpen;
use self::udp::{Hub, Hy1Packets};
use self::wire::{client_hello, client_request, read_server_hello, read_server_response};
use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Egress, info_for};
use crate::quic::{
    Brutal, Hop, ObfsSpec, QuicConn, QuicLink, QuicStream, SharedConn, SwitchFactory, io_error,
    node_crypto,
};
use crate::session_slot::SessionSlot;
use crate::util::{parse_bps, parse_ports};

const DEFAULT_STREAM_WINDOW: u64 = 15_728_640;
const DEFAULT_CONN_WINDOW: u64 = 67_108_864;
const QUIC_STREAM_WINDOW: u64 = 6 * 1024 * 1024;
const MAX_IDLE: Duration = Duration::from_secs(30);
const KEEP_ALIVE: Duration = Duration::from_secs(10);
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_HOP_SECS: u64 = 10;
/// A hysteria 1 server sizes its datagrams by the advertised
/// `max_datagram_frame_size` alone, never by the packet size, so anything above
/// what quic-go itself advertises leaves a reply that fits no packet at the head
/// of the server's queue.
const DATAGRAM_FRAME: u64 = 1200;
const MBPS: u64 = 125_000;
const BRUTAL_MTU: u16 = 1200;
const CLOSE_PROTOCOL: u32 = 1;
const CLOSE_AUTH: u32 = 2;

struct Hy1Conn {
    shared: SharedConn<Hub>,
    _control: QuicStream,
}

impl Hy1Conn {
    fn alive(&self) -> bool {
        self.shared.alive()
    }

    fn close(&self) {
        self.shared.close();
    }
}

struct Hysteria {
    info: OutboundInfo,
    link: QuicLink,
    auth: Vec<u8>,
    up: u64,
    down: u64,
    fast_open: bool,
    controllers: Arc<SwitchFactory>,
    current: SessionSlot<Hy1Conn>,
    connecting: tokio::sync::Mutex<()>,
}

impl Hysteria {
    async fn handshake(&self, quic: &QuicConn) -> io::Result<QuicStream> {
        let (send, recv) = tokio::time::timeout(PROTOCOL_TIMEOUT, quic.conn.open_bi())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io_error)?;
        let mut control = QuicStream::new(send, recv, Box::new(()));
        control
            .write_all(&client_hello(self.up, self.down, &self.auth)?)
            .await?;
        control.flush().await?;
        let hello = read_server_hello(&mut control).await?;
        if !hello.ok {
            quic.conn.close(VarInt::from_u32(CLOSE_AUTH), b"auth error");
            return Err(io::Error::other(format!("auth error: {}", hello.message)));
        }
        let rate = if hello.recv_bps == 0 {
            self.up
        } else {
            hello.recv_bps
        };
        if let Some(switch) = self.controllers.handle() {
            switch.replace(Box::new(Brutal::new(rate, BRUTAL_MTU, Instant::now())));
        }
        Ok(control)
    }

    async fn establish(&self, cx: &DialCx<'_>) -> io::Result<Arc<Hy1Conn>> {
        let quic = self.link.connect(cx).await?;
        let control = match self.handshake(&quic).await {
            Ok(control) => control,
            Err(err) => {
                quic.conn
                    .close(VarInt::from_u32(CLOSE_PROTOCOL), b"protocol error");
                return Err(err);
            }
        };
        Ok(Arc::new(Hy1Conn {
            shared: SharedConn::new(quic, Hub::default()),
            _control: control,
        }))
    }

    async fn offer(&self, cx: &DialCx<'_>) -> io::Result<Arc<Hy1Conn>> {
        self.current
            .offer(
                &self.connecting,
                Hy1Conn::alive,
                || self.establish(cx),
                |conn| conn.close(),
            )
            .await
    }

    fn forget(&self, conn: &Arc<Hy1Conn>) {
        self.current.forget(conn);
    }

    /// A connection that fails to open a stream is replaced once, as the
    /// reference client does for a permanent error.
    async fn open_stream(
        &self,
        cx: &DialCx<'_>,
    ) -> io::Result<(Arc<Hy1Conn>, SendStream, quinn::RecvStream)> {
        let mut last = None;
        for _ in 0..2 {
            let conn = self.offer(cx).await?;
            match conn.shared.quic.conn.open_bi().await {
                Ok((send, recv)) => return Ok((conn, send, recv)),
                Err(err) => {
                    self.forget(&conn);
                    last = Some(io_error(err));
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotConnected)))
    }

    async fn request(
        &self,
        cx: &DialCx<'_>,
        udp: bool,
        host: &str,
        port: u16,
    ) -> io::Result<(Arc<Hy1Conn>, QuicStream)> {
        let (conn, send, recv) = self.open_stream(cx).await?;
        let mut stream = QuicStream::new(send, recv, Box::new(conn.clone()));
        stream.write_all(&client_request(udp, host, port)?).await?;
        Ok((conn, stream))
    }
}

#[async_trait]
impl Outbound for Hysteria {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let (_conn, mut stream) = self
            .request(cx, false, &dst.host_string(), dst.port())
            .await?;
        if self.fast_open {
            return Ok(Box::new(FastOpen::new(stream)));
        }
        let response = read_server_response(&mut stream).await?;
        if !response.ok {
            return Err(io::Error::other(format!(
                "connection rejected: {}",
                response.message
            )));
        }
        Ok(Box::new(stream))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let (conn, mut stream) = self.request(cx, true, "", 0).await?;
        let response = read_server_response(&mut stream).await?;
        if !response.ok {
            return Err(io::Error::other(format!(
                "connection rejected: {}",
                response.message
            )));
        }
        Ok(Arc::new(Hy1Packets::new(
            conn.shared.quic.conn.clone(),
            conn.shared.hub.clone(),
            response.session,
            stream,
            conn,
            &self.link.tasks,
        )))
    }

    fn reset_sessions(&self) {
        if let Some(conn) = self.current.reset() {
            conn.close();
        }
    }
}

fn transport(opts: &HysteriaOpts, controllers: Arc<SwitchFactory>) -> Arc<TransportConfig> {
    let (stream, conn) = if opts.recv_window == 0 {
        (DEFAULT_STREAM_WINDOW, DEFAULT_CONN_WINDOW)
    } else if opts.recv_window_conn == 0 {
        (QUIC_STREAM_WINDOW, u64::from(opts.recv_window))
    } else {
        (
            u64::from(opts.recv_window_conn),
            u64::from(opts.recv_window),
        )
    };
    let mut config = crate::quic::transport_config();
    config
        .max_idle_timeout(IdleTimeout::try_from(MAX_IDLE).ok())
        .keep_alive_interval(Some(KEEP_ALIVE))
        .stream_receive_window(VarInt::from_u64(stream).unwrap_or(VarInt::MAX))
        .receive_window(VarInt::from_u64(conn).unwrap_or(VarInt::MAX))
        .send_window(conn.saturating_mul(2))
        .datagram_receive_buffer_size(Some(crate::quic::datagram_buffer(DATAGRAM_FRAME)))
        .congestion_controller_factory(controllers);
    if opts.disable_mtu_discovery {
        config.mtu_discovery_config(None);
    }
    Arc::new(config)
}

fn auth(opts: &HysteriaOpts) -> Result<Vec<u8>, BuildError> {
    if opts.auth.is_empty() {
        return Ok(opts.auth_str.as_bytes().to_vec());
    }
    STANDARD
        .decode(&opts.auth)
        .map_err(|err| BuildError::invalid(format!("hysteria auth: {err}")))
}

fn rates(opts: &HysteriaOpts) -> Result<(u64, u64), BuildError> {
    let up = parse_bps(&opts.up);
    if up == 0 {
        return Err(BuildError::invalid(format!(
            "invaild upload speed: {}",
            opts.up
        )));
    }
    let down = parse_bps(&opts.down);
    if down == 0 {
        return Err(BuildError::invalid(format!(
            "invaild download speed: {}",
            opts.down
        )));
    }
    let mbps = |value: u32, fallback: u64| {
        if value == 0 {
            fallback
        } else {
            u64::from(value) * MBPS
        }
    };
    Ok((mbps(opts.up_speed, up), mbps(opts.down_speed, down)))
}

fn protocol(opts: &HysteriaOpts) -> &str {
    [opts.obfs_protocol.as_str(), opts.protocol.as_str()]
        .into_iter()
        .find(|name| !name.is_empty())
        .unwrap_or("udp")
}

fn obfs_spec(opts: &HysteriaOpts) -> Result<ObfsSpec, BuildError> {
    let key = Some(opts.obfs.as_bytes().to_vec()).filter(|key| !key.is_empty());
    match protocol(opts) {
        "udp" => Ok(key.map_or(ObfsSpec::None, ObfsSpec::XPlus)),
        "wechat-video" => Ok(ObfsSpec::WeChat(key)),
        "faketcp" => Err(BuildError::unsupported(
            "hysteria protocol faketcp needs raw sockets and is not implemented",
        )),
        other => Err(BuildError::invalid(format!(
            "unsupported protocol: {other}"
        ))),
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &HysteriaOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let (up, down) = rates(opts)?;
    let auth = auth(opts)?;
    let obfs = obfs_spec(opts)?;
    let hopping = matches!(obfs, ObfsSpec::None | ObfsSpec::XPlus(_));
    let ports = if hopping {
        parse_ports(&opts.ports)?
    } else {
        Vec::new()
    };
    if opts.port == 0 && ports.is_empty() {
        return Err(BuildError::invalid("invalid port"));
    }
    let hop = (!ports.is_empty()).then(|| {
        let every = Duration::from_secs(match opts.hop_interval {
            0 => DEFAULT_HOP_SECS,
            secs => u64::from(secs),
        });
        Hop {
            ports: ports.clone(),
            min: every,
            max: every,
        }
    });
    let (server_name, tls) = node_crypto(&opts.tls, &opts.server, "hysteria", ctx)?;
    let initial: Arc<dyn ControllerFactory + Send + Sync> = Arc::new(crate::quic::cubic());
    let controllers = SwitchFactory::new(initial);
    let port = if opts.port == 0 {
        ports.first().copied().unwrap_or(0)
    } else {
        opts.port
    };
    let link = QuicLink {
        egress: Egress::new(&def.name, &def.common),
        server: Address::new(&opts.server, port),
        server_name: Some(server_name),
        crypto: tls,
        transport: transport(opts, controllers.clone()),
        obfs,
        hop,
        datagram_frame: Some(DATAGRAM_FRAME),
        tasks: ctx.tasks.clone(),
    };
    Ok(Arc::new(Hysteria {
        info: info_for(def, OutboundKind::Hysteria, &opts.server, opts.port, true),
        link,
        auth,
        up,
        down,
        fast_open: opts.fast_open,
        controllers,
        current: SessionSlot::default(),
        connecting: tokio::sync::Mutex::new(()),
    }))
}
