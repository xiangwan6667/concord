mod conn;
mod stream;
mod udp;
mod wire;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{ProxyDef, TuicOpts};
use quinn::congestion::ControllerFactory;
use quinn::{IdleTimeout, TransportConfig, VarInt};

use self::conn::Pool;
use self::stream::{V4Response, check_response};
use self::udp::{Relay, TuicPackets};
use self::wire::Version;
use crate::ctx::{BuildCtx, BuildError};
use crate::lazy::{HeadFirst, Kick};
use crate::node::{Egress, info_for};
use crate::quic::{BbrProfile, ObfsSpec, QuicLink, QuicStream, bbr_factory, io_error, node_crypto};
use crate::uot;

const DEFAULT_STREAM_WINDOW: u64 = 15_728_640;
const DEFAULT_CONN_WINDOW: u64 = 67_108_864;
const MAX_FRAME: usize = 1400;
const UDP_PACKET: usize = 1252;
const MAX_OPEN_STREAMS: u32 = 100;
const MAX_IDLE: Duration = Duration::from_secs(30);
const DEFAULT_CWND: u64 = 32;
const MAX_FRAG_V5: usize = 1200 - wire::V5_OVERHEAD - 3;

pub(crate) struct Shared {
    pub(crate) link: QuicLink,
    pub(crate) version: Version,
    pub(crate) uuid: [u8; 16],
    pub(crate) password: String,
    pub(crate) token: [u8; 32],
    pub(crate) native: bool,
}

struct Tuic {
    info: OutboundInfo,
    shared: Arc<Shared>,
    tcp: Pool,
    udp: Pool,
    max_open: i64,
    max_packet: usize,
    request_timeout: Duration,
    fast_open: bool,
    uot: Option<u8>,
}

impl Tuic {
    async fn open_stream(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let slot = self.tcp.pick(false, self.max_open);
        let live = slot.live(&self.shared, cx).await?;
        let counted = slot.count();
        let (mut send, mut recv) = live.quic.conn.open_bi().await.map_err(io_error)?;
        let head = wire::connect(self.shared.version, dst)?;
        if self.shared.version == Version::V5 {
            let stream =
                HeadFirst::new(QuicStream::new(send, recv, Box::new((live, counted))), head);
            return Ok(Box::new(Kick::new(stream)));
        }
        if self.fast_open {
            let stream =
                HeadFirst::new(QuicStream::new(send, recv, Box::new((live, counted))), head);
            return Ok(Box::new(Kick::new(V4Response::new(
                stream,
                self.request_timeout,
            ))));
        }
        send.write_all(&head).await.map_err(io_error)?;
        let mut answer = [0u8; 3];
        let read = recv.read_exact(&mut answer);
        let read = if self.request_timeout.is_zero() {
            read.await
        } else {
            tokio::time::timeout(self.request_timeout, read)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        };
        read.map_err(io_error)?;
        check_response(&answer)?;
        Ok(Box::new(QuicStream::new(
            send,
            recv,
            Box::new((live, counted)),
        )))
    }
}

#[async_trait]
impl Outbound for Tuic {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        self.open_stream(cx, dst).await
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if let Some(version) = self.uot {
            let stream = self.open_stream(cx, &uot::destination(version)).await?;
            return uot::session(stream, version, hint, &self.shared.link.tasks);
        }
        let slot = self.udp.pick(true, self.max_open);
        let live = slot.live(&self.shared, cx).await?;
        let relay = Relay {
            version: self.shared.version,
            native: self.shared.native,
            max_packet: self.max_packet,
        };
        Ok(Arc::new(TuicPackets::new(live, relay, slot.count())?))
    }

    fn reset_sessions(&self) {
        self.tcp.close();
        self.udp.close();
    }
}

fn controller(
    opts: &TuicOpts,
) -> Result<Option<Arc<dyn ControllerFactory + Send + Sync>>, BuildError> {
    let cwnd = if opts.cwnd == 0 {
        DEFAULT_CWND
    } else {
        u64::from(opts.cwnd)
    };
    Ok(match opts.congestion_controller.as_str() {
        "cubic" => Some(Arc::new(crate::quic::cubic())),
        "new_reno" => Some(Arc::new(crate::quic::new_reno())),
        "bbr" | "bbr_meta_v1" | "bbr_meta_v2" => Some(bbr_factory(
            BbrProfile::parse(&opts.bbr_profile),
            cwnd * crate::quic::INITIAL_PACKET_SIZE,
        )),
        _ => None,
    })
}

fn window(value: u32, fallback: u64) -> VarInt {
    VarInt::from_u64(if value == 0 {
        fallback
    } else {
        u64::from(value)
    })
    .unwrap_or(VarInt::MAX)
}

fn transport(
    opts: &TuicOpts,
    heartbeat: Duration,
    max_open: u32,
    frame: usize,
) -> Result<Arc<TransportConfig>, BuildError> {
    let mut config = crate::quic::transport_config();
    let streams = u64::from(max_open + max_open.div_ceil(10));
    config
        .max_idle_timeout(IdleTimeout::try_from(MAX_IDLE).ok())
        .keep_alive_interval(Some(heartbeat))
        .stream_receive_window(window(opts.recv_window_conn, DEFAULT_STREAM_WINDOW))
        .receive_window(window(opts.recv_window, DEFAULT_CONN_WINDOW))
        .max_concurrent_bidi_streams(VarInt::from_u64(streams).unwrap_or(VarInt::MAX))
        .max_concurrent_uni_streams(VarInt::from_u64(streams).unwrap_or(VarInt::MAX))
        .datagram_receive_buffer_size(Some(crate::quic::datagram_buffer(
            u64::try_from(frame).unwrap_or(u64::MAX),
        )));
    if opts.disable_mtu_discovery {
        config.mtu_discovery_config(None);
    }
    if let Some(factory) = controller(opts)? {
        config.congestion_controller_factory(factory);
    }
    Ok(Arc::new(config))
}

fn parse_uuid(text: &str) -> Result<[u8; 16], BuildError> {
    uuid::Uuid::parse_str(text)
        .map(|uuid| *uuid.as_bytes())
        .map_err(|_| BuildError::invalid("invalid tuic uuid"))
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &TuicOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let version = if opts.token.is_empty() {
        Version::V5
    } else {
        Version::V4
    };
    let uuid = if version == Version::V5 {
        parse_uuid(&opts.uuid)?
    } else {
        [0; 16]
    };
    let mut tls_def = opts.tls.clone();
    if opts.disable_sni {
        tls_def.skip_cert_verify = true;
    }
    let (server_name, tls) = node_crypto(&tls_def, &opts.server, "h3", ctx)?;

    let heartbeat = Duration::from_millis(if opts.heartbeat_interval == 0 {
        10_000
    } else {
        u64::from(opts.heartbeat_interval)
    });
    let request_timeout = Duration::from_millis(if opts.request_timeout == 0 {
        8_000
    } else {
        u64::from(opts.request_timeout)
    });
    let max_open = if opts.max_open_streams == 0 {
        MAX_OPEN_STREAMS
    } else {
        opts.max_open_streams
    };
    let client_max_open = if max_open == MAX_OPEN_STREAMS {
        max_open - max_open.div_ceil(10)
    } else {
        max_open
    }
    .max(1);

    let overhead = match version {
        Version::V5 => wire::V5_OVERHEAD,
        Version::V4 => wire::V4_OVERHEAD,
    };
    let requested = if opts.max_udp_relay_packet_size == 0 {
        UDP_PACKET
    } else {
        opts.max_udp_relay_packet_size as usize
    };
    let frame = if opts.max_datagram_frame_size == 0 {
        requested + overhead
    } else {
        opts.max_datagram_frame_size as usize
    }
    .min(MAX_FRAME);
    let mut max_packet = frame.saturating_sub(overhead).max(1);
    if version == Version::V5 {
        max_packet = max_packet.min(MAX_FRAG_V5);
    }

    let stream_version = match opts.udp_over_stream_version {
        0 | uot::LEGACY_VERSION => uot::LEGACY_VERSION,
        2 => 2,
        other => {
            return Err(BuildError::invalid(format!(
                "tuic {} unknown udp over stream protocol version: {other}",
                opts.server
            )));
        }
    };
    let uot = opts.udp_over_stream.then_some(stream_version);

    let host = if opts.ip.is_empty() {
        &opts.server
    } else {
        &opts.ip
    };
    let link = QuicLink {
        egress: Egress::new(&def.name, &def.common),
        server: Address::new(host, opts.port),
        server_name: (!opts.disable_sni).then_some(server_name),
        crypto: tls,
        transport: transport(opts, heartbeat, client_max_open, frame)?,
        obfs: ObfsSpec::None,
        hop: None,
        datagram_frame: u64::try_from(frame).ok(),
        tasks: ctx.tasks.clone(),
    };
    let shared = Arc::new(Shared {
        link,
        version,
        uuid,
        password: opts.password.clone(),
        token: *blake3::hash(opts.token.as_bytes()).as_bytes(),
        native: opts.udp_relay_mode != "quic",
    });
    Ok(Arc::new(Tuic {
        info: info_for(def, OutboundKind::Tuic, &opts.server, opts.port, true),
        shared,
        tcp: Pool::default(),
        udp: Pool::default(),
        max_open: i64::from(client_max_open),
        max_packet,
        request_timeout,
        fast_open: opts.fast_open,
        uot,
    }))
}
