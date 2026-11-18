pub(crate) mod crypto;
mod stream;

use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketBuf, PacketSession,
};
use concord_config::proxy::{ProxyDef, VmessOpts};

use self::crypto::{CHUNK, CMD_MUX, CMD_TCP, CMD_UDP, Request, Security};
use self::stream::{BoxedVmess, VmessCfg, VmessStream};
use crate::addr_codec::{MAX_ADDR_LEN, PACKET_ADDR, VMESS};
use crate::ctx::{BuildCtx, BuildError};
use crate::dgram::{Decoded, Decoder, Encoder, StreamSession};
use crate::lazy::Kick;
use crate::link::{Flavor, LinkSpec, build_link};
use crate::node::{Link, info_for};
use crate::util::{invalid_data, lock};

const PACKET_ADDR_MAGIC: &str = "sp.packet-addr.v2fly.arpa";
const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const NETWORK_UDP: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpMode {
    Plain,
    PacketAddr,
    Xudp,
}

pub(crate) fn udp_mode(packet_addr: bool, xudp: bool, encoding: &str) -> UdpMode {
    let (mut packet_addr, mut xudp) = (packet_addr, xudp);
    match encoding {
        "packetaddr" | "packet" => packet_addr = true,
        "xudp" => xudp = true,
        _ => {}
    }
    if xudp {
        packet_addr = false;
    }
    match (xudp, packet_addr) {
        (true, _) => UdpMode::Xudp,
        (_, true) => UdpMode::PacketAddr,
        _ => UdpMode::Plain,
    }
}

struct Vmess {
    info: OutboundInfo,
    link: Link,
    cfg: Arc<VmessCfg>,
    mode: UdpMode,
}

impl Vmess {
    fn stream(&self, io: BoxStream, command: u8, dst: Address) -> io::Result<BoxedVmess> {
        let request = Request::new(
            self.cfg.security,
            command,
            self.cfg.global_padding,
            self.cfg.authenticated_length,
        );
        VmessStream::new(io, self.cfg.clone(), request, dst)
    }
}

#[async_trait]
impl Outbound for Vmess {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let io = self.link.open(cx).await?;
        Ok(Box::new(Kick::new(self.stream(
            io,
            CMD_TCP,
            dst.clone(),
        )?)))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let io = self.link.open(cx).await?;
        match self.mode {
            UdpMode::Xudp => {
                let stream = self.stream(io, CMD_MUX, hint.clone())?;
                Ok(Arc::new(StreamSession::new(
                    Box::new(stream),
                    XudpFrames::new(cx.source()),
                    XudpFrames::new(None),
                    hint.clone(),
                    self.link.tasks(),
                )))
            }
            UdpMode::PacketAddr => {
                let magic = Address::new(PACKET_ADDR_MAGIC, 443);
                Ok(Arc::new(VmessPackets::new(
                    self.stream(io, CMD_UDP, magic)?,
                    hint.clone(),
                    true,
                )))
            }
            UdpMode::Plain => Ok(Arc::new(VmessPackets::new(
                self.stream(io, CMD_UDP, hint.clone())?,
                hint.clone(),
                false,
            ))),
        }
    }

    fn multi_destination_udp(&self) -> bool {
        self.mode != UdpMode::Plain
    }
}

/// Datagrams that are one VMess chunk each.
struct VmessPackets {
    stream: Mutex<BoxedVmess>,
    remote: Address,
    packet_addr: bool,
    inflight: AtomicUsize,
    closed: AtomicBool,
}

impl VmessPackets {
    fn new(stream: BoxedVmess, remote: Address, packet_addr: bool) -> Self {
        VmessPackets {
            stream: Mutex::new(stream),
            remote,
            packet_addr,
            inflight: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        }
    }
}

impl PacketSession for VmessPackets {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let queued = self.inflight.load(Ordering::Relaxed);
        if queued == 0 || queued != pkt.len() {
            if self.packet_addr {
                let len = PACKET_ADDR.len(dst);
                PACKET_ADDR.write_into(dst, pkt.prepend(len))?;
            } else if dst != &self.remote {
                return Poll::Ready(Err(io::Error::other(
                    "udp packet dropped due to mismatched remote address",
                )));
            }
        }
        if pkt.len() > CHUNK {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram larger than a vmess chunk",
            )));
        }
        let result = lock(&self.stream).poll_send(cx, pkt.as_slice());
        match result {
            Poll::Pending => {
                self.inflight.store(pkt.len(), Ordering::Relaxed);
                Poll::Pending
            }
            Poll::Ready(outcome) => {
                self.inflight.store(0, Ordering::Relaxed);
                match outcome {
                    Ok(n) if n == pkt.len() => Poll::Ready(Ok(())),
                    Ok(_) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>, out: &mut PacketBuf) -> Poll<io::Result<Address>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let mut stream = lock(&self.stream);
        let range = match stream.poll_recv_chunk(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(None)) => return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
            Poll::Ready(Ok(Some(range))) => range,
        };
        let data = stream.chunk(range);
        if !self.packet_addr {
            out.extend_from_slice(data);
            return Poll::Ready(Ok(self.remote.clone()));
        }
        let Some((addr, used)) = PACKET_ADDR.parse(data)? else {
            return Poll::Ready(Err(invalid_data("short packet-addr packet")));
        };
        out.extend_from_slice(data.get(used..).unwrap_or_default());
        Poll::Ready(Ok(addr))
    }

    fn headroom(&self) -> usize {
        MAX_ADDR_LEN
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

/// XUDP: v2ray mux frames carrying one datagram each, on a connection opened
/// with the mux command.
pub(crate) struct XudpFrames {
    first: bool,
    global_id: [u8; 8],
}

impl XudpFrames {
    pub(crate) fn new(source: Option<SocketAddr>) -> Self {
        XudpFrames {
            first: true,
            global_id: source.map(global_id).unwrap_or_default(),
        }
    }
}

/// mihomo's `utils.GlobalID`: a per-process keyed hash of the client address, which an
/// XUDP server uses to hand a reconnecting client its old session.
fn global_id(source: SocketAddr) -> [u8; 8] {
    static SEED: OnceLock<RandomState> = OnceLock::new();
    if source.port() == 0 {
        return [0; 8];
    }
    SEED.get_or_init(RandomState::new)
        .hash_one(source)
        .to_le_bytes()
}

impl Encoder for XudpFrames {
    fn headroom(&self) -> usize {
        2 + 5 + MAX_ADDR_LEN + 8 + 2
    }

    fn encode(&mut self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        let data_len = u16::try_from(pkt.len()).map_err(|_| invalid_data("datagram too long"))?;
        let addr_len = VMESS.len(dst);
        let id_len = if self.first && self.global_id != [0; 8] {
            self.global_id.len()
        } else {
            0
        };
        let meta =
            u16::try_from(5 + addr_len + id_len).map_err(|_| invalid_data("address too long"))?;
        let head = pkt.prepend(2 + 5 + addr_len + id_len + 2);
        let (lead, rest) = head.split_at_mut(7);
        lead.get_mut(..2)
            .ok_or_else(|| invalid_data("buffer"))?
            .copy_from_slice(&meta.to_be_bytes());
        lead.get_mut(2..4)
            .ok_or_else(|| invalid_data("buffer"))?
            .fill(0);
        let (status, option, network) = (
            if self.first { STATUS_NEW } else { STATUS_KEEP },
            1u8,
            NETWORK_UDP,
        );
        lead.get_mut(4..7)
            .ok_or_else(|| invalid_data("buffer"))?
            .copy_from_slice(&[status, option, network]);
        let (addr, tail) = rest.split_at_mut(addr_len);
        VMESS.write_into(dst, addr)?;
        let (id, len) = tail.split_at_mut(id_len);
        id.copy_from_slice(self.global_id.get(..id_len).unwrap_or_default());
        len.copy_from_slice(&data_len.to_be_bytes());
        self.first = false;
        Ok(())
    }
}

impl Decoder for XudpFrames {
    fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded> {
        let Some(&[hi, lo]) = input.get(..2) else {
            return Ok(Decoded::NeedMore);
        };
        let meta_len = usize::from(u16::from_be_bytes([hi, lo]));
        let meta_end = 2 + meta_len;
        let Some(meta) = input.get(2..meta_end) else {
            return Ok(Decoded::NeedMore);
        };
        let (status, option) = match meta {
            [_, _, status, option, ..] => (*status, *option),
            _ => return Err(invalid_data("short xudp frame")),
        };
        if option & 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "remote closed",
            ));
        }
        let addr = match status {
            STATUS_NEW => return Err(invalid_data("unexpected frame new")),
            STATUS_END => return Err(io::ErrorKind::UnexpectedEof.into()),
            STATUS_KEEP if meta_len > 4 => {
                let body = meta.get(5..).unwrap_or_default();
                Some(
                    VMESS
                        .parse(body)?
                        .ok_or_else(|| invalid_data("short xudp address"))?
                        .0,
                )
            }
            STATUS_KEEP | STATUS_KEEP_ALIVE => None,
            _ => return Err(invalid_data("unexpected xudp frame")),
        };
        if option & 1 == 0 {
            return Ok(Decoded::Skip(meta_end));
        }
        let Some(&[dhi, dlo]) = input.get(meta_end..meta_end + 2) else {
            return Ok(Decoded::NeedMore);
        };
        let data_len = usize::from(u16::from_be_bytes([dhi, dlo]));
        let start = meta_end + 2;
        if input.len() < start + data_len {
            return Ok(Decoded::NeedMore);
        }
        if status == STATUS_KEEP_ALIVE {
            return Ok(Decoded::Skip(start + data_len));
        }
        Ok(Decoded::Packet {
            addr,
            payload: start..start + data_len,
            consumed: start + data_len,
        })
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &VmessOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let security = Security::parse(&opts.cipher.to_lowercase()).ok_or_else(|| {
        BuildError::invalid(format!("vmess: unsupported security type {}", opts.cipher))
    })?;
    let link = build_link(
        LinkSpec {
            def,
            server: &opts.server,
            port: opts.port,
            tls: &opts.tls,
            transport: &opts.transport,
            flavor: Flavor::Vmess,
        },
        ctx,
    )?;
    let cfg = VmessCfg::new(
        &opts.uuid,
        opts.alter_id,
        security,
        opts.global_padding,
        opts.authenticated_length,
        ctx.clock.clone(),
    );
    Ok(Arc::new(Vmess {
        info: info_for(
            def,
            OutboundKind::Vmess,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link,
        cfg: Arc::new(cfg),
        mode: udp_mode(opts.packet_addr, opts.xudp, &opts.packet_encoding),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xudp_wins_over_packet_addr() {
        assert!(udp_mode(true, true, "") == UdpMode::Xudp);
        assert!(udp_mode(true, false, "") == UdpMode::PacketAddr);
        assert!(udp_mode(false, false, "packetaddr") == UdpMode::PacketAddr);
        assert!(udp_mode(true, false, "xudp") == UdpMode::Xudp);
        assert!(udp_mode(false, false, "") == UdpMode::Plain);
    }

    #[test]
    fn xudp_frames_round_trip() {
        let dst = Address::new("1.2.3.4", 53);
        let mut enc = XudpFrames::new(Some("10.0.0.2:5353".parse().unwrap()));
        let mut dec = XudpFrames::new(None);
        let mut pkt = PacketBuf::with_headroom(enc.headroom());
        pkt.extend_from_slice(b"hi");
        enc.encode(&mut pkt, &dst).unwrap();
        let mut wire = pkt.as_slice().to_vec();
        wire[4] = STATUS_KEEP;
        let Decoded::Packet { addr, payload, .. } = dec.decode(&mut wire).unwrap() else {
            panic!("expected a packet");
        };
        assert_eq!(addr, Some(dst));
        assert_eq!(&wire[payload], b"hi");
    }
}
