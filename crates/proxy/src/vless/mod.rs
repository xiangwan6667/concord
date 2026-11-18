mod encryption;
mod stream;
mod vision_io;
#[cfg(test)]
mod xray_tests;

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketBuf, PacketSession,
};
use concord_config::proxy::{ProxyDef, VlessOpts};

use self::stream::{CMD_MUX, CMD_TCP, CMD_UDP, FLOW_VISION, ResponseSkip, Vision, request_header};
use crate::addr_codec::{MAX_ADDR_LEN, PACKET_ADDR};
use crate::ctx::{BuildCtx, BuildError};
use crate::dgram::{Decoded, Decoder, Encoder, StreamSession};
use crate::lazy::{HeadFirst, Kick};
use crate::link::{Flavor, LinkSpec, build_link};
use crate::node::{Link, info_for};
use crate::vmess::crypto::user_id;
use crate::vmess::{UdpMode, XudpFrames};

const PACKET_ADDR_MAGIC: &str = "sp.packet-addr.v2fly.arpa";

struct Vless {
    info: OutboundInfo,
    link: Link,
    user: [u8; 16],
    vision: bool,
    mode: UdpMode,
    encryption: Option<Arc<encryption::Client>>,
}

impl Vless {
    async fn stream(&self, cx: &DialCx<'_>, command: u8, dst: &Address) -> io::Result<BoxStream> {
        let flow = self.vision.then_some(FLOW_VISION);
        let header = request_header(&self.user, flow, command, dst)?;
        if let Some(encryption) = &self.encryption {
            let encrypted = encryption.handshake(self.link.open(cx).await?).await?;
            if self.vision {
                let (read, write) = encrypted.into_halves();
                return Ok(Box::new(Vision::from_halves(
                    read, write, header, self.user,
                )));
            }
            return Ok(Box::new(ResponseSkip::new(HeadFirst::new(
                encrypted, header,
            ))));
        }
        if self.vision {
            if self.link.tls.is_none() || !self.link.stack.is_empty() {
                return Err(io::Error::other(
                    "failed to use vision, maybe \"tls\" is not enable and \"encryption\" is empty",
                ));
            }
            let tls = self.link.open_tls(cx).await?;
            return Ok(Box::new(Vision::new(tls, header, self.user)?));
        }
        let io = self.link.open(cx).await?;
        Ok(Box::new(ResponseSkip::new(HeadFirst::new(io, header))))
    }
}

#[async_trait]
impl Outbound for Vless {
    fn reset_sessions(&self) {
        if let Some(encryption) = &self.encryption {
            encryption.reset();
        }
    }
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        Ok(Box::new(Kick::new(self.stream(cx, CMD_TCP, dst).await?)))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if self.mode == UdpMode::Xudp {
            let stream = self.stream(cx, CMD_MUX, hint).await?;
            return Ok(Arc::new(StreamSession::new(
                stream,
                XudpFrames::new(cx.source()),
                XudpFrames::new(None),
                hint.clone(),
                self.link.tasks(),
            )));
        }
        let magic = Address::new(PACKET_ADDR_MAGIC, 443);
        let stream = self.stream(cx, CMD_UDP, &magic).await?;
        Ok(Arc::new(StreamSession::new(
            stream,
            PacketAddrFrames,
            PacketAddrFrames,
            hint.clone(),
            self.link.tasks(),
        )))
    }
}

/// `[length][packet-addr address][payload]`, the length covering the rest.
struct PacketAddrFrames;

impl Encoder for PacketAddrFrames {
    fn headroom(&self) -> usize {
        2 + MAX_ADDR_LEN
    }

    fn encode(&mut self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        let addr_len = PACKET_ADDR.len(dst);
        let total = u16::try_from(addr_len + pkt.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too long"))?;
        PACKET_ADDR.write_into(dst, pkt.prepend(addr_len))?;
        pkt.prepend(2).copy_from_slice(&total.to_be_bytes());
        Ok(())
    }
}

impl Decoder for PacketAddrFrames {
    fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded> {
        let Some(&[hi, lo]) = input.get(..2) else {
            return Ok(Decoded::NeedMore);
        };
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        let Some(body) = input.get(2..2 + len) else {
            return Ok(Decoded::NeedMore);
        };
        let (addr, used) = PACKET_ADDR.parse(body)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "short packet-addr packet")
        })?;
        Ok(Decoded::Packet {
            addr: Some(addr),
            payload: 2 + used..2 + len,
            consumed: 2 + len,
        })
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &VlessOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let vision = if opts.flow.len() >= 16 {
        if opts.flow.get(..16) != Some(FLOW_VISION) {
            return Err(BuildError::invalid(format!(
                "unsupported xtls flow type: {}",
                opts.flow.get(..16).unwrap_or(&opts.flow)
            )));
        }
        true
    } else {
        false
    };
    let encryption = encryption::Client::parse(&opts.encryption)?;
    let link = build_link(
        LinkSpec {
            def,
            server: &opts.server,
            port: opts.port,
            tls: &opts.tls,
            transport: &opts.transport,
            flavor: Flavor::Vless,
        },
        ctx,
    )?;
    let (mut packet_addr, mut xudp) = (opts.packet_addr, opts.xudp);
    if matches!(opts.packet_encoding.as_str(), "packetaddr" | "packet") {
        packet_addr = true;
        xudp = false;
    } else if !packet_addr {
        xudp = true;
    }
    if xudp {
        packet_addr = false;
    }
    let mode = if packet_addr {
        UdpMode::PacketAddr
    } else {
        UdpMode::Xudp
    };
    Ok(Arc::new(Vless {
        info: info_for(
            def,
            OutboundKind::Vless,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link,
        user: user_id(&opts.uuid),
        vision,
        mode,
        encryption,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_addr_frames_round_trip() {
        let dst = Address::new("8.8.8.8", 53);
        let mut pkt = PacketBuf::with_headroom(PacketAddrFrames.headroom());
        pkt.extend_from_slice(b"dns");
        PacketAddrFrames.encode(&mut pkt, &dst).unwrap();
        let mut wire = pkt.as_slice().to_vec();
        let Decoded::Packet {
            addr,
            payload,
            consumed,
        } = PacketAddrFrames.decode(&mut wire).unwrap()
        else {
            panic!("expected a packet");
        };
        assert_eq!(addr, Some(dst));
        assert_eq!(&wire[payload], b"dns");
        assert_eq!(consumed, wire.len());
    }
}
