use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketBuf, PacketSession,
};
use concord_config::proxy::{ProxyDef, TrojanOpts};
use sha2::{Digest, Sha224};
use shadowsocks::context::SharedContext;
use shadowsocks::crypto::CipherKind;

use crate::addr_codec::{MAX_ADDR_LEN, SOCKS};
use crate::ctx::{BuildCtx, BuildError};
use crate::dgram::{Decoded, Decoder, Encoder, StreamSession};
use crate::lazy::{HeadFirst, Kick};
use crate::link::{Flavor, LinkSpec, build_link};
use crate::node::{Link, info_for};
use crate::ss::crypto::{CryptoIo, SsKey, new_context};
use crate::ssr::{SsrCipher, stream_cipher};

const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 3;
const MAX_PACKET: usize = 8192;
const CRLF: &[u8; 2] = b"\r\n";

#[allow(
    clippy::large_enum_variant,
    reason = "one per connection; boxing the existing cipher would add an allocation to existing protocols"
)]
enum SsLayer {
    Crate {
        key: SsKey,
        context: SharedContext,
    },
    /// djb ChaCha20 and XChaCha20, which the `shadowsocks` crate lacks.
    Stream(SsrCipher),
}

struct Trojan {
    info: OutboundInfo,
    link: Link,
    key: [u8; 56],
    ss: Option<SsLayer>,
}

fn password_key(password: &str) -> [u8; 56] {
    let digest = Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    let _ = hex::encode_to_slice(digest, &mut out);
    out
}

impl Trojan {
    fn header(&self, command: u8, dst: &Address) -> io::Result<Vec<u8>> {
        let mut head = Vec::with_capacity(56 + 2 + 1 + MAX_ADDR_LEN + 2);
        head.extend_from_slice(&self.key);
        head.extend_from_slice(CRLF);
        head.push(command);
        SOCKS.write(dst, &mut head)?;
        head.extend_from_slice(CRLF);
        Ok(head)
    }

    async fn open(&self, cx: &DialCx<'_>) -> io::Result<BoxStream> {
        let stream = self.link.open(cx).await?;
        Ok(match &self.ss {
            Some(SsLayer::Crate { key, context }) => {
                Box::new(CryptoIo::new(stream, key, context.clone()))
            }
            Some(SsLayer::Stream(cipher)) => stream_cipher(stream, cipher)?,
            None => stream,
        })
    }
}

#[async_trait]
impl Outbound for Trojan {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let stream = self.open(cx).await?;
        let head = self.header(CMD_TCP, dst)?;
        Ok(Box::new(Kick::new(HeadFirst::new(stream, head))))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let stream = self.open(cx).await?;
        let head = self.header(CMD_UDP, hint)?;
        Ok(Arc::new(StreamSession::new(
            Box::new(HeadFirst::new(stream, head)),
            TrojanFrames,
            TrojanFrames,
            hint.clone(),
            self.link.tasks(),
        )))
    }
}

struct TrojanFrames;

impl Encoder for TrojanFrames {
    fn headroom(&self) -> usize {
        MAX_ADDR_LEN + 4
    }

    fn encode(&mut self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        if pkt.len() > MAX_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram larger than a trojan packet",
            ));
        }
        let len = u16::try_from(pkt.len()).map_err(|_| io::Error::other("datagram too long"))?;
        let addr_len = SOCKS.len(dst);
        let head = pkt.prepend(addr_len + 4);
        let (addr, tail) = head.split_at_mut(addr_len);
        SOCKS.write_into(dst, addr)?;
        let (size, crlf) = tail.split_at_mut(2);
        size.copy_from_slice(&len.to_be_bytes());
        crlf.copy_from_slice(CRLF);
        Ok(())
    }

    /// mihomo sends a longer datagram as packets of up to 8192 bytes to the same address
    /// (`transport/trojan/trojan.go:69-94`).
    fn encode_into(
        &mut self,
        pkt: &mut PacketBuf,
        dst: &Address,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        if pkt.len() <= MAX_PACKET {
            self.encode(pkt, dst)?;
            out.extend_from_slice(pkt.as_slice());
            return Ok(());
        }
        let mark = out.len();
        let framed = pkt
            .as_slice()
            .chunks(MAX_PACKET)
            .try_for_each(|chunk| -> io::Result<()> {
                let len =
                    u16::try_from(chunk.len()).map_err(|_| io::Error::other("chunk too long"))?;
                SOCKS.write(dst, out)?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(CRLF);
                out.extend_from_slice(chunk);
                Ok(())
            });
        if framed.is_err() {
            out.truncate(mark);
        }
        framed
    }
}

impl Decoder for TrojanFrames {
    fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded> {
        let Some((addr, used)) = SOCKS.parse(input)? else {
            return Ok(Decoded::NeedMore);
        };
        let Some(&[hi, lo, cr, lf]) = input.get(used..used + 4) else {
            return Ok(Decoded::NeedMore);
        };
        if [cr, lf] != *CRLF {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad trojan packet",
            ));
        }
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        if len > MAX_PACKET {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet invalid"));
        }
        let start = used + 4;
        if input.len() < start + len {
            return Ok(Decoded::NeedMore);
        }
        Ok(Decoded::Packet {
            addr: Some(addr),
            payload: start..start + len,
            consumed: start + len,
        })
    }
}

fn ss_layer(opts: &TrojanOpts) -> Result<Option<SsLayer>, BuildError> {
    let Some(ss) = opts.ss.as_ref().filter(|ss| ss.enabled) else {
        return Ok(None);
    };
    if ss.password.is_empty() {
        return Err(BuildError::invalid("empty password"));
    }
    let method = if ss.method.is_empty() {
        "AES-128-GCM"
    } else {
        ss.method.as_str()
    };
    // go-shadowsocks2's PickCipher table, which mihomo's trojan uses, less the
    // 192-bit AES AEADs and the chacha8 AEADs the crypto crate lacks.
    if let Some(cipher) = SsrCipher::chacha(method, &ss.password) {
        return Ok(Some(SsLayer::Stream(cipher)));
    }
    let kind = match method.to_ascii_uppercase().as_str() {
        "DUMMY" => CipherKind::NONE,
        "AES-128-GCM" => CipherKind::AES_128_GCM,
        "AES-256-GCM" => CipherKind::AES_256_GCM,
        "AES-128-CCM" => CipherKind::AES_128_CCM,
        "AES-256-CCM" => CipherKind::AES_256_CCM,
        "CHACHA20-IETF-POLY1305" => CipherKind::CHACHA20_POLY1305,
        "XCHACHA20-IETF-POLY1305" => CipherKind::XCHACHA20_POLY1305,
        "RC4-MD5" => CipherKind::SS_RC4_MD5,
        "AES-128-CTR" => CipherKind::AES_128_CTR,
        "AES-192-CTR" => CipherKind::AES_192_CTR,
        "AES-256-CTR" => CipherKind::AES_256_CTR,
        "AES-128-CFB" => CipherKind::AES_128_CFB128,
        "AES-192-CFB" => CipherKind::AES_192_CFB128,
        "AES-256-CFB" => CipherKind::AES_256_CFB128,
        "CHACHA20-IETF" => CipherKind::CHACHA20,
        _ => {
            return Err(BuildError::unsupported(format!(
                "trojan ss-opts method {method} is not supported"
            )));
        }
    };
    Ok(Some(SsLayer::Crate {
        key: SsKey::new(kind, &ss.password)?,
        context: new_context(),
    }))
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &TrojanOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let link = build_link(
        LinkSpec {
            def,
            server: &opts.server,
            port: opts.port,
            tls: &opts.tls,
            transport: &opts.transport,
            flavor: Flavor::Trojan,
        },
        ctx,
    )?;
    Ok(Arc::new(Trojan {
        info: info_for(
            def,
            OutboundKind::Trojan,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link,
        key: password_key(&opts.password),
        ss: ss_layer(opts)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_the_hex_sha224_of_the_password() {
        assert_eq!(
            &password_key("password"),
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn frames_round_trip() {
        let dst = Address::new("example.com", 53);
        let mut pkt = PacketBuf::with_headroom(TrojanFrames.headroom());
        pkt.extend_from_slice(b"hello");
        TrojanFrames.encode(&mut pkt, &dst).unwrap();
        let mut wire = pkt.as_slice().to_vec();
        assert_eq!(&wire[wire.len() - 9..], b"\0\x05\r\nhello");
        let Decoded::Packet {
            addr,
            payload,
            consumed,
        } = TrojanFrames.decode(&mut wire).unwrap()
        else {
            panic!("expected a packet");
        };
        assert_eq!(addr, Some(dst));
        assert_eq!(&wire[payload], b"hello");
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn a_short_frame_waits_for_more() {
        let mut wire = vec![1, 1, 2, 3, 4, 0, 53, 0];
        assert!(matches!(
            TrojanFrames.decode(&mut wire).unwrap(),
            Decoded::NeedMore
        ));
    }

    #[tokio::test]
    async fn a_datagram_over_the_packet_limit_goes_out_as_several_packets() {
        use concord_common::send_packet;
        use tokio::io::AsyncReadExt;

        let (near, mut far) = tokio::io::duplex(1 << 16);
        let dst = Address::new("1.2.3.4", 53);
        let session = StreamSession::new(
            Box::new(near),
            TrojanFrames,
            TrojanFrames,
            dst.clone(),
            &Default::default(),
        );
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut pkt = PacketBuf::with_headroom(session.headroom());
        pkt.extend_from_slice(&data);
        send_packet(&session, &mut pkt, &dst).await.unwrap();
        let header = SOCKS.len(&dst) + 4;
        let mut wire = vec![0u8; 2 * header + data.len()];
        far.read_exact(&mut wire).await.unwrap();
        let (mut sent, mut at) = (Vec::new(), 0);
        while at < wire.len() {
            let Decoded::Packet {
                addr,
                payload,
                consumed,
            } = TrojanFrames.decode(&mut wire[at..]).unwrap()
            else {
                panic!("expected a packet");
            };
            assert_eq!(addr.as_ref(), Some(&dst));
            sent.push(wire[at..][payload].to_vec());
            at += consumed;
        }
        assert_eq!(sent.iter().map(Vec::len).collect::<Vec<_>>(), [8192, 1808]);
        assert_eq!(sent.concat(), data);
    }
}
