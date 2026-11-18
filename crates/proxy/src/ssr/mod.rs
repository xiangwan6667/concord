mod chacha;
mod chain;
mod cipher;
mod obfs;
mod protocol;
mod stream;

#[cfg(test)]
mod tests;

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketBuf, PacketSession,
};
use concord_config::proxy::{ProxyDef, SsrOpts};
use tokio::io::AsyncWriteExt;

pub(crate) use self::cipher::SsrCipher;
use self::obfs::ObfsFactory;
use self::protocol::{PacketProtocol, ProtocolFactory};
use self::stream::CodecStream;
use crate::addr_codec::{MAX_ADDR_LEN, SOCKS};
use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Link, info_for};
use crate::udprelay::{UdpCodec, UdpRelay};

struct ShadowsocksR {
    info: OutboundInfo,
    link: Link,
    cipher: SsrCipher,
    obfs: ObfsFactory,
    protocol: ProtocolFactory,
}

#[async_trait]
impl Outbound for ShadowsocksR {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let raw = self.link.open(cx).await?;
        let obfs = CodecStream::new(raw, self.obfs.layer());
        let cipher = CodecStream::new(obfs, self.cipher.layer()?);
        let iv = cipher.layer().iv.clone();
        let mut stream = CodecStream::new(cipher, self.protocol.stream(iv));
        let mut head = Vec::new();
        SOCKS.write(dst, &mut head)?;
        stream.write_all(&head).await?;
        stream.flush().await?;
        Ok(Box::new(stream))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let server = self.link.server_socket(cx).await?;
        let codec = SsrUdp {
            cipher: self.cipher.clone(),
            protocol: self.protocol.packet(),
        };
        let session = UdpRelay::open(&self.link.egress, cx, server, codec, None).await?;
        Ok(Arc::new(session))
    }
}

pub(crate) struct SsrUdp {
    cipher: SsrCipher,
    protocol: PacketProtocol,
}

/// A shadowsocks stream cipher is SSR with protocol `origin` and obfs `plain` on the wire: the IV,
/// then everything after it under the cipher. Shadowsocks and trojan's `ss-opts` run djb ChaCha20
/// and XChaCha20, which the `shadowsocks` crate lacks, through this layer.
pub(crate) fn stream_cipher(raw: BoxStream, cipher: &SsrCipher) -> io::Result<BoxStream> {
    Ok(Box::new(CodecStream::new(raw, cipher.layer()?)))
}

pub(crate) fn stream_udp(cipher: SsrCipher) -> SsrUdp {
    SsrUdp {
        cipher,
        protocol: PacketProtocol::Plain,
    }
}

impl UdpCodec for SsrUdp {
    fn headroom(&self) -> usize {
        MAX_ADDR_LEN + self.cipher.headroom()
    }

    fn seal(&self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        let len = SOCKS.len(dst);
        SOCKS.write_into(dst, pkt.prepend(len))?;
        self.protocol.seal(pkt);
        self.cipher.seal_packet(pkt)
    }

    fn open(&self, pkt: &mut PacketBuf) -> io::Result<Address> {
        self.cipher.open_packet(pkt)?;
        self.protocol.open(pkt)?;
        let (addr, used) = SOCKS.parse(pkt.as_slice())?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "short shadowsocksr udp packet")
        })?;
        pkt.consume(used);
        Ok(addr)
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &SsrOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let cipher_name = if opts.cipher == "none" {
        "dummy"
    } else {
        opts.cipher.as_str()
    };
    let cipher = SsrCipher::pick(cipher_name, &opts.password)?;
    let (obfs, obfs_overhead) = ObfsFactory::pick(
        &opts.obfs,
        &opts.server,
        opts.port,
        cipher.key.clone(),
        cipher.iv_len(),
        &opts.obfs_param,
        ctx.clock.clone(),
    )?;
    let protocol = ProtocolFactory::pick(
        &opts.protocol,
        cipher.key.clone(),
        obfs_overhead,
        &opts.protocol_param,
        ctx.clock.clone(),
    )?;
    let link = Link::plain(def, &opts.server, opts.port, &ctx.tasks);
    Ok(Arc::new(ShadowsocksR {
        info: info_for(
            def,
            OutboundKind::ShadowsocksR,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link,
        cipher,
        obfs,
        protocol,
    }))
}
