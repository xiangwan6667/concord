use super::*;
use crate::addr_codec::SOCKS;
use crate::lazy::HeadFirst;
use crate::ssr::{SsrCipher, stream_cipher, stream_udp};

struct StreamShadowsocks {
    info: OutboundInfo,
    link: Link,
    cipher: SsrCipher,
    uot: Option<u8>,
}

impl StreamShadowsocks {
    async fn open(&self, cx: &DialCx<'_>, target: &Address) -> io::Result<HeadFirst<BoxStream>> {
        let stream = stream_cipher(self.link.open(cx).await?, &self.cipher)?;
        let mut head = Vec::new();
        SOCKS.write(target, &mut head)?;
        Ok(HeadFirst::new(stream, head))
    }
}

#[async_trait]
impl Outbound for StreamShadowsocks {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        Ok(Box::new(Kick::new(self.open(cx, dst).await?)))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if let Some(version) = self.uot {
            let stream = self.open(cx, &uot::destination(version)).await?;
            return uot::session(Box::new(stream), version, hint, self.link.tasks());
        }
        let server = self.link.server_socket(cx).await?;
        let codec = stream_udp(self.cipher.clone());
        Ok(Arc::new(
            UdpRelay::open(&self.link.egress, cx, server, codec, None).await?,
        ))
    }
}

pub(super) fn build(
    def: &ProxyDef,
    opts: &SsOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    if opts.password.is_empty() {
        return Err(BuildError::invalid("missing password"));
    }
    let cipher = SsrCipher::chacha(&opts.cipher, &opts.password)
        .ok_or_else(|| BuildError::invalid("unknown stream cipher"))?;
    let version = uot_version(opts)?;
    Ok(Arc::new(StreamShadowsocks {
        info: info_for(
            def,
            OutboundKind::Shadowsocks,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link: plugin_link(def, opts, ctx)?,
        cipher,
        uot: opts.udp_over_tcp.then_some(version),
    }))
}
