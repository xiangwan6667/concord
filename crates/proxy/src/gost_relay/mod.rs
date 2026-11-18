#[cfg(test)]
mod tests;
mod wire;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{GostRelayOpts, ProxyDef};
use concord_transport::{Layer, TransportStack};
use tokio::io::AsyncWriteExt;

use crate::ctx::{BuildCtx, BuildError};
use crate::dgram::StreamSession;
use crate::link::simple_link;
use crate::node::{Link, info_for};

struct GostRelay {
    info: OutboundInfo,
    link: Link,
    opts: GostRelayOpts,
}

impl GostRelay {
    async fn open(&self, cx: &DialCx<'_>, target: &Address, udp: bool) -> io::Result<BoxStream> {
        let mut stream = self.link.open(cx).await?;
        let target = (!self.opts.forward).then_some(target);
        let request = wire::request(target, udp, &self.opts.username, &self.opts.password)?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        wire::response(&mut stream).await?;
        Ok(stream)
    }
}

#[async_trait]
impl Outbound for GostRelay {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        self.open(cx, dst, false).await
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let remote = match hint {
            Address::Socket(_) => hint.clone(),
            Address::Domain(host, port) => {
                let version = self.link.egress.version();
                let ips = cx.env.resolver.lookup(host, version, cx.initiator).await?;
                let ip = ips
                    .first(version)
                    .ok_or_else(|| concord_common::CoreError::IpNotFound(host.to_string()))?;
                Address::Socket(SocketAddr::new(ip, *port))
            }
        };
        let stream = self.open(cx, &remote, true).await?;
        Ok(Arc::new(StreamSession::new(
            stream,
            wire::Frames(remote.clone()),
            wire::Frames(remote.clone()),
            remote,
            self.link.tasks(),
        )))
    }

    fn multi_destination_udp(&self) -> bool {
        false
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &GostRelayOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    if opts.username.len() > 255 || opts.password.len() > 255 {
        return Err(BuildError::invalid(
            "gost relay username or password too long",
        ));
    }
    let mut link = simple_link(def, &opts.server, opts.port, &opts.tls, ctx)?;
    if opts.mux {
        link.stack = TransportStack::new(vec![Layer::Smux], ctx.tasks.clone());
    }
    Ok(Arc::new(GostRelay {
        info: info_for(
            def,
            OutboundKind::GostRelay,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link,
        opts: opts.clone(),
    }))
}
