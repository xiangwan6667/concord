mod padding;
mod pool;
#[cfg(test)]
mod raw_tests;
#[cfg(test)]
mod recovery_tests;
mod scan;
mod stream;
#[cfg(test)]
mod tests;
mod transport;

use std::io;
use std::sync::Arc;

use crate::anytls::padding::{Padding, Size};
use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{MiuOpts, ProxyDef};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use self::pool::{IdleLane, Pool};
use self::stream::{MiuStream, frame};
use crate::addr_codec::SOCKS;
use crate::ctx::{BuildCtx, BuildError};
use crate::link::simple_link;
use crate::node::{Link, info_for};
use crate::uot;

struct Miu {
    info: OutboundInfo,
    link: Arc<Link>,
    token: [u8; 32],
    pool: Arc<Pool>,
    min_idle: usize,
}

async fn dial_lane(
    link: &Link,
    token: &[u8; 32],
    padding: &Padding,
    cx: &DialCx<'_>,
) -> io::Result<IdleLane> {
    let tls = link.open_tls(cx).await?;
    if !tls.is_tls13() {
        return Err(io::Error::other("miu requires TLS 1.3"));
    }
    let mut lane = IdleLane::tls(tls);
    let mut hello = token.to_vec();
    let pad = match padding.sizes(0).first() {
        Some(Size::Bytes(size)) => *size,
        _ => 30,
    };
    let pad = u16::try_from(pad).unwrap_or(30);
    hello.extend_from_slice(&pad.to_be_bytes());
    hello.resize(34 + usize::from(pad), 0);
    frame(
        &mut hello,
        1,
        format!("v=2\nraw=1\npadding-md5={}", padding.md5).as_bytes(),
    )?;
    lane.io.write_all(&hello).await?;
    Ok(lane)
}

impl Miu {
    async fn open(&self, cx: &DialCx<'_>, dst: &Address, udp: bool) -> io::Result<BoxStream> {
        let (generation, pooled) = self.pool.take();
        self.pool
            .prewarm(&self.link, self.token, cx.env, self.min_idle);
        let mut address = Vec::new();
        SOCKS.write(dst, &mut address)?;
        let mut open = Vec::new();
        frame(&mut open, 4, &address)?;
        if let Some(lane) = pooled {
            return Ok(Box::new(
                MiuStream::new(lane, self.pool.clone(), generation)
                    .with_open(open.clone(), udp)
                    .replay_pooled(self.link.clone(), self.token, cx.env.clone(), open),
            ));
        }
        let padding = self.pool.padding.load_full();
        let lane = dial_lane(&self.link, &self.token, &padding, cx).await?;
        Ok(Box::new(
            MiuStream::new(lane, self.pool.clone(), generation).with_open(open, udp),
        ))
    }
}

#[async_trait]
impl Outbound for Miu {
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
        let stream = self.open(cx, &uot::destination(2), true).await?;
        uot::session(stream, 2, hint, self.link.tasks())
    }

    fn reset_sessions(&self) {
        self.pool.clear();
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &MiuOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let link = simple_link(def, &opts.server, opts.port, &opts.tls, ctx)?;
    let token = Sha256::digest(opts.psk.as_bytes()).into();
    let padding = padding::derive(&token).map_err(|err| BuildError::invalid(err.to_string()))?;
    Ok(Arc::new(Miu {
        info: info_for(
            def,
            OutboundKind::Miu,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link: Arc::new(link),
        token,
        pool: Pool::new(opts.idle_session_timeout, padding, ctx.tasks.clone()),
        min_idle: if opts.min_idle_session == 0 {
            2
        } else {
            opts.min_idle_session as usize
        },
    }))
}
