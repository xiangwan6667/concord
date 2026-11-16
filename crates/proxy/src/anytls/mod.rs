mod frame;
pub(crate) mod padding;
mod pool;
mod session;
mod stream;
#[cfg(test)]
mod tests;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{AnyTlsOpts, ProxyDef};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use self::padding::{Padding, Size};
use self::pool::Pool;
use self::session::Session;
use crate::addr_codec::SOCKS;
use crate::ctx::{BuildCtx, BuildError};
use crate::link::simple_link;
use crate::node::{Link, info_for};
use crate::session_slot::overtaken;
use crate::uot;

const MIN_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
const UOT_VERSION: u8 = 2;

struct AnyTls {
    info: OutboundInfo,
    link: Link,
    password: [u8; 32],
    padding: Arc<ArcSwap<Padding>>,
    metadata: String,
    pool: Arc<Pool>,
    sessions: AtomicU64,
    check_interval: Duration,
    idle_timeout: Duration,
}

impl AnyTls {
    async fn connect_session(&self, cx: &DialCx<'_>) -> io::Result<Arc<Session>> {
        let ticket = self.pool.ticket();
        let mut conn = self.link.open(cx).await?;
        let planned = match self.padding.load().sizes(0).first() {
            Some(Size::Bytes(len)) => (*len).min(usize::from(u16::MAX)),
            _ => 0,
        };
        let mut auth = Vec::with_capacity(34 + planned);
        auth.extend_from_slice(&self.password);
        auth.extend_from_slice(&(planned as u16).to_be_bytes());
        auth.resize(34 + planned, 0);
        conn.write_all(&auth).await?;
        conn.flush().await?;
        let seq = self.sessions.fetch_add(1, Ordering::AcqRel) + 1;
        let session = Session::start(conn, seq, &self.pool, self.padding.clone(), &self.metadata);
        if !self.pool.register(session.clone(), ticket) {
            session.close();
            return Err(overtaken());
        }
        self.pool
            .start_cleaner(self.check_interval, self.idle_timeout);
        Ok(session)
    }

    async fn open_stream(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let idle = if self.pool.disable_reuse() {
            None
        } else {
            self.pool.take_idle()
        };
        let session = match idle {
            Some(session) => session,
            None => self.connect_session(cx).await?,
        };
        let mut stream = match session.open_stream().await {
            Ok(stream) => stream,
            Err(err) => {
                session.close();
                return Err(err);
            }
        };
        let mut head = Vec::new();
        SOCKS.write(dst, &mut head)?;
        stream.write_all(&head).await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Outbound for AnyTls {
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
        let stream = self.open_stream(cx, &uot::destination(UOT_VERSION)).await?;
        uot::session(stream, UOT_VERSION, hint)
    }

    fn reset_sessions(&self) {
        self.pool.close_all();
    }
}

fn interval(seconds: u32) -> Duration {
    let value = Duration::from_secs(u64::from(seconds));
    if value <= MIN_INTERVAL {
        DEFAULT_INTERVAL
    } else {
        value
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &AnyTlsOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let mut tls = opts.tls.clone();
    tls.enabled = true;
    let link = simple_link(def, &opts.server, opts.port, &tls, ctx)?;
    let mut password = [0u8; 32];
    password.copy_from_slice(&Sha256::digest(opts.password.as_bytes()));
    Ok(Arc::new(AnyTls {
        info: info_for(
            def,
            OutboundKind::AnyTls,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link,
        password,
        padding: Arc::new(ArcSwap::from_pointee(Padding::default_scheme())),
        metadata: opts.client_metadata.clone(),
        pool: Pool::new(opts.disable_reuse, opts.min_idle_session as usize),
        sessions: AtomicU64::new(0),
        check_interval: interval(opts.idle_session_check_interval),
        idle_timeout: interval(opts.idle_session_timeout),
    }))
}
