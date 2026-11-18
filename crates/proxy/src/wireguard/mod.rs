mod amnezia;
pub(crate) mod config;
pub(crate) mod dns;
mod session;
mod transport;
mod tunnel;

#[cfg(test)]
mod tests;

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession, Tasks,
};
use concord_config::proxy::{ProxyDef, WireGuardOpts};
use concord_net::dial_found;
use tokio::time::timeout;

use self::config::WgConfig;
use self::tunnel::{Tunnel, watch_idle};
use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Egress, info};
use crate::session_slot::SessionSlot;
use crate::stack::IpStream;

pub(crate) struct Shared {
    info: OutboundInfo,
    egress: Egress,
    config: WgConfig,
    slot: SessionSlot<Tunnel>,
    init: tokio::sync::Mutex<()>,
    tasks: Tasks,
}

struct WireGuard {
    shared: Arc<Shared>,
}

impl Shared {
    fn current(&self) -> Option<Arc<Tunnel>> {
        self.slot.get(Tunnel::usable).0
    }

    fn retire(&self, tunnel: &Arc<Tunnel>) {
        self.slot.forget(tunnel);
    }

    async fn tunnel(self: &Arc<Self>, cx: &DialCx<'_>) -> io::Result<Arc<Tunnel>> {
        if let Some(tunnel) = self.current() {
            tunnel.touch();
            tunnel
                .refresh_endpoints(cx, &self.egress, &self.config)
                .await;
            return Ok(tunnel);
        }
        let mut built = false;
        let build = || {
            built = true;
            Tunnel::build(cx, &self.egress, &self.config, &self.tasks)
        };
        let tunnel = self
            .slot
            .offer(&self.init, Tunnel::usable, build, |_| {})
            .await?;
        if !built {
            tunnel.touch();
            return Ok(tunnel);
        }
        let owner = Arc::downgrade(self);
        watch_idle(&tunnel, move |tunnel| {
            if let Some(owner) = owner.upgrade() {
                owner.retire(tunnel);
            }
        });
        Ok(tunnel)
    }
}

#[async_trait]
impl Outbound for WireGuard {
    fn info(&self) -> &OutboundInfo {
        &self.shared.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let shared = &self.shared;
        let tunnel = shared.tunnel(cx).await?;
        let wait = cx.remaining();
        let open = |target: SocketAddr| {
            let tunnel = &tunnel;
            async move {
                let mut conn = tunnel.tcp(target, &shared.config)?;
                let established = poll_fn(|cx| conn.poll_established(cx));
                match wait {
                    Some(wait) => timeout(wait, established).await.map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "wireguard connect timed out")
                    })??,
                    None => established.await?,
                }
                Ok(conn)
            }
        };
        let conn = match dst {
            Address::Socket(addr) => open(*addr).await?,
            Address::Domain(host, _) => {
                let version = shared.egress.version();
                let found = tunnel
                    .lookup(
                        &shared.config,
                        &*cx.env.resolver,
                        host,
                        version,
                        cx.initiator,
                    )
                    .await?;
                dial_found(cx, found, dst, version, open).await?
            }
        };
        Ok(Box::new(IpStream::new(conn, tunnel)))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let shared = &self.shared;
        let tunnel = shared.tunnel(cx).await?;
        let session = session::open(
            tunnel.clone(),
            shared.clone(),
            cx.env.resolver.clone(),
            cx.initiator,
        )?;
        if let Address::Domain(host, _) = hint {
            session
                .seed(host)
                .await
                .map_err(|err| io::Error::other(format!("can't resolve ip: {err}")))?;
        }
        Ok(Arc::new(session))
    }

    async fn resolve_udp(&self, cx: &DialCx<'_>, host: &str) -> Option<io::Result<IpAddr>> {
        let shared = &self.shared;
        if shared.config.remote_dns.is_empty() {
            return None;
        }
        let resolved = async {
            let tunnel = shared.tunnel(cx).await?;
            tunnel
                .resolve(
                    &shared.config,
                    &*cx.env.resolver,
                    host,
                    shared.egress.version(),
                    cx.initiator,
                )
                .await
        };
        Some(
            resolved
                .await
                .map_err(|err| io::Error::other(format!("can't resolve ip: {err}"))),
        )
    }

    fn reset_sessions(&self) {
        self.shared.slot.reset();
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &WireGuardOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    Ok(Arc::new(construct(def, opts, ctx.tasks.clone())?))
}

fn construct(def: &ProxyDef, opts: &WireGuardOpts, tasks: Tasks) -> Result<WireGuard, BuildError> {
    let config = config::parse(opts)?;
    let first = config
        .peers
        .first()
        .ok_or_else(|| BuildError::invalid("wireguard: server or peers must be set"))?;
    let info = info(
        &def.name,
        OutboundKind::WireGuard,
        &first.server,
        first.port,
        def.common.udp,
    );
    Ok(WireGuard {
        shared: Arc::new(Shared {
            info,
            egress: Egress::new(&def.name, &def.common),
            config,
            slot: SessionSlot::default(),
            init: tokio::sync::Mutex::new(()),
            tasks,
        }),
    })
}
