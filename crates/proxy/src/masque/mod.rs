mod body;
mod capsule;
mod config;
mod connect;
mod datagram;
mod h2;
mod h3;
mod session;
mod tls;
mod tunnel;

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, HostResolver, Initiator, LookupIps, Outbound,
    OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{MasqueOpts, ProxyDef};
use concord_net::dial_found;

use self::config::Config;
use self::connect::Connector;
use self::tunnel::Tunnel;
use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Egress, info};
use crate::session_slot::SessionSlot;

struct Shared {
    info: OutboundInfo,
    egress: Egress,
    config: Config,
    ip: SessionSlot<Tunnel>,
    l4: SessionSlot<h3::Client>,
    dns: crate::wireguard::dns::RemoteDns,
    init: tokio::sync::Mutex<()>,
}

struct Masque {
    shared: Arc<Shared>,
}

async fn bounded<T>(
    wait: Option<Duration>,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match wait {
        Some(wait) => tokio::time::timeout(wait, future)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
        None => future.await,
    }
}

impl Shared {
    fn timeout(&self, cx: &DialCx<'_>) -> Option<Duration> {
        match (cx.remaining(), self.config.timeout) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    async fn tunnel(&self, cx: &DialCx<'_>) -> io::Result<Arc<Tunnel>> {
        let connect = || bounded(self.timeout(cx), Tunnel::connect(&self.config, cx));
        self.ip
            .offer(&self.init, Tunnel::usable, connect, |tunnel| tunnel.close())
            .await
    }

    async fn l4(&self, cx: &DialCx<'_>) -> io::Result<Arc<h3::Client>> {
        let connect = || bounded(self.timeout(cx), h3::Client::connect(&self.config, cx));
        self.l4
            .offer(&self.init, h3::Client::usable, connect, |_| {})
            .await
    }
}

impl Tunnel {
    async fn lookup(
        &self,
        shared: &Shared,
        resolver: &dyn HostResolver,
        host: &str,
        initiator: Initiator,
    ) -> io::Result<LookupIps> {
        if shared.config.dns.is_empty() {
            resolver
                .lookup(host, shared.egress.version(), initiator)
                .await
        } else {
            self.dns
                .lookup(&self.stack, host, shared.config.congestion)
                .await
        }
    }

    async fn resolve(
        &self,
        shared: &Shared,
        resolver: &dyn HostResolver,
        host: &str,
        initiator: Initiator,
    ) -> io::Result<std::net::IpAddr> {
        self.lookup(shared, resolver, host, initiator)
            .await?
            .first(shared.egress.version())
            .ok_or_else(|| CoreError::IpNotFound(host.to_string()).into())
    }
}

#[async_trait]
impl Outbound for Masque {
    fn info(&self) -> &OutboundInfo {
        &self.shared.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let shared = &self.shared;
        let connector = Connector::new(shared, cx).await?;
        let open = |target| connector.open(shared, cx, target);
        match dst {
            Address::Socket(addr) if matches!(&connector, Connector::L4(_)) => {
                bounded(cx.remaining(), open(*addr)).await
            }
            Address::Socket(addr) => open(*addr).await,
            Address::Domain(host, _) => {
                let found = connector.lookup(shared, cx, host).await?;
                dial_found(cx, found, dst, shared.egress.version(), open).await
            }
        }
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if !self.shared.info.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "MASQUE UDP is disabled",
            ));
        }
        let tunnel = self.shared.tunnel(cx).await?;
        let session = session::open(
            tunnel,
            self.shared.clone(),
            cx.env.resolver.clone(),
            cx.initiator,
        )?;
        if let Address::Domain(host, _) = hint {
            session.seed(host).await?;
        }
        Ok(Arc::new(session))
    }

    fn reset_sessions(&self) {
        if let Some(tunnel) = self.shared.ip.reset() {
            tunnel.close();
        }
        if let Some(client) = self.shared.l4.reset() {
            client
                .quic
                .conn
                .close(quinn::VarInt::from_u32(0), b"network changed");
        }
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &MasqueOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let egress = Egress::new(&def.name, &def.common);
    let config = Config::new(opts, egress.clone(), ctx)?;
    let udp = def.common.udp && opts.network != "h3-l4proxy";
    if def.common.udp && !udp {
        tracing::warn!("MASQUE L4 proxy does not support UDP; disabling it");
    }
    Ok(Arc::new(Masque {
        shared: Arc::new(Shared {
            info: info(
                &def.name,
                OutboundKind::Masque,
                &opts.server,
                opts.port,
                udp,
            ),
            dns: crate::wireguard::dns::RemoteDns::new(config.dns.clone(), true),
            egress,
            config,
            ip: SessionSlot::default(),
            l4: SessionSlot::default(),
            init: tokio::sync::Mutex::new(()),
        }),
    }))
}

#[cfg(test)]
mod tests;
