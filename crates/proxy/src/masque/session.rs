use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use concord_common::{HostResolver, Initiator};

use super::Shared;
use super::tunnel::Tunnel;
use crate::stack::{SessionTunnel, StackSession};

pub(super) struct MasqueUdp {
    tunnel: Arc<Tunnel>,
    shared: Arc<Shared>,
    resolver: Arc<dyn HostResolver>,
    initiator: Initiator,
}

impl SessionTunnel for MasqueUdp {
    fn resolve(&self, host: String) -> impl Future<Output = io::Result<IpAddr>> + Send + 'static {
        let tunnel = self.tunnel.clone();
        let shared = self.shared.clone();
        let resolver = self.resolver.clone();
        let initiator = self.initiator;
        async move { tunnel.resolve(&shared, &*resolver, &host, initiator).await }
    }

    fn usable(&self) -> bool {
        self.tunnel.usable()
    }
}

pub(super) fn open(
    tunnel: Arc<Tunnel>,
    shared: Arc<Shared>,
    resolver: Arc<dyn HostResolver>,
    initiator: Initiator,
) -> io::Result<StackSession<MasqueUdp>> {
    Ok(StackSession::new(
        tunnel.stack.bind_udp()?,
        MasqueUdp {
            tunnel,
            shared,
            resolver,
            initiator,
        },
    ))
}
