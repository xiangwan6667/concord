use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use concord_common::{BoxStream, DialCx, LookupIps};

use super::body::Body;
use super::h3::Client;
use super::tunnel::Tunnel;
use super::{Shared, bounded};
use crate::stack::IpStream;

pub(super) enum Connector {
    L4(Arc<Client>),
    Ip(Arc<Tunnel>),
}

impl Connector {
    pub(super) async fn new(shared: &Shared, cx: &DialCx<'_>) -> io::Result<Self> {
        if shared.config.network == "h3-l4proxy" {
            Ok(Self::L4(shared.l4(cx).await?))
        } else {
            Ok(Self::Ip(shared.tunnel(cx).await?))
        }
    }

    pub(super) async fn open(
        &self,
        shared: &Shared,
        cx: &DialCx<'_>,
        target: SocketAddr,
    ) -> io::Result<BoxStream> {
        match self {
            Self::L4(client) => {
                let stream = client
                    .request(&shared.config, Some(&target.to_string()))
                    .await?;
                Ok(Box::new(Body::new(stream, client.clone())))
            }
            Self::Ip(tunnel) => {
                let mut conn = tunnel.stack.connect_tcp(target, shared.config.congestion)?;
                bounded(cx.remaining(), poll_fn(|cx| conn.poll_established(cx))).await?;
                Ok(Box::new(IpStream::new(conn, tunnel.clone())))
            }
        }
    }

    pub(super) async fn lookup(
        &self,
        shared: &Shared,
        cx: &DialCx<'_>,
        host: &str,
    ) -> io::Result<LookupIps> {
        match self {
            Self::Ip(tunnel) => {
                tunnel
                    .lookup(shared, &*cx.env.resolver, host, cx.initiator)
                    .await
            }
            Self::L4(_) if shared.config.dns.is_empty() => {
                cx.env
                    .resolver
                    .lookup(host, shared.egress.version(), cx.initiator)
                    .await
            }
            Self::L4(_) => {
                shared
                    .dns
                    .lookup_tcp(host, |server| self.open(shared, cx, server))
                    .await
            }
        }
    }
}
