use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use concord_common::packet::PacketBuf;
use concord_common::{
    Address, BoxStream, CoreError, Initiator, PacketSession, SockOpts, SocketFactory, recv_packet,
    send_packet,
};
use concord_transport::SessionSocket;
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::resolver::Group;

/// The name `respect-rules` hands to `UpstreamDialer`: the route the rules pick
/// for the upstream's own address.
pub const RESPECT_RULES: &str = "RULES";

/// Reaches an upstream through the tunnel. The engine implements it over its
/// outbound table and rules; the resolver holds it weakly because the tunnel
/// owns the resolver.
#[async_trait]
pub trait UpstreamDialer: Send + Sync {
    /// Whether `via` names an outbound. A name that is not one is taken as an
    /// interface to bind the upstream's socket to, as `#en0` does.
    fn knows(&self, via: &str) -> bool;

    async fn connect(&self, via: &str, target: &Address) -> io::Result<BoxStream>;

    async fn bind_udp(&self, via: &str, target: &Address) -> io::Result<Arc<dyn PacketSession>>;
}

tokio::task_local! {
    /// Outbounds this query is dialled through; a node's own lookup gets a fresh dial context.
    static THROUGH: Arc<[Arc<str>]>;
}

pub(crate) fn through() -> Arc<[Arc<str>]> {
    THROUGH
        .try_with(Arc::clone)
        .unwrap_or_else(|_| Arc::from(Vec::new()))
}

pub(crate) fn spawn<F>(task: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(THROUGH.scope(through(), task))
}

async fn passing<T>(name: &str, dial: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    let mut path = through().to_vec();
    path.push(Arc::from(name));
    THROUGH.scope(Arc::from(path), dial).await
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Via {
    Direct,
    Named(String),
    Rules,
}

impl Via {
    pub(crate) fn from_fragment(proxy: Option<&str>, respect_rules: bool) -> Via {
        match proxy {
            Some(name) if name == RESPECT_RULES => Via::Rules,
            Some(name) if !name.is_empty() => Via::Named(name.to_string()),
            _ if respect_rules => Via::Rules,
            _ => Via::Direct,
        }
    }
}

pub(crate) struct Shared {
    pub sockets: Arc<dyn SocketFactory>,
    pub dialer: Weak<dyn UpstreamDialer>,
    pub sock_opts: SockOpts,
    pub trust: Arc<concord_tls::TrustStore>,
    pub ipv6: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct Cx {
    pub initiator: Initiator,
}

pub(crate) enum UdpLink {
    Socket(UdpSocket),
    Session {
        session: Arc<dyn PacketSession>,
        peer: Address,
    },
}

impl UdpLink {
    pub(crate) async fn send(&self, data: &[u8]) -> io::Result<()> {
        match self {
            UdpLink::Socket(sock) => sock.send(data).await.map(|_| ()),
            UdpLink::Session { session, peer } => {
                let mut packet = PacketBuf::with_headroom(session.headroom());
                packet.extend_from_slice(data);
                send_packet(session.as_ref(), &mut packet, peer).await
            }
        }
    }

    pub(crate) async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            UdpLink::Socket(sock) => sock.recv(buf).await,
            UdpLink::Session { session, .. } => {
                let (packet, _) = recv_packet(session.as_ref()).await?;
                let data = packet.as_slice();
                let n = data.len().min(buf.len());
                if let (Some(out), Some(src)) = (buf.get_mut(..n), data.get(..n)) {
                    out.copy_from_slice(src);
                }
                Ok(n)
            }
        }
    }
}

/// Opens the sockets of one upstream: directly, bound to an interface, or
/// through the tunnel. A name that is not an IP is resolved with the
/// default-nameserver group.
pub(crate) struct Connector {
    shared: Arc<Shared>,
    via: Via,
    bootstrap: Option<Arc<Group>>,
}

impl Connector {
    pub(crate) fn new(shared: Arc<Shared>, via: Via, bootstrap: Option<Arc<Group>>) -> Self {
        Connector {
            shared,
            via,
            bootstrap,
        }
    }

    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    pub(crate) async fn resolve(&self, host: &str, cx: Cx) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            return Ok(vec![concord_common::addr::unmap(ip)]);
        }
        let Some(group) = &self.bootstrap else {
            return Err(CoreError::IpNotFound(host.to_string()).into());
        };
        let ips = group.lookup_ips(host, self.shared.ipv6, cx).await?;
        if ips.is_empty() {
            return Err(CoreError::IpNotFound(host.to_string()).into());
        }
        Ok(ips)
    }

    fn tunnel(&self) -> io::Result<Option<(Arc<dyn UpstreamDialer>, String)>> {
        let name = match &self.via {
            Via::Direct => return Ok(None),
            Via::Rules => RESPECT_RULES.to_string(),
            Via::Named(name) => name.clone(),
        };
        let dialer = self.shared.dialer.upgrade();
        if let (Via::Named(_), Some(dialer)) = (&self.via, &dialer)
            && !dialer.knows(&name)
        {
            return Ok(None);
        }
        if through().iter().any(|via| **via == *name) {
            return Err(CoreError::DialerLoop(name).into());
        }
        let dialer = dialer.ok_or_else(|| io::Error::other("the tunnel is gone"))?;
        Ok(Some((dialer, name)))
    }

    fn opts(&self) -> SockOpts {
        let mut opts = self.shared.sock_opts.clone();
        if let Via::Named(name) = &self.via {
            opts.interface = Some(Arc::from(name.as_str()));
        }
        opts
    }

    pub(crate) async fn tcp(&self, host: &str, port: u16, cx: Cx) -> io::Result<BoxStream> {
        if let Some((dialer, name)) = self.tunnel()? {
            let target = match &self.via {
                Via::Rules => {
                    let ip = self.resolve(host, cx).await?;
                    Address::Socket(SocketAddr::new(first_ip(&ip)?, port))
                }
                _ => Address::new(host, port),
            };
            return passing(&name, dialer.connect(&name, &target)).await;
        }
        let ips = self.resolve(host, cx).await?;
        let opts = self.opts();
        let mut last = io::Error::from(io::ErrorKind::NotFound);
        for ip in ips {
            match self
                .shared
                .sockets
                .connect_tcp(SocketAddr::new(ip, port), &opts)
                .await
            {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(err) => last = err,
            }
        }
        Err(last)
    }

    /// The socket of a QUIC endpoint, which names the peer on every send: a local
    /// socket, or a UDP session through the outbound, as mihomo's `ListenPacket` gives.
    pub(crate) async fn quic_socket(
        &self,
        host: &str,
        port: u16,
        cx: Cx,
    ) -> io::Result<(Arc<dyn AsyncUdpSocket>, SocketAddr)> {
        let ips = self.resolve(host, cx).await?;
        let peer = SocketAddr::new(first_ip(&ips)?, port);
        if let Some((dialer, name)) = self.tunnel()? {
            let session = passing(&name, dialer.bind_udp(&name, &Address::Socket(peer))).await?;
            let socket: Arc<dyn AsyncUdpSocket> =
                SessionSocket::new(session, peer, &Default::default());
            return Ok((socket, peer));
        }
        let sock = self.shared.sockets.bind_udp(peer.ip(), &self.opts())?;
        Ok((TokioRuntime.wrap_udp_socket(sock.into_std()?)?, peer))
    }

    pub(crate) async fn udp(&self, host: &str, port: u16, cx: Cx) -> io::Result<UdpLink> {
        let ips = self.resolve(host, cx).await?;
        let peer = SocketAddr::new(first_ip(&ips)?, port);
        if let Some((dialer, name)) = self.tunnel()? {
            let peer = Address::Socket(peer);
            let session = passing(&name, dialer.bind_udp(&name, &peer)).await?;
            return Ok(UdpLink::Session { session, peer });
        }
        let sock = self.shared.sockets.bind_udp(peer.ip(), &self.opts())?;
        // Connected, so a server that is down answers with a refusal at once rather
        // than the whole query timeout, and the next upstream gets its turn.
        sock.connect(peer).await?;
        Ok(UdpLink::Socket(sock))
    }
}

fn first_ip(ips: &[IpAddr]) -> io::Result<IpAddr> {
    ips.first()
        .copied()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}
