use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

use crate::addr::{Address, IpVersion};
use crate::error::CoreError;
use crate::event::{EventSink, Initiator};
use crate::packet::PacketSession;
use crate::stream::BoxStream;

/// `wire_name` is mihomo's `AdapterType.String()`, which Dart compares literally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutboundKind {
    Direct,
    Reject,
    RejectDrop,
    Compatible,
    Pass,
    PassRule,
    Shadowsocks,
    ShadowsocksR,
    Snell,
    Socks5,
    Http,
    Vmess,
    Vless,
    Trojan,
    Hysteria,
    Hysteria2,
    WireGuard,
    Tuic,
    Ssh,
    Mieru,
    AnyTls,
    Miu,
    ShadowQuic,
}

impl OutboundKind {
    pub fn wire_name(self) -> &'static str {
        match self {
            OutboundKind::Direct => "Direct",
            OutboundKind::Reject => "Reject",
            OutboundKind::RejectDrop => "RejectDrop",
            OutboundKind::Compatible => "Compatible",
            OutboundKind::Pass => "Pass",
            OutboundKind::PassRule => "PassRule",
            OutboundKind::Shadowsocks => "Shadowsocks",
            OutboundKind::ShadowsocksR => "ShadowsocksR",
            OutboundKind::Snell => "Snell",
            OutboundKind::Socks5 => "Socks5",
            OutboundKind::Http => "Http",
            OutboundKind::Vmess => "Vmess",
            OutboundKind::Vless => "Vless",
            OutboundKind::Trojan => "Trojan",
            OutboundKind::Hysteria => "Hysteria",
            OutboundKind::Hysteria2 => "Hysteria2",
            OutboundKind::WireGuard => "WireGuard",
            OutboundKind::Tuic => "Tuic",
            OutboundKind::Ssh => "Ssh",
            OutboundKind::Mieru => "Mieru",
            OutboundKind::AnyTls => "AnyTLS",
            OutboundKind::Miu => "Miu",
            OutboundKind::ShadowQuic => "ShadowQuic",
        }
    }

    pub fn is_direct(self) -> bool {
        matches!(self, OutboundKind::Direct | OutboundKind::Compatible)
    }
}

#[derive(Clone, Debug)]
pub struct OutboundInfo {
    pub name: Arc<str>,
    pub kind: OutboundKind,
    /// Part of the exit identity, so a provider swapping the node behind a name shows.
    pub addr: Arc<str>,
    pub udp: bool,
    pub provider: Option<Arc<str>>,
    /// The node's `ip-version`, which also picks the address a UDP destination resolves to.
    pub ip_version: IpVersion,
}

#[async_trait]
pub trait Outbound: Send + Sync + 'static {
    fn info(&self) -> &OutboundInfo;

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream>;

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>>;

    /// False for protocols that bind a UDP session to one destination, such as
    /// plain vmess. The tunnel then keeps one session per destination.
    fn multi_destination_udp(&self) -> bool {
        true
    }

    fn reset_sessions(&self) {}

    /// The node's own answer for a UDP destination name, mihomo's per-adapter
    /// `ResolveUDP`; `None` leaves it to the engine's resolver.
    async fn resolve_udp(&self, _cx: &DialCx<'_>, _host: &str) -> Option<io::Result<IpAddr>> {
        None
    }
}

#[derive(Clone, Debug, Default)]
pub struct SockOpts {
    pub interface: Option<Arc<str>>,
    pub routing_mark: Option<u32>,
    pub tfo: bool,
    pub mptcp: bool,
    pub keep_alive_idle_secs: u32,
    pub keep_alive_interval_secs: u32,
    pub disable_keep_alive: bool,
    /// For a socket carrying a whole tunnel, whose bursts overflow the default buffers.
    pub tunnel_udp_buffers: bool,
}

/// The one way sockets are created, which is what makes `protect`, interface
/// binding and fd-pressure checks impossible to skip.
#[async_trait]
pub trait SocketFactory: Send + Sync {
    async fn connect_tcp(&self, target: SocketAddr, opts: &SockOpts) -> io::Result<TcpStream>;

    fn bind_udp(&self, peer: IpAddr, opts: &SockOpts) -> io::Result<UdpSocket>;

    /// Where a UDP server address really points once `dialer-ip4p-convert` is on.
    fn ip4p(&self, addr: SocketAddr) -> SocketAddr {
        addr
    }
}

#[derive(Clone, Debug, Default)]
pub struct LookupIps {
    pub v4: Vec<IpAddr>,
    pub v6: Vec<IpAddr>,
}

impl LookupIps {
    pub fn first(&self, version: IpVersion) -> Option<IpAddr> {
        match version {
            IpVersion::Dual | IpVersion::Ipv4Prefer => self.v4.first().or(self.v6.first()).copied(),
            IpVersion::Ipv4 => self.v4.first().copied(),
            IpVersion::Ipv6 => self.v6.first().copied(),
            IpVersion::Ipv6Prefer => self.v6.first().or(self.v4.first()).copied(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Names for proxy servers go to `proxy-server-nameserver`; the initiator decides that.
#[async_trait]
pub trait HostResolver: Send + Sync {
    async fn lookup(
        &self,
        host: &str,
        version: IpVersion,
        initiator: Initiator,
    ) -> io::Result<LookupIps>;

    /// The `ECHConfigList` of the HTTPS record for `host`.
    async fn resolve_ech(&self, host: &str, initiator: Initiator) -> io::Result<Vec<u8>> {
        let _ = (host, initiator);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this resolver does not look up ECH configs",
        ))
    }
}

/// `dialer-proxy` targets by name: a group, or a provider node an update replaces.
#[async_trait]
pub trait NodeDialer: Send + Sync {
    async fn dial_via(&self, name: &str, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream>;

    async fn associate_via(
        &self,
        name: &str,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>>;
}

#[derive(Clone)]
pub struct DialEnv {
    pub sockets: Arc<dyn SocketFactory>,
    pub resolver: Arc<dyn HostResolver>,
    pub nodes: Arc<dyn NodeDialer>,
    pub events: Arc<dyn EventSink>,
    /// A node's own value overrides these.
    pub sock_opts: SockOpts,
    pub tcp_concurrent: bool,
    pub ipv6: bool,
}

pub struct DialCx<'a> {
    pub env: &'a DialEnv,
    pub initiator: Initiator,
    pub deadline: Option<Instant>,
    source: Option<SocketAddr>,
    parent: Option<&'a DialCx<'a>>,
    node: &'a str,
}

impl<'a> DialCx<'a> {
    pub fn new(env: &'a DialEnv, initiator: Initiator, deadline: Option<Instant>) -> Self {
        DialCx {
            env,
            initiator,
            deadline,
            source: None,
            parent: None,
            node: "",
        }
    }

    /// The client the dial is for, as mihomo's metadata source.
    pub fn with_source(mut self, source: SocketAddr) -> Self {
        self.source = Some(source);
        self
    }

    pub fn source(&self) -> Option<SocketAddr> {
        self.source
    }

    /// A `dialer-proxy` loop through a group only shows at run time, when the
    /// group's pick closes the circle.
    pub fn enter(&'a self, node: &'a str) -> io::Result<DialCx<'a>> {
        let mut seen = Some(self);
        while let Some(cx) = seen {
            if cx.node == node {
                return Err(CoreError::DialerLoop(node.to_string()).into());
            }
            seen = cx.parent;
        }
        Ok(DialCx {
            env: self.env,
            initiator: self.initiator,
            deadline: self.deadline,
            source: self.source,
            parent: Some(self),
            node,
        })
    }

    pub fn remaining(&self) -> Option<std::time::Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }
}
