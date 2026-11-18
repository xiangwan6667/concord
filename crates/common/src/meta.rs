use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::addr::{Address, Host, Network};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InboundKind {
    Http,
    Https,
    Socks4,
    Socks5,
    Redir,
    TProxy,
    Tun,
    Inner,
}

impl InboundKind {
    pub fn wire_name(self) -> &'static str {
        match self {
            InboundKind::Http => "HTTP",
            InboundKind::Https => "HTTPS",
            InboundKind::Socks4 => "Socks4",
            InboundKind::Socks5 => "Socks5",
            InboundKind::Redir => "Redir",
            InboundKind::TProxy => "TProxy",
            InboundKind::Tun => "Tun",
            InboundKind::Inner => "Inner",
        }
    }

    /// `IN-TYPE` compares upper-case spellings: `SOCKS5`, not `Socks5`.
    pub fn rule_name(self) -> &'static str {
        match self {
            InboundKind::Http => "HTTP",
            InboundKind::Https => "HTTPS",
            InboundKind::Socks4 => "SOCKS4",
            InboundKind::Socks5 => "SOCKS5",
            InboundKind::Redir => "REDIR",
            InboundKind::TProxy => "TPROXY",
            InboundKind::Tun => "TUN",
            InboundKind::Inner => "INNER",
        }
    }
}

#[derive(Clone, Debug)]
pub struct InboundInfo {
    pub kind: InboundKind,
    pub name: Arc<str>,
    pub addr: Option<SocketAddr>,
    pub user: Option<Arc<str>>,
}

impl InboundInfo {
    pub fn new(kind: InboundKind) -> Self {
        InboundInfo {
            kind,
            name: Arc::from(""),
            addr: None,
            user: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FlowMeta {
    pub network: Network,
    pub inbound: InboundInfo,
    pub src: SocketAddr,
    /// The destination before any fake-ip reversal.
    pub dst: Address,
    /// The DSCP of the packet that opened the flow; only TProxy UDP reads it, as in mihomo.
    pub dscp: u8,
}

/// A datagram's flow as its inbound sees it. A handler builds the owned [`FlowMeta`] only for
/// a flow it has not seen.
pub struct UdpFlow<'a> {
    pub inbound: &'a InboundInfo,
    pub src: SocketAddr,
    pub dst: Address,
    /// Read only by TProxy, as in [`FlowMeta::dscp`].
    pub dscp: u8,
}

impl UdpFlow<'_> {
    pub fn meta(&self) -> FlowMeta {
        FlowMeta {
            network: Network::Udp,
            inbound: self.inbound.clone(),
            src: self.src,
            dst: self.dst.clone(),
            dscp: self.dscp,
        }
    }
}

impl FlowMeta {
    /// The address the flow arrived at on this machine: the accepted socket's own address
    /// for a proxy listener, the flow's destination before any fake-ip reversal for the
    /// others. `None` when it is not a concrete address.
    pub fn arrived_at(&self) -> Option<SocketAddr> {
        let addr = match self.inbound.kind {
            InboundKind::Http | InboundKind::Https | InboundKind::Socks4 | InboundKind::Socks5 => {
                self.inbound.addr
            }
            InboundKind::Tun | InboundKind::Redir | InboundKind::TProxy => match &self.dst {
                Address::Socket(addr) => Some(*addr),
                Address::Domain(..) => None,
            },
            InboundKind::Inner => None,
        };
        addr.filter(|addr| !addr.ip().is_unspecified())
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcessInfo {
    pub uid: Option<u32>,
    pub name: String,
    pub path: String,
}

/// What a process lookup and a TUN flow are keyed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub network: Network,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// Filled in as routing progresses, each item computed at most once.
#[derive(Clone, Debug, Default)]
pub struct RouteState {
    pub host: Option<Host>,
    pub ip: Option<IpAddr>,
    pub ip_resolved: bool,
    pub process: Option<Arc<ProcessInfo>>,
    pub process_looked_up: bool,
    pub special_rules: Option<Arc<str>>,
    pub rematch_name: Option<Arc<str>>,
}

impl RouteState {
    pub fn seed(dst: &Address) -> Self {
        match dst {
            Address::Socket(addr) => RouteState {
                ip: Some(addr.ip()),
                ip_resolved: true,
                ..Default::default()
            },
            Address::Domain(host, _) => RouteState {
                host: Some(host.clone()),
                ..Default::default()
            },
        }
    }
}

/// `metadata.dnsMode` on the wire; Dart's enum knows exactly these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnsMode {
    Normal,
    FakeIp,
    RedirHost,
    Hosts,
}

impl DnsMode {
    pub fn wire_name(self) -> &'static str {
        match self {
            DnsMode::Normal => "normal",
            DnsMode::FakeIp => "fake-ip",
            DnsMode::RedirHost => "redir-host",
            DnsMode::Hosts => "hosts",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(kind: InboundKind, listen: Option<&str>, dst: Address) -> FlowMeta {
        let mut inbound = InboundInfo::new(kind);
        inbound.addr = listen.map(|addr| addr.parse().unwrap());
        FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound,
            src: "10.0.0.2:5000".parse().unwrap(),
            dst,
        }
    }

    #[test]
    fn a_proxy_listener_flow_arrived_at_the_accepted_address() {
        let dst = Address::new("example.com", 443);
        let meta = flow(InboundKind::Socks5, Some("127.0.0.1:7890"), dst.clone());
        assert_eq!(meta.arrived_at(), Some("127.0.0.1:7890".parse().unwrap()));
        assert_eq!(
            flow(InboundKind::Http, None, dst.clone()).arrived_at(),
            None
        );
        let any = flow(InboundKind::Http, Some("0.0.0.0:7890"), dst);
        assert_eq!(any.arrived_at(), None);
    }

    #[test]
    fn transparent_and_tun_flows_arrived_at_their_destination() {
        let dst = Address::from("1.1.1.1:443".parse::<SocketAddr>().unwrap());
        for kind in [InboundKind::Tun, InboundKind::Redir, InboundKind::TProxy] {
            let meta = flow(kind, Some("127.0.0.1:7892"), dst.clone());
            assert_eq!(meta.arrived_at(), Some("1.1.1.1:443".parse().unwrap()));
        }
        let named = flow(InboundKind::Tun, None, Address::new("example.com", 443));
        assert_eq!(named.arrived_at(), None);
        assert_eq!(flow(InboundKind::Inner, None, dst).arrived_at(), None);
    }
}
