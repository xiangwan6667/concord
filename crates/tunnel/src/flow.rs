use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use concord_common::addr::unmap;
use concord_common::{
    Address, CORE_NAME, ConnMeta, DnsMode, FlowKey, FlowMeta, Host, InboundKind, ProcessInfo,
    RouteState,
};
use concord_dns::Resolver;
use concord_rules::Observed;

use crate::intercept::InterceptFlow;
use crate::sniff::SniffTarget;

/// mihomo's `Metadata`: what a flow has learned about where it is going.
#[derive(Clone, Debug)]
pub(crate) struct FlowState {
    pub meta: FlowMeta,
    pub host: Option<Host>,
    pub dst_ip: Option<IpAddr>,
    pub port: u16,
    pub dns_mode: Option<DnsMode>,
    pub sniff_host: Option<Host>,
    pub special_proxy: Option<Arc<str>>,
    pub special_rules: Option<Arc<str>>,
    pub rematch_name: Option<Arc<str>>,
    pub process: Option<Arc<ProcessInfo>>,
    pub process_looked_up: bool,
    pub ip_resolved: bool,
    pub dscp: u8,
    pub observed: Observed,
}

/// `netip.ParseAddr`: an IPv6 literal may carry a `%zone`, which the address drops.
fn host_ip(host: &str) -> Option<IpAddr> {
    match host.split_once('%') {
        Some((ip, zone)) if !zone.is_empty() => ip.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
        Some(_) => None,
        None => host.parse().ok(),
    }
}

impl FlowState {
    /// A flow the MITM engine dials on behalf of its client.
    pub fn of_intercept(flow: &InterceptFlow) -> Self {
        let mut state = FlowState::new(flow.meta.clone());
        if flow.sniffed {
            state.sniff_host = flow.host.clone();
        } else if flow.host.is_some() {
            state.host = flow.host.clone();
        }
        state.dst_ip = flow.dst_ip;
        state.port = flow.port;
        state
    }

    /// What the MITM engine sees of this flow: the name rules would match.
    pub fn intercept(&self) -> InterceptFlow {
        InterceptFlow {
            meta: self.meta.clone(),
            host: self.rule_host().cloned(),
            sniffed: self.sniff_host.is_some(),
            dst_ip: self.dst_ip,
            port: self.port,
        }
    }

    pub fn new(meta: FlowMeta) -> Self {
        let dscp = meta.dscp;
        let (host, dst_ip) = match &meta.dst {
            Address::Socket(addr) => (None, Some(unmap(addr.ip()))),
            Address::Domain(host, _) => match host_ip(host) {
                Some(ip) => (None, Some(unmap(ip))),
                None => (Some(host.clone()).filter(|host| !host.is_empty()), None),
            },
        };
        let port = meta.dst.port();
        let inner = meta.inbound.kind == InboundKind::Inner;
        FlowState {
            meta,
            host,
            dst_ip,
            port,
            dns_mode: None,
            sniff_host: None,
            special_proxy: None,
            special_rules: None,
            rematch_name: None,
            process: inner.then(|| {
                Arc::new(ProcessInfo {
                    uid: None,
                    name: CORE_NAME.to_string(),
                    path: String::new(),
                })
            }),
            process_looked_up: inner,
            ip_resolved: false,
            dscp,
            observed: Observed::default(),
        }
    }

    pub fn valid(&self) -> bool {
        self.host.is_some() || self.dst_ip.is_some()
    }

    pub fn rule_host(&self) -> Option<&Host> {
        self.sniff_host.as_ref().or(self.host.as_ref())
    }

    pub fn sniff_target(&mut self) -> SniffTarget<'_> {
        SniffTarget {
            host: &mut self.host,
            dst_ip: &mut self.dst_ip,
            src_ip: self.meta.src.ip(),
            dst_port: self.port,
            dns_mode: &mut self.dns_mode,
            sniff_host: &mut self.sniff_host,
        }
    }

    pub fn route_state(&self) -> RouteState {
        RouteState {
            host: self.rule_host().cloned(),
            ip: self.dst_ip,
            ip_resolved: self.ip_resolved,
            process: self.process.clone(),
            process_looked_up: self.process_looked_up,
            special_rules: self.special_rules.clone(),
            rematch_name: self.rematch_name.clone(),
        }
    }

    pub fn owner_key(&self) -> FlowKey {
        let dst = self
            .dst_ip
            .or_else(|| self.meta.dst.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        FlowKey {
            network: self.meta.network,
            src: self.meta.src,
            dst: SocketAddr::new(dst, self.port),
        }
    }

    /// mihomo's `RemoteAddress`: the name when there is one.
    pub fn remote_address(&self) -> Address {
        match (&self.host, self.dst_ip) {
            (Some(host), _) => Address::Domain(host.clone(), self.port),
            (None, Some(ip)) => Address::Socket(SocketAddr::new(ip, self.port)),
            (None, None) => Address::Domain(Host::const_new(""), self.port),
        }
    }

    /// `Metadata.Pure`: a mapped or hosts entry already says which IP to use.
    pub fn pure_address(&self) -> Address {
        match (self.dns_mode, self.dst_ip) {
            (Some(DnsMode::RedirHost | DnsMode::Hosts), Some(ip)) => {
                Address::Socket(SocketAddr::new(ip, self.port))
            }
            _ => self.remote_address(),
        }
    }

    pub fn remote_text(&self) -> String {
        let host = self
            .host
            .as_ref()
            .map(ToString::to_string)
            .or_else(|| self.dst_ip.map(|ip| ip.to_string()))
            .unwrap_or_else(|| "<nil>".to_string());
        if host.contains(':') {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn source_detail(&self) -> String {
        if self.meta.inbound.kind == InboundKind::Inner {
            return CORE_NAME.to_string();
        }
        let source = self.meta.src;
        let process = self.process.as_deref();
        let name = process.map_or("", |process| process.name.as_str());
        let uid = process
            .and_then(|process| process.uid)
            .filter(|uid| *uid != 0);
        match (name.is_empty(), uid) {
            (false, Some(uid)) => format!("{source}({name}, uid={uid})"),
            (true, Some(uid)) => format!("{source}(uid={uid})"),
            (false, None) => format!("{source}({name})"),
            (true, None) => source.to_string(),
        }
    }

    pub fn network_name(&self) -> &'static str {
        match self.meta.network {
            concord_common::Network::Tcp => "TCP",
            concord_common::Network::Udp => "UDP",
        }
    }

    pub fn conn_meta(&self, remote_destination: String) -> ConnMeta {
        let process = self.process.as_deref();
        ConnMeta {
            network: self.meta.network,
            inbound: self.meta.inbound.clone(),
            src: self.meta.src,
            dst_ip: self.dst_ip,
            dst_port: self.port,
            host: self.host.clone().unwrap_or_default(),
            sniff_host: self.sniff_host.clone().unwrap_or_default(),
            dns_mode: self.dns_mode,
            uid: process.and_then(|process| process.uid),
            process: process
                .map(|process| process.name.clone())
                .unwrap_or_default(),
            process_path: process
                .map(|process| process.path.clone())
                .unwrap_or_default(),
            remote_destination,
            src_geoip: self.observed.src_geoip.clone(),
            dst_geoip: self.observed.dst_geoip.clone(),
            src_asn: self.observed.src_asn.clone(),
            dst_asn: self.observed.dst_asn.clone(),
            rematch_name: self.rematch_name.as_deref().unwrap_or_default().to_string(),
            special_rules: self
                .special_rules
                .as_deref()
                .unwrap_or_default()
                .to_string(),
            special_proxy: self
                .special_proxy
                .as_deref()
                .map(str::to_string)
                .unwrap_or_default(),
        }
    }
}

/// `preHandleMetadata`. An error means a fake-ip with no record behind it.
pub(crate) fn pre_handle(flow: &mut FlowState, dns: &Resolver) -> Result<(), String> {
    if let (true, None, Some(ip)) = (dns.mapping_enabled(), &flow.host, flow.dst_ip) {
        if let Some(host) = dns.find_host_by_ip(ip) {
            flow.dns_mode = Some(DnsMode::RedirHost);
            let is_fake = dns.is_fake_ip(ip);
            let (node, found) = if is_fake {
                (None, false)
            } else {
                dns.hosts().search(&host, false)
            };
            flow.host = Some(host);
            if is_fake {
                flow.dst_ip = None;
                flow.dns_mode = Some(DnsMode::FakeIp);
            } else if found {
                flow.dst_ip = node.and_then(|node| node.rand_ip());
            } else if let Some(node) = node.filter(|node| node.is_domain) {
                flow.host = Some(Host::from(node.domain));
            }
        } else if dns.is_fake_ip(ip) {
            return Err(format!("fake DNS record {ip} missing"));
        }
    } else if let Some(host) = &flow.host
        && let (Some(node), true) = dns.hosts().search(host, true)
    {
        flow.host = Some(Host::from(node.domain));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use concord_common::{InboundInfo, Network};

    use super::*;

    fn state(dst: Address) -> FlowState {
        FlowState::new(FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound: InboundInfo::new(InboundKind::Socks5),
            src: "10.0.0.1:1000".parse().unwrap(),
            dst,
        })
    }

    #[test]
    fn an_ip_written_as_a_host_is_an_ip() {
        let flow = state(Address::Domain(Host::const_new("1.2.3.4"), 80));
        assert_eq!(flow.host, None);
        assert_eq!(flow.dst_ip, Some("1.2.3.4".parse().unwrap()));
        assert!(flow.valid());
        assert!(!state(Address::Domain(Host::const_new(""), 80)).valid());
    }

    #[test]
    fn a_zoned_v6_literal_is_an_ip() {
        let flow = state(Address::Domain(Host::const_new("fe80::1%eth0"), 80));
        assert_eq!(flow.host, None);
        assert_eq!(flow.dst_ip, Some("fe80::1".parse().unwrap()));
        for bad in ["fe80::1%", "1.2.3.4%eth0", "a.example%eth0"] {
            assert!(
                state(Address::Domain(Host::const_new(bad), 80))
                    .host
                    .is_some()
            );
        }
    }

    #[test]
    fn the_sniffed_name_is_what_rules_see_but_not_what_is_dialled() {
        let mut flow = state(Address::Domain(Host::const_new("a.example"), 443));
        flow.sniff_host = Some(Host::const_new("b.example"));
        assert_eq!(flow.route_state().host.as_deref(), Some("b.example"));
        assert_eq!(flow.remote_address().domain(), Some("a.example"));
        assert_eq!(flow.remote_text(), "a.example:443");
    }

    #[test]
    fn pure_addresses_drop_the_name_only_for_mapped_entries() {
        let mut flow = state(Address::Domain(Host::const_new("a.example"), 443));
        flow.dst_ip = Some("1.1.1.1".parse().unwrap());
        assert_eq!(flow.pure_address().domain(), Some("a.example"));
        flow.dns_mode = Some(DnsMode::Hosts);
        assert_eq!(flow.pure_address().ip(), flow.dst_ip);
        flow.dns_mode = Some(DnsMode::FakeIp);
        assert_eq!(flow.pure_address().domain(), Some("a.example"));
    }

    #[test]
    fn the_source_detail_reads_like_the_other_core() {
        let mut flow = state(Address::new("1.1.1.1", 80));
        assert_eq!(flow.source_detail(), "10.0.0.1:1000");
        flow.process = Some(Arc::new(ProcessInfo {
            uid: Some(1000),
            name: "curl".to_string(),
            path: String::new(),
        }));
        assert_eq!(flow.source_detail(), "10.0.0.1:1000(curl, uid=1000)");
        flow.meta.inbound.kind = InboundKind::Inner;
        assert_eq!(flow.source_detail(), "concord");
    }

    #[test]
    fn what_rules_looked_up_reaches_the_connection_record() {
        let mut flow = state(Address::new("1.1.1.1", 80));
        let meta = flow.conn_meta(String::new());
        assert_eq!((meta.src_geoip, meta.dst_geoip), (None, None));
        flow.observed = Observed {
            src_geoip: Some(Vec::new()),
            dst_geoip: Some(vec!["au".to_string()]),
            src_asn: String::new(),
            dst_asn: "13335 Cloudflare".to_string(),
        };
        let meta = flow.conn_meta(String::new());
        assert_eq!(meta.src_geoip, Some(Vec::new()));
        assert_eq!(meta.dst_geoip, Some(vec!["au".to_string()]));
        assert_eq!(meta.dst_asn, "13335 Cloudflare");
    }

    #[test]
    fn a_v6_remote_is_bracketed() {
        let flow = state(Address::new("::1", 53));
        assert_eq!(flow.remote_text(), "[::1]:53");
    }
}
