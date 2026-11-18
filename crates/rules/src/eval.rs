//! Single-condition evaluation: the compiled form of a rule's condition and the
//! per-step context it runs in.

use std::net::IpAddr;
use std::sync::Arc;

use concord_common::{FlowMeta, InboundKind, Network, RouteState};
use concord_config::filter::Matcher;
use concord_config::net::{IpCidr, PortRange};
use concord_config::rule::UidRange;

use crate::geo::{GeoStore, SiteSlot, is_lan};
use crate::observed::Observed;
use crate::ruleset::RuleSetHandle;
use crate::text::{equal_fold, go_lower, wildcard_match};

/// Why evaluation stopped before an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Yield {
    /// The destination IP is needed. The count is how many address-dependent
    /// checks ran, unanswered, before this one in the same rule.
    Ip(u32),
    Process,
}

pub(crate) type EvResult = Result<bool, Yield>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PortKind {
    Src,
    Dst,
    In,
}

pub(crate) enum GeoIpSource {
    Lan,
    Mmdb,
}

pub(crate) enum ProcessMode {
    Equal(Box<str>),
    Regex(Box<Matcher>),
    Wildcard(Box<[u8]>),
}

pub(crate) enum Node {
    Match,
    Domain(Box<str>),
    Suffix(Box<str>),
    Keyword(Box<str>),
    Wildcard(Box<[u8]>),
    Regex(Box<Matcher>),
    GeoSite(Arc<SiteSlot>),
    GeoIp {
        country: Box<str>,
        negate: bool,
        source: GeoIpSource,
        src: bool,
        resolves: bool,
    },
    Asn {
        asn: Box<str>,
        src: bool,
        resolves: bool,
    },
    Cidr {
        net: IpCidr,
        src: bool,
        resolves: bool,
    },
    IpSuffix {
        ip: IpAddr,
        bits: u8,
        src: bool,
        resolves: bool,
    },
    Port {
        kind: PortKind,
        ranges: Box<[PortRange]>,
    },
    Dscp(Box<[PortRange]>),
    InUser(Box<[Box<str>]>),
    InName(Box<[Box<str>]>),
    RematchName(Box<[Box<str>]>),
    InType(u8),
    Process {
        by_name: bool,
        mode: ProcessMode,
    },
    Network(Network),
    Uid(Box<[UidRange]>),
    RuleSet {
        handle: Arc<RuleSetHandle>,
        src: bool,
        resolves: bool,
    },
    SubRule {
        cond: Box<Node>,
        sub: u32,
    },
    And(Box<[Node]>),
    Or(Box<[Node]>),
    Not(Box<Node>),
}

pub(crate) fn inbound_bit(kind: InboundKind) -> u8 {
    1 << match kind {
        InboundKind::Http => 0,
        InboundKind::Https => 1,
        InboundKind::Socks4 => 2,
        InboundKind::Socks5 => 3,
        InboundKind::Redir => 4,
        InboundKind::TProxy => 5,
        InboundKind::Tun => 6,
        InboundKind::Inner => 7,
    }
}

pub(crate) struct Ev<'a> {
    pub flow: &'a FlowMeta,
    pub state: &'a RouteState,
    pub geo: &'a GeoStore,
    pub dscp: u8,
    pub host: &'a str,
    pub observed: Observed,
    swapped: bool,
    quiet: bool,
    budget: u32,
    counted: u32,
    /// The last `false` came from a geo database still loading, so `NOT` keeps it from matching.
    pub(crate) unknown: bool,
}

impl<'a> Ev<'a> {
    pub(crate) fn new(
        flow: &'a FlowMeta,
        state: &'a RouteState,
        geo: &'a GeoStore,
        dscp: u8,
        replay: u32,
        observed: Observed,
    ) -> Self {
        Ev {
            flow,
            state,
            geo,
            dscp,
            host: state.host.as_deref().unwrap_or(""),
            observed,
            swapped: false,
            quiet: false,
            budget: replay,
            counted: 0,
            unknown: false,
        }
    }

    fn dst_unknown(&self) -> bool {
        self.state.ip.is_none() && !self.state.ip_resolved && self.state.host.is_some()
    }

    /// The destination address as this check sees it. `resolves` marks a check
    /// that, in mihomo, calls the resolver first: it yields when the address is
    /// still unknown. Checks answered before the yield keep seeing "unknown" when
    /// the rule is evaluated again, as mihomo does not revisit them.
    pub(crate) fn dst_ip(&mut self, resolves: bool) -> Result<Option<IpAddr>, Yield> {
        if self.swapped {
            return Ok(Some(self.flow.src.ip()));
        }
        if self.budget > 0 {
            self.budget -= 1;
            self.counted += 1;
            return Ok(None);
        }
        if self.dst_unknown() {
            if resolves && !self.quiet {
                return Err(Yield::Ip(self.counted));
            }
            self.counted += 1;
            return Ok(None);
        }
        Ok(self.state.ip)
    }

    pub(crate) fn src_ip(&self) -> Option<IpAddr> {
        if self.swapped {
            self.state.ip
        } else {
            Some(self.flow.src.ip())
        }
    }

    fn view_ip(&mut self, src: bool, resolves: bool) -> Result<Option<IpAddr>, Yield> {
        if src {
            Ok(self.src_ip())
        } else {
            self.dst_ip(resolves)
        }
    }

    fn port(&self, kind: PortKind) -> u16 {
        match (kind, self.swapped) {
            (PortKind::Dst, false) | (PortKind::Src, true) => self.flow.dst.port(),
            (PortKind::Src, false) | (PortKind::Dst, true) => self.flow.src.port(),
            (PortKind::In, _) => self.flow.inbound.addr.map_or(0, |addr| addr.port()),
        }
    }

    fn process(&self) -> Result<(&'a str, &'a str, Option<u32>), Yield> {
        if !self.state.process_looked_up {
            return Err(Yield::Process);
        }
        Ok(self.state.process.as_deref().map_or(("", "", None), |p| {
            (p.name.as_str(), p.path.as_str(), p.uid)
        }))
    }

    pub(crate) fn eval(&mut self, node: &Node) -> EvResult {
        self.unknown = false;
        Ok(match node {
            Node::Match => true,
            Node::Domain(domain) => self.host == &**domain,
            Node::Suffix(suffix) => has_domain_suffix(self.host, suffix),
            Node::Keyword(keyword) => self.host.contains(&**keyword),
            Node::Wildcard(pattern) => wildcard_match(pattern, self.host.as_bytes(), false),
            Node::Regex(matcher) => matcher.is_match(self.host),
            Node::GeoSite(slot) => slot.matches(self.host),
            Node::GeoIp {
                country,
                negate,
                source,
                src,
                resolves,
            } => {
                let Some(ip) = self.view_ip(*src, *resolves)? else {
                    return Ok(false);
                };
                let geo = self.geo;
                let seen = self.observed.geoip_mut(*src != self.swapped);
                let matched = match source {
                    GeoIpSource::Lan => is_lan(ip),
                    GeoIpSource::Mmdb => seen
                        .get_or_insert_with(|| geo.country_codes(ip))
                        .iter()
                        .any(|code| code == &**country),
                };
                matched != *negate
            }
            Node::Asn { .. } if !self.geo.has_asn() => {
                self.unknown = true;
                false
            }
            Node::Asn { asn, src, resolves } => match self.view_ip(*src, *resolves)? {
                Some(ip) => {
                    let geo = self.geo;
                    let seen = self.observed.asn_mut(*src != self.swapped);
                    if seen.is_empty() {
                        let (number, org) = geo
                            .asn(ip)
                            .map_or_else(Default::default, |record| (record.asn, record.org));
                        *seen = format!("{number} {org}");
                    }
                    seen.split(' ').next() == Some(&**asn)
                }
                None => false,
            },
            Node::Cidr { net, src, resolves } => match self.view_ip(*src, *resolves)? {
                Some(ip) => net.contains(ip),
                None => false,
            },
            Node::IpSuffix {
                ip: rule,
                bits,
                src,
                resolves,
            } => match self.view_ip(*src, *resolves)? {
                Some(ip) => ip_suffix_match(*rule, *bits, ip),
                None => false,
            },
            Node::Port { kind, ranges } => {
                let port = self.port(*kind);
                ranges.is_empty() || ranges.iter().any(|r| r.contains(port))
            }
            Node::Dscp(ranges) => {
                let value = u16::from(self.dscp);
                ranges.is_empty() || ranges.iter().any(|r| r.contains(value))
            }
            Node::InUser(users) => self
                .flow
                .inbound
                .user
                .as_deref()
                .is_some_and(|user| users.iter().any(|u| &**u == user)),
            Node::InName(names) => {
                let name: &str = &self.flow.inbound.name;
                names.iter().any(|n| &**n == name)
            }
            Node::RematchName(names) => {
                let name = self.state.rematch_name.as_deref().unwrap_or_default();
                names.iter().any(|n| &**n == name)
            }
            Node::InType(mask) => mask & inbound_bit(self.flow.inbound.kind) != 0,
            Node::Process { by_name, mode } => {
                let (name, path, _) = self.process()?;
                let target = if *by_name { name } else { path };
                match mode {
                    ProcessMode::Equal(pattern) => equal_fold(target, pattern),
                    ProcessMode::Regex(matcher) => matcher.is_match(target),
                    ProcessMode::Wildcard(pattern) if target.is_ascii() => {
                        wildcard_match(pattern, target.as_bytes(), true)
                    }
                    ProcessMode::Wildcard(pattern) => {
                        wildcard_match(pattern, go_lower(target).as_bytes(), false)
                    }
                }
            }
            Node::Network(network) => self.flow.network == *network,
            Node::Uid(ranges) => match self.process()?.2 {
                Some(uid) if uid != 0 => ranges.iter().any(|r| (r.start..=r.end).contains(&uid)),
                _ => false,
            },
            Node::RuleSet {
                handle,
                src,
                resolves,
            } => {
                let set = handle.load();
                let saved = (self.swapped, self.quiet);
                if *src {
                    self.swapped = true;
                    self.quiet = true;
                } else if !*resolves {
                    self.quiet = true;
                }
                let result = set.matches(self);
                (self.swapped, self.quiet) = saved;
                result?
            }
            Node::SubRule { cond, .. } => self.eval(cond)?,
            Node::And(children) => {
                let mut unknown = false;
                for child in children.iter() {
                    if !self.eval(child)? {
                        if !self.unknown {
                            return Ok(false);
                        }
                        unknown = true;
                    }
                }
                self.unknown = unknown;
                !unknown
            }
            Node::Or(children) => {
                let mut unknown = false;
                for child in children.iter() {
                    if self.eval(child)? {
                        return Ok(true);
                    }
                    unknown |= self.unknown;
                }
                self.unknown = unknown;
                false
            }
            Node::Not(child) => {
                let matched = self.eval(child)?;
                if matched {
                    self.unknown = false;
                }
                !matched && !self.unknown
            }
        })
    }
}

pub(crate) fn has_domain_suffix(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes().get(host.len() - suffix.len() - 1) == Some(&b'.')
}

/// The last `bits` bits of the address equal those of the rule's address.
pub(crate) fn ip_suffix_match(rule: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (rule, ip) {
        (IpAddr::V4(rule), IpAddr::V4(ip)) => {
            let mask = if bits >= 32 {
                u32::MAX
            } else {
                (1u32 << bits) - 1
            };
            u32::from(rule) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(rule), IpAddr::V6(ip)) => {
            let mask = if bits >= 128 {
                u128::MAX
            } else {
                (1u128 << bits) - 1
            };
            u128::from(rule) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_follows_label_boundaries() {
        assert!(has_domain_suffix("example.com", "example.com"));
        assert!(has_domain_suffix("a.example.com", "example.com"));
        assert!(!has_domain_suffix("badexample.com", "example.com"));
        assert!(!has_domain_suffix("example.com.cn", "example.com"));
        assert!(!has_domain_suffix("", "example.com"));
    }

    #[test]
    fn ip_suffix_compares_trailing_bits() {
        let rule: IpAddr = "0.0.0.1".parse().unwrap();
        assert!(ip_suffix_match(rule, 8, "9.9.9.1".parse().unwrap()));
        assert!(!ip_suffix_match(rule, 8, "9.9.9.2".parse().unwrap()));
        assert!(ip_suffix_match(rule, 12, "1.1.0.1".parse().unwrap()));
        assert!(!ip_suffix_match(rule, 12, "1.1.1.1".parse().unwrap()));
        assert!(!ip_suffix_match(rule, 8, "::1".parse().unwrap()));
        assert!(ip_suffix_match(
            "::1".parse().unwrap(),
            64,
            "5::1".parse().unwrap()
        ));
    }
}
