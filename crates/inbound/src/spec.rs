use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use concord_common::addr::unmap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    len: u8,
}

impl Cidr {
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (len <= max).then_some(Cidr { addr, len })
    }

    /// An IPv4-mapped address is compared as IPv4, as `netip.Prefix.Contains` is
    /// called after `Unmap` upstream.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, unmap(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    pub fn any_v4() -> Self {
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            len: 0,
        }
    }

    pub fn any_v6() -> Self {
        Cidr {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            len: 0,
        }
    }
}

impl FromStr for Cidr {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, ()> {
        match text.split_once('/') {
            Some((addr, len)) => {
                let addr: IpAddr = addr.parse().map_err(|_| ())?;
                Cidr::new(addr, len.parse().map_err(|_| ())?).ok_or(())
            }
            None => {
                let addr: IpAddr = text.parse().map_err(|_| ())?;
                Cidr::new(addr, if addr.is_ipv4() { 32 } else { 128 }).ok_or(())
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ListenSpec {
    /// `None` leaves the listener off; `Some(0)` binds an ephemeral port.
    pub mixed_port: Option<u16>,
    pub http_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    /// `*` is the wildcard. Only consulted while `allow_lan` is set.
    pub bind_address: String,
    pub allow_lan: bool,
    pub authentication: Vec<(String, String)>,
    /// Sources that connect without credentials, as mihomo's `skip-auth-prefixes`.
    pub skip_auth: Vec<Cidr>,
    pub lan_allowed_ips: Vec<Cidr>,
    pub lan_disallowed_ips: Vec<Cidr>,
    pub tcp_keepalive: bool,
    pub keepalive_idle_secs: u32,
    pub keepalive_interval_secs: u32,
    pub mptcp: bool,
}

impl Default for ListenSpec {
    fn default() -> Self {
        ListenSpec {
            mixed_port: None,
            http_port: None,
            socks_port: None,
            redir_port: None,
            tproxy_port: None,
            bind_address: "*".to_owned(),
            allow_lan: false,
            authentication: Vec::new(),
            skip_auth: Vec::new(),
            lan_allowed_ips: vec![Cidr::any_v4(), Cidr::any_v6()],
            lan_disallowed_ips: Vec::new(),
            tcp_keepalive: true,
            keepalive_idle_secs: 0,
            keepalive_interval_secs: 0,
            mptcp: false,
        }
    }
}

/// A `user:pass` line, split at the first colon. A line without one is dropped.
pub fn parse_credential(line: &str) -> Option<(String, String)> {
    line.split_once(':')
        .map(|(user, pass)| (user.to_owned(), pass.to_owned()))
}

#[derive(Debug, Default)]
pub(crate) struct Authenticator {
    users: HashMap<String, String>,
}

impl Authenticator {
    fn new(credentials: &[(String, String)]) -> Option<Self> {
        if credentials.is_empty() {
            return None;
        }
        Some(Authenticator {
            users: credentials.iter().cloned().collect(),
        })
    }

    pub(crate) fn verify(&self, user: &str, pass: &str) -> bool {
        self.users.get(user).is_some_and(|known| known == pass)
    }
}

/// What a connection checks at accept and at handshake. Swapped as a whole on
/// every reconcile, so an unchanged listener still sees the new lists.
#[derive(Debug)]
pub(crate) struct Policy {
    auth: Option<Authenticator>,
    skip_auth: Vec<Cidr>,
    allowed: Vec<Cidr>,
    disallowed: Vec<Cidr>,
    pub(crate) keepalive: Option<Keepalive>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Keepalive {
    pub(crate) idle: Duration,
    pub(crate) interval: Duration,
}

const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(15);

fn keepalive_secs(secs: u32) -> Duration {
    if secs == 0 {
        DEFAULT_KEEPALIVE
    } else {
        Duration::from_secs(u64::from(secs))
    }
}

impl Policy {
    pub(crate) fn from_spec(spec: &ListenSpec) -> Self {
        Policy {
            auth: Authenticator::new(&spec.authentication),
            skip_auth: spec.skip_auth.clone(),
            allowed: spec.lan_allowed_ips.clone(),
            disallowed: spec.lan_disallowed_ips.clone(),
            keepalive: spec.tcp_keepalive.then(|| Keepalive {
                idle: keepalive_secs(spec.keepalive_idle_secs),
                interval: keepalive_secs(spec.keepalive_interval_secs),
            }),
        }
    }

    pub(crate) fn admits(&self, ip: IpAddr) -> bool {
        self.allowed.iter().any(|net| net.contains(ip))
            && !self.disallowed.iter().any(|net| net.contains(ip))
    }

    pub(crate) fn authenticator(&self, ip: IpAddr) -> Option<&Authenticator> {
        if self.skip_auth.iter().any(|net| net.contains(ip)) {
            return None;
        }
        self.auth.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    #[test]
    fn cidr_matches_within_a_family_only() {
        assert!(cidr("10.0.0.0/8").contains("10.9.8.7".parse().unwrap()));
        assert!(!cidr("10.0.0.0/8").contains("11.0.0.1".parse().unwrap()));
        assert!(cidr("0.0.0.0/0").contains("203.0.113.9".parse().unwrap()));
        assert!(!cidr("0.0.0.0/0").contains("::1".parse().unwrap()));
        assert!(cidr("::/0").contains("::1".parse().unwrap()));
        assert!(cidr("fe80::/10").contains("fe80::1".parse().unwrap()));
        assert!(!cidr("fe80::/10").contains("fec0::1".parse().unwrap()));
    }

    #[test]
    fn keepalive_follows_the_spec_with_the_default_for_zero() {
        let secs = Duration::from_secs;
        let mut spec = ListenSpec::default();
        let default = Keepalive {
            idle: secs(15),
            interval: secs(15),
        };
        assert_eq!(Policy::from_spec(&spec).keepalive, Some(default));
        spec.keepalive_idle_secs = 120;
        spec.keepalive_interval_secs = 30;
        assert_eq!(
            Policy::from_spec(&spec).keepalive,
            Some(Keepalive {
                idle: secs(120),
                interval: secs(30),
            })
        );
        spec.tcp_keepalive = false;
        assert_eq!(Policy::from_spec(&spec).keepalive, None);
    }

    #[test]
    fn mapped_addresses_are_compared_as_ipv4() {
        assert!(cidr("192.168.0.0/16").contains("::ffff:192.168.1.1".parse().unwrap()));
        assert!(!cidr("::/0").contains("::ffff:192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn bare_addresses_are_host_prefixes_and_bad_lengths_fail() {
        assert!(cidr("1.2.3.4").contains("1.2.3.4".parse().unwrap()));
        assert!(!cidr("1.2.3.4").contains("1.2.3.5".parse().unwrap()));
        assert!("1.2.3.4/33".parse::<Cidr>().is_err());
        assert!("::/129".parse::<Cidr>().is_err());
        assert!("nope".parse::<Cidr>().is_err());
    }

    #[test]
    fn an_empty_allow_list_admits_nobody_and_deny_wins() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut spec = ListenSpec::default();
        assert!(Policy::from_spec(&spec).admits(ip));
        spec.lan_disallowed_ips = vec![cidr("10.0.0.0/24")];
        assert!(!Policy::from_spec(&spec).admits(ip));
        spec.lan_disallowed_ips.clear();
        spec.lan_allowed_ips.clear();
        assert!(!Policy::from_spec(&spec).admits(ip));
    }

    #[test]
    fn the_lists_cover_ipv6_peers() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        let mut spec = ListenSpec::default();
        assert!(Policy::from_spec(&spec).admits(ip));
        spec.lan_allowed_ips = vec![cidr("0.0.0.0/0")];
        assert!(!Policy::from_spec(&spec).admits(ip));
        spec.lan_allowed_ips = vec![cidr("fd00::/8")];
        assert!(Policy::from_spec(&spec).admits(ip));
        spec.lan_disallowed_ips = vec![cidr("fd00::1")];
        assert!(!Policy::from_spec(&spec).admits(ip));
    }

    #[test]
    fn credentials_split_at_the_first_colon() {
        assert_eq!(
            parse_credential("a:b:c"),
            Some(("a".to_owned(), "b:c".to_owned()))
        );
        assert_eq!(parse_credential("nocolon"), None);
    }
}
