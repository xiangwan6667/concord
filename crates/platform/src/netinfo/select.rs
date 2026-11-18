use std::net::IpAddr;

#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    windows,
    test
))]
pub struct Candidate {
    pub name: String,
    pub metric: u32,
    pub scoped: bool,
}

/// Unscoped routes win over per-interface scoped fallbacks, then the lowest metric,
/// then table order. Excluded names (the TUN device) and loopback never qualify.
#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    windows,
    test
))]
pub fn pick<'a>(candidates: &'a [Candidate], excluded: &[String]) -> Option<&'a Candidate> {
    candidates
        .iter()
        .filter(|candidate| {
            !excluded.iter().any(|name| name == &candidate.name)
                && !matches!(candidate.name.as_str(), "lo" | "lo0")
        })
        .min_by_key(|candidate| (candidate.scoped, candidate.metric))
}

pub struct Subnet {
    pub name: String,
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Subnet {
    fn contains(&self, ip: IpAddr) -> bool {
        let (net, ip, width) = match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => (
                u128::from(u32::from(net)) << 96,
                u128::from(u32::from(ip)) << 96,
                32,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => (u128::from(net), u128::from(ip), 128),
            _ => return false,
        };
        let prefix = u32::from(self.prefix).min(width);
        let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
        net & mask == ip & mask
    }
}

/// mihomo's `ResolveInterfaceByAddr`: the interface holding `dest` itself, else the
/// narrowest subnet around it.
pub fn by_addr(subnets: &[Subnet], dest: IpAddr) -> Option<&Subnet> {
    let dest = dest.to_canonical();
    subnets
        .iter()
        .find(|subnet| subnet.addr == dest)
        .or_else(|| {
            subnets
                .iter()
                .filter(|subnet| subnet.contains(dest))
                .rev()
                .max_by_key(|subnet| subnet.prefix)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(name: &str, metric: u32, scoped: bool) -> Candidate {
        Candidate {
            name: name.to_string(),
            metric,
            scoped,
        }
    }

    #[test]
    fn excluded_and_loopback_routes_are_skipped() {
        let all = [
            candidate("utun4", 0, false),
            candidate("lo0", 0, false),
            candidate("en1", 200, true),
            candidate("en0", 100, true),
        ];
        let excluded = vec!["utun4".to_string()];
        assert_eq!(pick(&all, &excluded).map(|c| c.name.as_str()), Some("en0"));
        assert!(pick(&all[..2], &excluded).is_none());
    }

    fn subnet(name: &str, addr: &str, prefix: u8) -> Subnet {
        Subnet {
            name: name.to_string(),
            addr: addr.parse().unwrap(),
            prefix,
        }
    }

    fn on<'a>(subnets: &'a [Subnet], dest: &str) -> Option<&'a str> {
        by_addr(subnets, dest.parse().unwrap()).map(|subnet| subnet.name.as_str())
    }

    #[test]
    fn a_destination_goes_to_the_interface_it_is_on() {
        let all = [
            subnet("en0", "192.168.1.20", 16),
            subnet("en1", "192.168.5.7", 24),
            subnet("utun4", "198.18.0.1", 30),
            subnet("en0", "2001:db8::20", 64),
        ];
        assert_eq!(on(&all, "192.168.5.9"), Some("en1"));
        assert_eq!(on(&all, "192.168.9.9"), Some("en0"));
        assert_eq!(on(&all, "::ffff:192.168.9.9"), Some("en0"));
        assert_eq!(on(&all, "198.18.0.2"), Some("utun4"));
        assert_eq!(on(&all, "2001:db8::1"), Some("en0"));
        assert_eq!(on(&all, "8.8.8.8"), None);
        assert_eq!(on(&all, "2001:db9::1"), None);
    }

    #[test]
    fn an_assigned_address_wins_over_a_narrower_subnet() {
        let all = [
            subnet("en1", "10.0.0.0", 32),
            subnet("en0", "10.0.0.9", 8),
            subnet("all", "0.0.0.0", 0),
        ];
        assert_eq!(on(&all, "10.0.0.9"), Some("en0"));
        assert_eq!(on(&all, "10.0.0.0"), Some("en1"));
        assert_eq!(on(&all, "11.0.0.1"), Some("all"));
    }

    #[test]
    fn unscoped_beats_scoped_and_lower_metric_beats_higher() {
        let all = [
            candidate("en1", 5, true),
            candidate("wlan0", 600, false),
            candidate("eth0", 100, false),
        ];
        assert_eq!(pick(&all, &[]).map(|c| c.name.as_str()), Some("eth0"));
    }
}
