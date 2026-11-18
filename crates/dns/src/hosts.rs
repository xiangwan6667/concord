use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use concord_common::addr::unmap;
use concord_common::sync::lock;
use concord_config::hosts::{HostValue as ConfigValue, HostsConfig};
use rand::Rng;

use crate::DnsError;
use crate::trie::DomainTrie;

const SYSTEM_HOSTS_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostValue {
    pub is_domain: bool,
    pub ips: Vec<IpAddr>,
    pub domain: String,
}

impl HostValue {
    pub fn from_ips(ips: Vec<IpAddr>) -> Option<Self> {
        (!ips.is_empty()).then(|| HostValue {
            is_domain: false,
            ips: ips.into_iter().map(unmap).collect(),
            domain: String::new(),
        })
    }

    pub fn from_domain(domain: &str) -> Option<Self> {
        let domain = domain.trim_matches('.');
        (domain.split('.').count() >= 2).then(|| HostValue {
            is_domain: true,
            ips: Vec::new(),
            domain: domain.to_string(),
        })
    }

    pub fn rand_ip(&self) -> Option<IpAddr> {
        if self.is_domain || self.ips.is_empty() {
            return None;
        }
        let pick = rand::rng().random_range(0..self.ips.len());
        self.ips.get(pick).copied()
    }
}

type HostTable = HashMap<String, Vec<IpAddr>>;

struct SystemHosts {
    path: PathBuf,
    cache: Mutex<Option<(Instant, HostTable)>>,
}

impl SystemHosts {
    fn new() -> Self {
        let path = match std::env::var_os("SystemRoot") {
            Some(root) => PathBuf::from(root).join(r"System32\drivers\etc\hosts"),
            None => PathBuf::from("/etc/hosts"),
        };
        SystemHosts {
            path,
            cache: Mutex::new(None),
        }
    }

    fn parse(text: &str) -> HashMap<String, Vec<IpAddr>> {
        let mut table: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default();
            let mut fields = line.split_whitespace();
            let Some(ip) = fields.next().and_then(|field| {
                field
                    .split('%')
                    .next()
                    .and_then(|bare| bare.parse::<IpAddr>().ok())
            }) else {
                continue;
            };
            for name in fields {
                table
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .push(unmap(ip));
            }
        }
        table
    }

    fn lookup(&self, domain: &str) -> Vec<IpAddr> {
        let mut cache = lock(&self.cache);
        let stale = cache
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() > SYSTEM_HOSTS_TTL);
        if stale {
            let table = std::fs::read_to_string(&self.path)
                .map(|text| Self::parse(&text))
                .unwrap_or_default();
            *cache = Some((Instant::now(), table));
        }
        cache
            .as_ref()
            .and_then(|(_, table)| table.get(&domain.to_ascii_lowercase()))
            .cloned()
            .unwrap_or_default()
    }
}

/// `resolver.DefaultHosts`: the `hosts` map plus, with `use-system-hosts`, the
/// operating system's hosts file.
pub struct Hosts {
    trie: DomainTrie<HostValue>,
    system: Option<SystemHosts>,
}

impl Default for Hosts {
    fn default() -> Self {
        Hosts {
            trie: DomainTrie::new(),
            system: None,
        }
    }
}

/// mihomo's `lan`: the host's addresses that are neither loopback nor link-local.
fn lan_addrs() -> Vec<IpAddr> {
    let mut addrs = concord_platform::interface_addrs();
    addrs.retain(|addr| {
        !addr.is_loopback()
            && match addr {
                IpAddr::V4(v4) => !v4.is_link_local(),
                IpAddr::V6(v6) => !v6.is_unicast_link_local(),
            }
    });
    addrs
}

impl Hosts {
    pub fn from_config(config: &HostsConfig, use_system_hosts: bool) -> Result<Self, DnsError> {
        let mut hosts = Hosts {
            trie: DomainTrie::new(),
            system: use_system_hosts.then(SystemHosts::new),
        };
        for entry in &config.entries {
            let value = match &entry.value {
                ConfigValue::Ips(ips) => HostValue::from_ips(ips.clone()),
                ConfigValue::Domain(domain) => HostValue::from_domain(domain),
                ConfigValue::Lan => HostValue::from_ips(lan_addrs()),
            }
            .ok_or_else(|| DnsError::config(format!("hosts[{}]: invalid value", entry.domain)))?;
            hosts
                .trie
                .insert(&entry.domain, value)
                .map_err(|err| DnsError::config(format!("hosts[{}]: {err}", entry.domain)))?;
        }
        Ok(hosts)
    }

    pub fn insert_ips(&mut self, domain: &str, ips: Vec<IpAddr>) -> Result<(), DnsError> {
        let value = HostValue::from_ips(ips)
            .ok_or_else(|| DnsError::config(format!("hosts[{domain}]: no address")))?;
        self.trie
            .insert(domain, value)
            .map_err(|err| DnsError::config(format!("hosts[{domain}]: {err}")))
    }

    pub fn insert_alias(&mut self, domain: &str, target: &str) -> Result<(), DnsError> {
        let value = HostValue::from_domain(target)
            .ok_or_else(|| DnsError::config(format!("hosts[{domain}]: invalid domain")))?;
        self.trie
            .insert(domain, value)
            .map_err(|err| DnsError::config(format!("hosts[{domain}]: {err}")))
    }

    /// Mirrors `Hosts.Search`: the value found and whether it has the shape
    /// the caller asked for. `is_domain` asks for an alias, otherwise for
    /// addresses; an alias is followed until the shape matches.
    pub fn search(&self, domain: &str, is_domain: bool) -> (Option<HostValue>, bool) {
        if let Some(found) = self.trie.search(domain) {
            let mut value = found.clone();
            for _ in 0..64 {
                if is_domain && value.is_domain {
                    return (Some(value), true);
                }
                match self.trie.search(&value.domain) {
                    Some(next) => value = next.clone(),
                    None => break,
                }
            }
            let shaped = value.is_domain == is_domain;
            return (Some(value), shaped);
        }
        if !is_domain && let Some(system) = &self.system {
            let ips = system.lookup(domain);
            if let Some(value) = HostValue::from_ips(ips) {
                return (Some(value), true);
            }
        }
        (None, false)
    }

    /// The addresses for `domain`, when `search` finds some.
    pub fn lookup_ips(&self, domain: &str) -> Option<Vec<IpAddr>> {
        match self.search(domain, false) {
            (Some(value), true) => Some(value.ips),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> Hosts {
        let mut hosts = Hosts::default();
        hosts
            .insert_ips("a.example", vec!["1.2.3.4".parse().unwrap()])
            .unwrap();
        hosts.insert_alias("b.example", "a.example").unwrap();
        hosts.insert_alias("c.example", "b.example").unwrap();
        hosts
            .insert_ips(
                "+.wild.example",
                vec!["::1".parse().unwrap(), "9.9.9.9".parse().unwrap()],
            )
            .unwrap();
        hosts
    }

    #[test]
    fn lan_takes_the_addresses_that_are_neither_loopback_nor_link_local() {
        let config = HostsConfig {
            entries: vec![concord_config::hosts::HostEntry {
                domain: "router.lan".into(),
                value: ConfigValue::Lan,
            }],
        };
        let expected = lan_addrs();
        assert!(expected.iter().all(|ip| !ip.is_loopback()));
        match Hosts::from_config(&config, false) {
            Ok(hosts) => assert_eq!(hosts.lookup_ips("router.lan").unwrap().to_vec(), expected),
            Err(err) => assert!(expected.is_empty(), "{err}"),
        }
    }

    #[test]
    fn address_search_follows_aliases() {
        let hosts = hosts();
        let (value, ok) = hosts.search("c.example", false);
        assert!(ok);
        assert_eq!(
            value.unwrap().ips,
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(hosts.lookup_ips("A.EXAMPLE").unwrap().len(), 1);
    }

    #[test]
    fn alias_search_returns_the_first_alias_and_flags_a_mismatch() {
        let hosts = hosts();
        let (value, ok) = hosts.search("c.example", true);
        assert!(ok);
        assert_eq!(value.unwrap().domain, "b.example");
        let (value, ok) = hosts.search("a.example", true);
        assert!(!ok);
        assert!(!value.unwrap().is_domain);
    }

    #[test]
    fn wildcards_and_misses() {
        let hosts = hosts();
        assert_eq!(hosts.lookup_ips("x.y.wild.example").unwrap().len(), 2);
        assert_eq!(hosts.search("nothing.example", false), (None, false));
        assert!(hosts.lookup_ips("c.example.org").is_none());
    }

    #[test]
    fn rand_ip_only_for_addresses() {
        let alias = HostValue::from_domain("x.example").unwrap();
        assert!(alias.rand_ip().is_none());
        let ips = HostValue::from_ips(vec!["::ffff:1.2.3.4".parse().unwrap()]).unwrap();
        assert_eq!(ips.rand_ip(), Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn system_hosts_file_format() {
        let table = SystemHosts::parse(
            "127.0.0.1 localhost lo # note\n::1 localhost\n# skip\n10.0.0.1 NAS.lan\nbad line\n",
        );
        assert_eq!(table.get("localhost").map(Vec::len), Some(2));
        assert!(table.contains_key("nas.lan"));
        assert!(table.contains_key("lo"));
    }
}
