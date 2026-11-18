use std::net::{IpAddr, Ipv4Addr};

use crate::Map;
use crate::error::{ConfigError, Result};
use crate::lenient::value_to_strings;
use crate::report::LoadReport;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostValue {
    Ips(Vec<IpAddr>),
    Domain(String),
    /// The host's own addresses, read when the profile is applied.
    Lan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEntry {
    pub domain: String,
    pub value: HostValue,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostsConfig {
    pub entries: Vec<HostEntry>,
}

impl HostsConfig {
    pub fn lookup(&self, name: &str) -> Option<&HostEntry> {
        let name = name.to_ascii_lowercase();
        if let Some(found) = self
            .entries
            .iter()
            .rev()
            .find(|e| e.domain.eq_ignore_ascii_case(&name))
        {
            return Some(found);
        }
        let mut rest = name.as_str();
        let mut first = true;
        while let Some((_, parent)) = rest.split_once('.') {
            let wildcard = self.entries.iter().rev().find(|entry| {
                let domain = entry.domain.to_ascii_lowercase();
                domain.strip_prefix("+.") == Some(parent)
                    || (first && domain.strip_prefix("*.") == Some(parent))
            });
            if wildcard.is_some() {
                return wildcard;
            }
            first = false;
            rest = parent;
        }
        None
    }
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains(' ')
}

pub fn parse_hosts(map: &Map, report: &mut LoadReport) -> Result<HostsConfig> {
    let mut config = HostsConfig {
        entries: vec![HostEntry {
            domain: "localhost".to_string(),
            value: HostValue::Ips(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        }],
    };
    for (domain, value) in map {
        let items = value_to_strings(value);
        let parsed = if items.len() == 1 && items.first().is_some_and(|item| item == "lan") {
            HostValue::Lan
        } else if items.len() == 1
            && items
                .first()
                .is_some_and(|item| item.parse::<IpAddr>().is_err())
        {
            HostValue::Domain(items.first().cloned().unwrap_or_default())
        } else {
            let mut ips = Vec::with_capacity(items.len());
            for item in &items {
                ips.push(item.parse::<IpAddr>().map_err(|_| {
                    ConfigError::new(format!("hosts[{domain}]: {value} is not a valid value"))
                })?);
            }
            if ips.is_empty() {
                return Err(ConfigError::new(format!(
                    "hosts[{domain}]: {value} is not a valid value"
                )));
            }
            HostValue::Ips(ips)
        };
        if !valid_domain(domain) {
            report.warn(
                "invalid_host",
                format!("hosts.{domain}"),
                "skip invalid hosts entry",
            );
            continue;
        }
        if let HostValue::Domain(target) = &parsed {
            if target.eq_ignore_ascii_case(domain) {
                report.warn(
                    "invalid_host",
                    format!("hosts.{domain}"),
                    "the entry maps the name to itself and is skipped, so the name is resolved by DNS",
                );
                continue;
            }
            let cycle =
                || ConfigError::new(format!("{domain}, there is a cycle in domain name mapping"));
            let mut hops = 0;
            let mut current = config.lookup(target);
            while let Some(entry) = current {
                let HostValue::Domain(next) = &entry.value else {
                    break;
                };
                if next.eq_ignore_ascii_case(domain) {
                    return Err(cycle());
                }
                hops += 1;
                if hops > 1024 {
                    break;
                }
                current = config.lookup(next);
            }
        }
        config.entries.retain(|entry| entry.domain != *domain);
        config.entries.push(HostEntry {
            domain: domain.clone(),
            value: parsed,
        });
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(value: serde_json::Value) -> Result<HostsConfig> {
        let serde_json::Value::Object(map) = value else {
            return Err(ConfigError::new("not a map"));
        };
        parse_hosts(&map, &mut LoadReport::default())
    }

    #[test]
    fn ips_lists_and_domain_aliases() {
        let hosts = parse(json!({
            "a.example": "1.2.3.4",
            "b.example": ["1.2.3.4", "::1"],
            "c.example": "a.example",
            "+.wild.example": "9.9.9.9"
        }))
        .unwrap();
        assert_eq!(hosts.entries.len(), 5);
        assert!(matches!(&hosts.entries[3].value, HostValue::Domain(d) if d == "a.example"));
        assert!(hosts.lookup("x.y.wild.example").is_some());
        assert!(hosts.lookup("localhost").is_some());
    }

    #[test]
    fn a_name_mapped_to_itself_is_skipped_with_a_warning() {
        let map: Map =
            serde_json::from_value(json!({"a.example": "A.example", "b.example": "a.example"}))
                .unwrap();
        let mut report = LoadReport::default();
        let hosts = parse_hosts(&map, &mut report).unwrap();
        assert!(hosts.lookup("a.example").is_none());
        assert!(
            matches!(&hosts.lookup("b.example").unwrap().value, HostValue::Domain(d) if d == "a.example")
        );
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, "invalid_host");
        assert_eq!(report.warnings[0].path, "hosts.a.example");
    }

    #[test]
    fn domain_cycles_are_rejected() {
        let err = parse(
            json!({"a.example": "b.example", "b.example": "c.example", "c.example": "a.example"}),
        )
        .unwrap_err();
        assert!(
            err.message.contains("cycle in domain name mapping"),
            "{err}"
        );
        assert!(parse(json!({"a.example": "b.example", "b.example": "9.9.9.9"})).is_ok());
    }

    #[test]
    fn lan_stands_for_the_hosts_own_addresses() {
        let hosts = parse(json!({"router.lan": "lan"})).unwrap();
        assert_eq!(hosts.lookup("router.lan").unwrap().value, HostValue::Lan);
    }
}
