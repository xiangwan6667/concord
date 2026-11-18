use crate::Map;
use crate::error::{ConfigError, Result};
use crate::lenient::{Fields, to_bool, value_to_strings};
use crate::net::{IpCidr, PortRange, parse_port_ranges};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SniffProtocol {
    Http,
    Tls,
    Quic,
}

impl SniffProtocol {
    fn parse(name: &str) -> Option<SniffProtocol> {
        match name.to_ascii_uppercase().as_str() {
            "HTTP" => Some(SniffProtocol::Http),
            "TLS" => Some(SniffProtocol::Tls),
            "QUIC" => Some(SniffProtocol::Quic),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SniffEntry {
    pub protocol: SniffProtocol,
    pub ports: Vec<PortRange>,
    pub override_destination: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnifferConfig {
    pub enable: bool,
    pub override_destination: bool,
    pub sniff: Vec<SniffEntry>,
    pub force_domain: Vec<String>,
    pub skip_domain: Vec<String>,
    pub force_dns_mapping: bool,
    pub parse_pure_ip: bool,
    pub skip_src_address: SniffIps,
    pub skip_dst_address: SniffIps,
}

/// `skip-src-address` / `skip-dst-address`: plain CIDRs and IPs, plus the names
/// of `geoip:` country codes and `rule-set:` providers to resolve at apply time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SniffIps {
    pub cidrs: Vec<IpCidr>,
    pub geoip: Vec<String>,
    pub rule_sets: Vec<String>,
}

impl SniffIps {
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.geoip.is_empty() && self.rule_sets.is_empty()
    }
}

fn ip_entries(values: Vec<String>, what: &str) -> Result<SniffIps> {
    let mut out = SniffIps::default();
    for text in values {
        let lower = text.to_ascii_lowercase();
        let names = || {
            text.split(':')
                .nth(1)
                .unwrap_or_default()
                .split(',')
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        if lower.starts_with("geoip:") {
            out.geoip.extend(names());
        } else if lower.starts_with("rule-set:") {
            out.rule_sets.extend(names());
        } else {
            let cidr = crate::net::parse_cidr(&text)
                .or_else(|_| {
                    text.parse::<std::net::IpAddr>()
                        .map(|addr| IpCidr {
                            addr,
                            prefix: if addr.is_ipv4() { 32 } else { 128 },
                        })
                        .map_err(|_| ConfigError::new(format!("invalid CIDR {text}")))
                })
                .map_err(|err| {
                    ConfigError::new(format!("error in {what}, error:{}", err.message))
                })?;
            out.cidrs.push(cidr);
        }
    }
    Ok(out)
}

impl SnifferConfig {
    pub fn from_map(map: &Map) -> Result<SnifferConfig> {
        let mut f = Fields::new(map, "sniffer", false);
        let mut out = SnifferConfig {
            enable: f.boolean("enable")?,
            override_destination: f.boolean("override-destination")?,
            force_dns_mapping: f.boolean("force-dns-mapping")?,
            parse_pure_ip: f.boolean("parse-pure-ip")?,
            force_domain: f.strings("force-domain")?,
            skip_domain: f.strings("skip-domain")?,
            ..SnifferConfig::default()
        };
        out.skip_src_address = ip_entries(f.strings("skip-src-address")?, "skip-src-address")?;
        out.skip_dst_address = ip_entries(f.strings("skip-dst-address")?, "skip-dst-address")?;
        if let Some(sniff) = f.object("sniff")? {
            for (name, value) in sniff {
                let protocol = SniffProtocol::parse(name)
                    .ok_or_else(|| ConfigError::new(format!("not find the sniffer[{name}]")))?;
                let mut ports = Vec::new();
                let mut override_destination = out.override_destination;
                if let serde_json::Value::Object(entry) = value {
                    if let Some(list) = entry.get("ports") {
                        for text in value_to_strings(list) {
                            ports.extend(parse_port_ranges(&text).map_err(|err| {
                                err.prefixed(&format!("sniffer.sniff.{name}.ports: "))
                            })?);
                        }
                    }
                    if let Some(flag) = entry.get("override-destination").and_then(to_bool) {
                        override_destination = flag;
                    }
                }
                out.sniff.push(SniffEntry {
                    protocol,
                    ports,
                    override_destination,
                });
            }
        }
        if out.sniff.is_empty() {
            let ports = parse_port_ranges_list(f.strings("port-whitelist")?)?;
            for name in f.strings("sniffing")? {
                let protocol = SniffProtocol::parse(&name)
                    .ok_or_else(|| ConfigError::new(format!("not find the sniffer[{name}]")))?;
                out.sniff.retain(|entry| entry.protocol != protocol);
                out.sniff.push(SniffEntry {
                    protocol,
                    ports: ports.clone(),
                    override_destination: out.override_destination,
                });
            }
        }
        Ok(out)
    }
}

fn parse_port_ranges_list(values: Vec<String>) -> Result<Vec<PortRange>> {
    let mut ports = Vec::new();
    for text in values {
        ports.extend(parse_port_ranges(&text)?);
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::sniffer_defaults;
    use serde_json::json;

    #[test]
    fn sniff_entries_inherit_the_global_override() {
        let mut map = sniffer_defaults();
        map.insert("enable".into(), json!(true));
        map.insert("override-destination".into(), json!(false));
        map.insert(
            "sniff".into(),
            json!({"TLS": {"ports": [443, "8443-8444"]}, "http": {"ports": ["80"], "override-destination": true}}),
        );
        let config = SnifferConfig::from_map(&map).unwrap();
        assert_eq!(config.sniff.len(), 2);
        assert_eq!(config.sniff[0].protocol, SniffProtocol::Tls);
        assert_eq!(config.sniff[0].ports.len(), 2);
        assert!(!config.sniff[0].override_destination);
        assert!(config.sniff[1].override_destination);
    }

    #[test]
    fn unknown_protocols_and_bad_ports_fail() {
        let mut map = sniffer_defaults();
        map.insert("sniff".into(), json!({"SSH": {"ports": [22]}}));
        assert!(SnifferConfig::from_map(&map).is_err());
        map.insert("sniff".into(), json!({"TLS": {"ports": ["x"]}}));
        assert!(SnifferConfig::from_map(&map).is_err());
    }

    #[test]
    fn deprecated_sniffing_list_takes_the_global_ports_and_override() {
        let mut map = sniffer_defaults();
        map.insert("sniffing".into(), json!(["tls", "HTTP"]));
        map.insert("port-whitelist".into(), json!([80, "443"]));
        map.insert("override-destination".into(), json!(false));
        let config = SnifferConfig::from_map(&map).unwrap();
        assert_eq!(config.sniff.len(), 2);
        assert_eq!(config.sniff[0].protocol, SniffProtocol::Tls);
        assert_eq!(config.sniff[1].protocol, SniffProtocol::Http);
        assert!(
            config
                .sniff
                .iter()
                .all(|e| e.ports.len() == 2 && !e.override_destination)
        );

        map.insert("sniff".into(), json!({"QUIC": {"ports": [443]}}));
        let config = SnifferConfig::from_map(&map).unwrap();
        assert_eq!(config.sniff.len(), 1);
        assert_eq!(config.sniff[0].protocol, SniffProtocol::Quic);

        let mut map = sniffer_defaults();
        map.insert("sniffing".into(), json!(["ssh"]));
        assert!(SnifferConfig::from_map(&map).is_err());
    }

    #[test]
    fn skip_addresses_keep_geoip_and_rule_set_names() {
        let mut map = sniffer_defaults();
        map.insert(
            "skip-dst-address".into(),
            json!(["geoip:CN,lan", "RULE-SET:a,b", "10.0.0.0/8", "1.2.3.4"]),
        );
        let config = SnifferConfig::from_map(&map).unwrap();
        let dst = &config.skip_dst_address;
        assert_eq!(dst.geoip, ["CN", "lan"]);
        assert_eq!(dst.rule_sets, ["a", "b"]);
        assert_eq!(dst.cidrs.len(), 2);
        assert!(config.skip_src_address.is_empty());
    }
}
