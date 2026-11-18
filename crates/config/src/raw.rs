use indexmap::IndexMap;
use serde_json::Value;

use crate::Map;
use crate::crypt;
use crate::error::{ConfigError, Result};
use crate::general::General;
use crate::keys::{self, Tier, Tiers};
use crate::lenient::scalar_text;
use crate::report::LoadReport;
use crate::rule::RuleLines;
use crate::yaml::{self, ParsedDocument, SourceLines};

#[derive(Clone, Debug)]
pub struct RawConfig {
    pub general: Map,
    pub proxies: Vec<Map>,
    pub proxy_groups: Vec<Map>,
    pub proxy_providers: IndexMap<String, Map>,
    pub rule_providers: IndexMap<String, Map>,
    pub rules: RuleLines,
    pub sub_rules: IndexMap<String, Vec<String>>,
    pub hosts: Map,
    pub dns: Map,
    pub tun: Map,
    pub sniffer: Map,
    pub ntp: Map,
    pub geox_url: Map,
    pub profile: Map,
    pub experimental: Map,
    pub tls: Map,
    pub mitm: Map,
    pub extra: Map,
    pub lines: SourceLines,
    pub report: LoadReport,
}

impl Default for RawConfig {
    fn default() -> Self {
        RawConfig::from_document(ParsedDocument::default()).unwrap_or_else(|_| RawConfig::bare())
    }
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "sequence",
        Value::Object(_) => "map",
    }
}

fn expect_map(value: Value, what: &str) -> Result<Map> {
    match value {
        Value::Null => Ok(Map::new()),
        Value::Object(map) => Ok(map),
        other => Err(ConfigError::new(format!(
            "yaml: unmarshal errors: cannot unmarshal {} into {what}",
            kind_of(&other)
        ))),
    }
}

fn expect_maps(value: Value, what: &str, lines: &[u32]) -> Result<Vec<Map>> {
    let items = match value {
        Value::Null => return Ok(Vec::new()),
        Value::Array(items) => items,
        other => {
            return Err(ConfigError::new(format!(
                "yaml: unmarshal errors: cannot unmarshal {} into []map[string]interface {{}} ({what})",
                kind_of(&other)
            )));
        }
    };
    items
        .into_iter()
        .enumerate()
        .map(|(index, item)| match item {
            Value::Object(map) => Ok(map),
            other => {
                let line = lines.get(index).copied();
                Err(ConfigError::new(format!(
                    "yaml: unmarshal errors: {what}[{index}]: cannot unmarshal {} into map[string]interface {{}}",
                    kind_of(&other)
                ))
                .with_line(line))
            }
        })
        .collect()
}

pub(crate) fn expect_strings(value: Value, what: &str) -> Result<Vec<String>> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .into_iter()
            .map(|item| {
                scalar_text(&item).ok_or_else(|| {
                    ConfigError::new(format!(
                        "yaml: unmarshal errors: cannot unmarshal {} into string ({what})",
                        kind_of(&item)
                    ))
                })
            })
            .collect(),
        other => Err(ConfigError::new(format!(
            "yaml: unmarshal errors: cannot unmarshal {} into []string ({what})",
            kind_of(&other)
        ))),
    }
}

fn expect_named_maps(value: Value, what: &str) -> Result<IndexMap<String, Map>> {
    let map = expect_map(value, what)?;
    map.into_iter()
        .map(|(name, item)| {
            expect_map(item, what)
                .map(|inner| (name.clone(), inner))
                .map_err(|err| err.prefixed(&format!("{what}[{name}]: ")))
        })
        .collect()
}

/// The app writes every key it knows, so an unsupported key left empty asks for nothing.
pub(crate) fn asks_for_something(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn section_user_keys(report: &mut LoadReport, name: &str, user: &Map, tiers: &Tiers) {
    for (key, value) in user {
        match tiers.of(key) {
            Some(Tier::T2) if !asks_for_something(value) => {}
            Some(Tier::T2) => report.warn(
                "unsupported_key",
                format!("{name}.{key}"),
                unsupported_message(name, key),
            ),
            None => report.warn("unknown_key", format!("{name}.{key}"), "unknown key"),
            _ => {}
        }
    }
}

fn unsupported_message(section: &str, key: &str) -> &'static str {
    match key {
        "global-client-fingerprint" if section.is_empty() => {
            "key was removed and is ignored; set client-fingerprint on each node instead"
        }
        _ if section != "tun" || !keys::TUN_SCOPE.contains(&key) => {
            "key is not supported by this core and is ignored"
        }
        "include-package" | "exclude-package" | "include-android-user" => {
            "key is not supported by this core and is ignored, so the TUN captures other apps than the profile says; an app that embeds the core picks the apps itself"
        }
        _ => {
            "key is not supported by this core and is ignored, so the TUN captures other traffic than the profile says"
        }
    }
}

impl RawConfig {
    fn bare() -> RawConfig {
        RawConfig {
            general: keys::general_defaults(),
            proxies: Vec::new(),
            proxy_groups: Vec::new(),
            proxy_providers: IndexMap::new(),
            rule_providers: IndexMap::new(),
            rules: RuleLines::default(),
            sub_rules: IndexMap::new(),
            hosts: Map::new(),
            dns: keys::dns_defaults(),
            tun: keys::tun_defaults(),
            sniffer: keys::sniffer_defaults(),
            ntp: keys::ntp_defaults(),
            geox_url: keys::geox_defaults(),
            profile: keys::profile_defaults(),
            experimental: keys::experimental_defaults(),
            tls: keys::tls_defaults(),
            mitm: keys::mitm_defaults(),
            extra: Map::new(),
            lines: SourceLines::default(),
            report: LoadReport::default(),
        }
    }

    pub fn from_document(doc: ParsedDocument) -> Result<RawConfig> {
        let mut raw = RawConfig::bare();
        let mut scalars = Map::new();
        raw.lines = doc.lines;
        raw.rules = doc.rules.unwrap_or_default();
        for (key, value) in doc.root {
            match key.as_str() {
                "proxies" => raw.proxies = expect_maps(value, "proxies", &raw.lines.proxies)?,
                "proxy-groups" => {
                    raw.proxy_groups = expect_maps(value, "proxy-groups", &raw.lines.proxy_groups)?;
                }
                "proxy-providers" => {
                    raw.proxy_providers = expect_named_maps(value, "proxy-providers")?
                }
                "rule-providers" => {
                    raw.rule_providers = expect_named_maps(value, "rule-providers")?
                }
                "rules" => {
                    raw.rules = expect_strings(value, "rules")?
                        .iter()
                        .map(String::as_str)
                        .collect();
                }
                "sub-rules" => {
                    let map = expect_map(value, "sub-rules")?;
                    for (name, rules) in map {
                        raw.sub_rules.insert(
                            name.clone(),
                            expect_strings(rules, &format!("sub-rules[{name}]"))?,
                        );
                    }
                }
                "hosts" => raw.hosts = expect_map(value, "hosts")?,
                "dns" => raw.dns = raw.section("dns", value, keys::dns_defaults(), &keys::DNS)?,
                "tun" => {
                    raw.tun = raw.section("tun", value, keys::tun_defaults(), &keys::TUN)?;
                }
                "sniffer" => {
                    raw.sniffer =
                        raw.section("sniffer", value, keys::sniffer_defaults(), &keys::SNIFFER)?;
                    stringify_sniff_ports(&mut raw.sniffer);
                }
                "ntp" => raw.ntp = raw.section("ntp", value, keys::ntp_defaults(), &keys::NTP)?,
                "geox-url" => {
                    raw.geox_url =
                        raw.section("geox-url", value, keys::geox_defaults(), &keys::GEOX)?;
                }
                "profile" => {
                    raw.profile =
                        raw.section("profile", value, keys::profile_defaults(), &keys::PROFILE)?;
                }
                "experimental" => {
                    let user = expect_map(value, "experimental")?;
                    raw.experimental = keys::overlay(&keys::experimental_defaults(), user);
                }
                "tls" => {
                    let user = expect_map(value, "tls")?;
                    raw.tls = keys::overlay(&keys::tls_defaults(), user);
                }
                "mitm" => {
                    let user = expect_map(value, "mitm")?;
                    raw.mitm = keys::overlay(&keys::mitm_defaults(), user);
                }
                other => match keys::TOP.of(other) {
                    Some(Tier::T0 | Tier::T1 | Tier::Inert) => {
                        scalars.insert(key, value);
                    }
                    Some(Tier::T2) => {
                        let geodata_off = other == "geodata-mode" && value == Value::Bool(false);
                        if asks_for_something(&value) && !geodata_off {
                            raw.report.warn(
                                "unsupported_key",
                                other,
                                unsupported_message("", other),
                            );
                        }
                        raw.extra.insert(key, value);
                    }
                    // Kept, it would return in the overlay as a plain map that no longer reads as a template.
                    None if doc.anchored.contains(other) => {}
                    None => {
                        raw.report.warn("unknown_key", other, "unknown key");
                        raw.extra.insert(key, value);
                    }
                },
            }
        }
        raw.general = keys::overlay(&keys::general_defaults(), scalars);
        General::from_map(&raw.general).map_err(|err| err.prefixed("yaml: unmarshal errors: "))?;
        Ok(raw)
    }

    fn section(&mut self, name: &str, value: Value, defaults: Map, tiers: &Tiers) -> Result<Map> {
        let user = expect_map(value, name)?;
        section_user_keys(&mut self.report, name, &user, tiers);
        if name == "dns"
            && let Some(Value::Object(filter)) = user.get("fallback-filter")
        {
            section_user_keys(
                &mut self.report,
                "dns.fallback-filter",
                filter,
                &keys::FALLBACK_FILTER_TIERS,
            );
        }
        Ok(keys::overlay(&defaults, user))
    }

    fn json_with(&self, heavy: bool) -> Value {
        let mut out = self.general.clone();
        out.insert("proxy-providers".into(), named_json(&self.proxy_providers));
        out.insert("rule-providers".into(), named_json(&self.rule_providers));
        out.insert(
            "sub-rules".into(),
            if self.sub_rules.is_empty() {
                Value::Null
            } else {
                Value::Object(
                    self.sub_rules
                        .iter()
                        .map(|(name, rules)| {
                            (
                                name.clone(),
                                Value::Array(rules.iter().cloned().map(Value::String).collect()),
                            )
                        })
                        .collect(),
                )
            },
        );
        if heavy {
            out.insert(
                "proxies".into(),
                Value::Array(self.proxies.iter().cloned().map(Value::Object).collect()),
            );
            out.insert(
                "proxy-groups".into(),
                Value::Array(
                    self.proxy_groups
                        .iter()
                        .cloned()
                        .map(Value::Object)
                        .collect(),
                ),
            );
            out.insert(
                "rule".into(),
                Value::Array(
                    self.rules
                        .iter()
                        .map(|rule| Value::String(rule.to_string()))
                        .collect(),
                ),
            );
        } else {
            for key in ["proxies", "proxy-groups", "rule", "sub-rules"] {
                out.insert(key.into(), Value::Null);
            }
        }
        out.insert("hosts".into(), Value::Object(self.hosts.clone()));
        for (name, section) in [
            ("dns", &self.dns),
            ("tun", &self.tun),
            ("sniffer", &self.sniffer),
            ("ntp", &self.ntp),
            ("geox-url", &self.geox_url),
            ("profile", &self.profile),
            ("experimental", &self.experimental),
            ("tls", &self.tls),
            ("mitm", &self.mitm),
        ] {
            out.insert(name.into(), Value::Object(section.clone()));
        }
        for (key, value) in &self.extra {
            out.insert(key.clone(), value.clone());
        }
        Value::Object(out)
    }

    pub fn to_json(&self) -> Value {
        self.json_with(true)
    }

    pub fn to_json_light(&self) -> Value {
        self.json_with(false)
    }

    pub fn to_yaml(&self) -> String {
        raw_to_yaml(self)
    }
}

fn named_json(items: &IndexMap<String, Map>) -> Value {
    if items.is_empty() {
        return Value::Null;
    }
    Value::Object(
        items
            .iter()
            .map(|(name, item)| (name.clone(), Value::Object(item.clone())))
            .collect(),
    )
}

pub fn raw_to_yaml(raw: &RawConfig) -> String {
    let mut out = String::new();
    for (key, value) in &raw.general {
        if matches!(
            key.as_str(),
            "proxy-providers" | "rule-providers" | "sub-rules"
        ) {
            continue;
        }
        yaml::write_entry(&mut out, key, value);
    }
    for (key, items) in [
        ("proxy-providers", &raw.proxy_providers),
        ("rule-providers", &raw.rule_providers),
    ] {
        if !items.is_empty() {
            yaml::write_entry(&mut out, key, &named_json(items));
        }
    }
    if !raw.sub_rules.is_empty() {
        let map: Map = raw
            .sub_rules
            .iter()
            .map(|(name, rules)| {
                (
                    name.clone(),
                    Value::Array(rules.iter().cloned().map(Value::String).collect()),
                )
            })
            .collect();
        yaml::write_entry(&mut out, "sub-rules", &Value::Object(map));
    }
    yaml::write_entry(&mut out, "hosts", &Value::Object(raw.hosts.clone()));
    for (name, section) in [
        ("dns", &raw.dns),
        ("tun", &raw.tun),
        ("sniffer", &raw.sniffer),
        ("ntp", &raw.ntp),
        ("geox-url", &raw.geox_url),
        ("profile", &raw.profile),
        ("experimental", &raw.experimental),
        ("tls", &raw.tls),
        ("mitm", &raw.mitm),
    ] {
        yaml::write_entry(&mut out, name, &Value::Object(section.clone()));
    }
    for (key, value) in &raw.extra {
        yaml::write_entry(&mut out, key, value);
    }
    yaml::write_map_list(&mut out, "proxies", &raw.proxies);
    yaml::write_map_list(&mut out, "proxy-groups", &raw.proxy_groups);
    yaml::write_rules(&mut out, "rules", &raw.rules);
    out
}

/// `RawSniffingConfig.Ports` is a string list, so a number in the file reads back as text.
fn stringify_sniff_ports(sniffer: &mut Map) {
    let Some(Value::Object(protocols)) = sniffer.get_mut("sniff") else {
        return;
    };
    for protocol in protocols.values_mut() {
        if let Some(Value::Array(ports)) = protocol.get_mut("ports") {
            for port in ports.iter_mut() {
                if let Value::Number(number) = port {
                    *port = Value::String(number.to_string());
                }
            }
        }
    }
}

pub fn parse_raw_str(text: &str) -> Result<RawConfig> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    RawConfig::from_document(yaml::parse_document(text)?)
}

pub fn parse_raw_with_key(bytes: &[u8], age_secret_key: Option<&str>) -> Result<RawConfig> {
    let keys: Vec<&str> = age_secret_key.into_iter().collect();
    let plain = crypt::decrypt_config(bytes, &keys)?;
    let text = std::str::from_utf8(&plain)
        .map_err(|_| ConfigError::new("yaml: invalid leading UTF-8 octet"))?;
    parse_raw_str(text)
}

pub fn parse_raw(bytes: &[u8]) -> Result<RawConfig> {
    parse_raw_with_key(bytes, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_default_raw_config() {
        let json = RawConfig::default().to_json();
        let get = |path: &str| {
            path.split('.')
                .try_fold(&json, |value, key| value.get(key))
                .cloned()
                .unwrap_or(Value::Null)
        };
        assert_eq!(get("mode"), "rule");
        assert_eq!(get("log-level"), "info");
        assert_eq!(get("ipv6"), true);
        assert_eq!(get("find-process-mode"), "strict");
        assert_eq!(get("geo-update-interval"), 24);
        assert_eq!(get("geodata-loader"), "memconservative");
        assert_eq!(get("authentication"), serde_json::json!([]));
        assert_eq!(get("skip-auth-prefixes"), Value::Null);
        assert_eq!(get("dns.enhanced-mode"), "redir-host");
        assert_eq!(get("dns.fake-ip-range"), "198.18.0.1/16");
        assert_eq!(get("dns.fake-ip-ttl"), 1);
        assert_eq!(get("dns.ipv6-timeout"), 100);
        assert_eq!(get("dns.use-hosts"), true);
        assert_eq!(get("dns.fake-ip-filter-mode"), "blacklist");
        assert_eq!(get("dns.fallback-filter.geoip"), false);
        assert_eq!(get("dns.fallback-filter.geoip-code"), "");
        assert_eq!(
            get("dns.default-nameserver"),
            serde_json::json!(["114.114.114.114", "223.5.5.5", "8.8.8.8", "1.0.0.1"])
        );
        assert_eq!(
            get("dns.nameserver"),
            serde_json::json!(["https://doh.pub/dns-query", "tls://223.5.5.5:853"])
        );
        assert_eq!(get("tun.stack"), "Mips");
        assert_eq!(get("tun.dns-hijack"), serde_json::json!(["0.0.0.0:53"]));
        assert_eq!(get("tun.auto-route"), true);
        assert_eq!(get("ntp.server"), "time.apple.com");
        assert_eq!(get("ntp.port"), 123);
        assert_eq!(get("ntp.interval"), 30);
        assert_eq!(get("sniffer.force-dns-mapping"), true);
        assert_eq!(get("sniffer.parse-pure-ip"), true);
        assert_eq!(get("sniffer.override-destination"), true);
        assert_eq!(get("profile.store-selected"), true);
        assert_eq!(
            get("geox-url.mmdb"),
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"
        );
        assert_eq!(get("experimental.quic-go-disable-ecn"), true);
        assert_eq!(get("hosts"), serde_json::json!({}));
        assert_eq!(get("rule"), serde_json::json!([]));
        assert_eq!(get("proxies"), serde_json::json!([]));
        assert_eq!(get("proxy-groups"), serde_json::json!([]));
        assert!(json.get("rules").is_none());
    }

    #[test]
    fn user_values_override_defaults_key_by_key() {
        let raw = parse_raw(b"dns:\n  enable: true\n  fallback-filter:\n    geoip-code: US\nmixed-port: 7890\nmode: Global\n").unwrap();
        let json = raw.to_json();
        assert_eq!(json["dns"]["enable"], true);
        assert_eq!(json["dns"]["fallback-filter"]["geoip-code"], "US");
        assert_eq!(json["dns"]["fallback-filter"]["geoip"], false);
        assert_eq!(json["dns"]["use-hosts"], true);
        assert_eq!(json["mixed-port"], 7890);
        assert_eq!(json["mode"], "Global");
    }

    #[test]
    fn an_unsupported_key_left_empty_is_not_worth_a_warning() {
        let raw = parse_raw_str(
            "external-ui: \"\"\nexternal-controller-tls: \"\"\ntun:\n  dns-mode: \"\"\nsniffer:\n  sniffing: null\n  port-whitelist: []\n",
        )
        .unwrap();
        assert!(raw.report.warnings.is_empty());
        let raw = parse_raw_str("external-ui: ui\ntun:\n  dns-mode: fake\n").unwrap();
        assert_eq!(raw.report.warnings.len(), 2);
    }

    #[test]
    fn the_removed_global_fingerprint_points_at_the_nodes() {
        let raw = parse_raw_str("global-client-fingerprint: chrome\n").unwrap();
        let warning = &raw.report.warnings[0];
        assert_eq!(warning.code, "unsupported_key");
        assert_eq!(
            warning.message,
            "key was removed and is ignored; set client-fingerprint on each node instead"
        );
    }

    #[test]
    fn a_tun_key_that_changes_what_is_captured_says_so() {
        let raw = parse_raw_str(
            "iptables: {enable: true}\ntun:\n  include-package: [a.b]\n  exclude-uid-range: ['1:2']\n  dns-mode: fake\n",
        )
        .unwrap();
        let warned: Vec<(&str, &str, &str)> = raw
            .report
            .warnings
            .iter()
            .map(|w| (w.code, w.path.as_str(), w.message.as_str()))
            .collect();
        let plain = "key is not supported by this core and is ignored";
        assert_eq!(
            warned,
            [
                ("unsupported_key", "iptables", plain),
                (
                    "unsupported_key",
                    "tun.include-package",
                    "key is not supported by this core and is ignored, so the TUN captures other apps than the profile says; an app that embeds the core picks the apps itself"
                ),
                (
                    "unsupported_key",
                    "tun.exclude-uid-range",
                    "key is not supported by this core and is ignored, so the TUN captures other traffic than the profile says"
                ),
                ("unsupported_key", "tun.dns-mode", plain),
            ]
        );
    }

    #[test]
    fn unknown_and_t2_keys_are_kept_and_reported() {
        let raw = parse_raw(b"listeners:\n  - {name: a, type: mixed, port: 1}\nfoo: bar\ntun:\n  enable: true\n  gso-max-size: 4\n").unwrap();
        let json = raw.to_json();
        assert_eq!(json["foo"], "bar");
        assert_eq!(json["listeners"][0]["name"], "a");
        assert_eq!(json["tun"]["gso-max-size"], 4);
        let paths: Vec<&str> = raw
            .report
            .warnings
            .iter()
            .map(|w| w.path.as_str())
            .collect();
        assert!(paths.contains(&"listeners"));
        assert!(paths.contains(&"foo"));
        assert!(paths.contains(&"tun.gso-max-size"));
    }

    #[test]
    fn anchored_template_keys_are_neither_reported_nor_kept() {
        let raw = parse_raw_str(
            "p: &p {type: http, interval: 3600}\nname: &n plain\nproxy-providers:\n  a: {<<: *p, url: 'https://x'}\nfoo: bar\n",
        )
        .unwrap();
        let json = raw.to_json();
        assert_eq!(json["proxy-providers"]["a"]["interval"], 3600);
        assert!(json.get("p").is_none());
        assert!(json.get("name").is_none());
        let paths: Vec<&str> = raw
            .report
            .warnings
            .iter()
            .map(|w| w.path.as_str())
            .collect();
        assert_eq!(paths, ["foo"]);
    }

    #[test]
    fn the_rules_key_reads_back_as_rule() {
        let raw = parse_raw(b"rules:\n  - MATCH,DIRECT\n").unwrap();
        assert_eq!(raw.to_json()["rule"], serde_json::json!(["MATCH,DIRECT"]));
    }

    #[test]
    fn yaml_output_parses_back_to_the_same_config() {
        let raw = parse_raw(
            b"mixed-port: 7890\nproxies:\n  - {name: a, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: '0123'}\nproxy-groups:\n  - {name: g, type: select, proxies: [a]}\nrules:\n  - DOMAIN,a.com,g\n  - MATCH,DIRECT\nfoo: [1, 2]\n",
        )
        .unwrap();
        let again = parse_raw(raw_to_yaml(&raw).as_bytes()).unwrap();
        assert_eq!(raw.to_json(), again.to_json());
    }

    #[test]
    fn type_errors_in_scalars_are_hard_errors() {
        assert!(parse_raw(b"mixed-port: abc\n").is_err());
        assert!(parse_raw(b"proxies: nope\n").is_err());
        assert!(parse_raw(b"proxies:\n  - 1\n").is_err());
        assert!(parse_raw(b"mode: sideways\n").is_err());
    }
}
