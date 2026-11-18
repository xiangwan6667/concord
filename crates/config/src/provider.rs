use indexmap::IndexMap;
use serde_json::Value;

use crate::Map;
use crate::crypt;
use crate::error::{ConfigError, Result};
use crate::filter::{self, CompiledFilter};
use crate::lenient::{Fields, scalar_text};
use crate::net::parse_unsigned_ranges;
use crate::report::LoadReport;
use crate::{share_link, yaml};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpSource {
    pub url: String,
    pub path: String,
    pub proxy: String,
    pub header: IndexMap<String, Vec<String>>,
    pub size_limit: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxySource {
    File { path: String },
    Http(HttpSource),
    Inline { payload: Vec<Map> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthCheckDef {
    pub enable: bool,
    pub url: String,
    pub interval: u32,
    pub timeout: u32,
    pub lazy: bool,
    pub expected_status: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameRewrite {
    pub pattern: String,
    pub target: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OverrideDef {
    pub expr: bool,
    pub tfo: Option<bool>,
    pub mptcp: Option<bool>,
    pub udp: Option<bool>,
    pub udp_over_tcp: Option<bool>,
    pub up: Option<String>,
    pub down: Option<String>,
    pub dialer_proxy: Option<String>,
    pub skip_cert_verify: Option<bool>,
    pub name_cert_verify: Option<String>,
    pub interface_name: Option<String>,
    pub routing_mark: Option<u32>,
    pub ip_version: Option<String>,
    pub additional_prefix: Option<String>,
    pub additional_suffix: Option<String>,
    pub proxy_name: Vec<NameRewrite>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyProviderDef {
    pub name: String,
    pub source: ProxySource,
    pub interval: u32,
    pub filter: String,
    pub exclude_filter: String,
    pub exclude_type: String,
    pub dialer_proxy: String,
    pub age_secret_key: String,
    pub health_check: HealthCheckDef,
    pub override_: OverrideDef,
    /// `payload` of a file or http provider: its nodes until a load succeeds.
    pub fallback: Vec<Map>,
    pub raw: Map,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleBehavior {
    Domain,
    IpCidr,
    Classical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleFormat {
    Yaml,
    Text,
    Mrs,
    /// Surge's DOMAIN-SET, text in which `.example.com` covers `example.com` too; Concord's own.
    DomainSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleSource {
    File { path: String },
    Http(HttpSource),
    Inline { payload: Vec<String> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleProviderDef {
    pub name: String,
    pub source: RuleSource,
    pub behavior: RuleBehavior,
    pub format: RuleFormat,
    pub interval: u32,
    /// `payload` of a file or http provider: its rules until a load succeeds.
    pub fallback: Vec<String>,
    /// Where mihomo finds the provider in `BundleMRS.7z` when its local file is missing; never read.
    pub path_in_bundle: String,
    pub raw: Map,
}

fn http_source(f: &mut Fields<'_>) -> Result<HttpSource> {
    Ok(HttpSource {
        url: f.string("url")?,
        path: f.string("path")?,
        proxy: f.string("proxy")?,
        header: f.list_map("header")?,
        size_limit: f.i64("size-limit")?,
    })
}

fn opt_override(f: &mut Fields<'_>, key: &str) -> Result<Option<String>> {
    f.opt_string(key)
}

fn parse_override(f: &mut Fields<'_>) -> Result<OverrideDef> {
    let Some(mut o) = f.sub("override")? else {
        return Ok(OverrideDef::default());
    };
    let mut def = OverrideDef {
        expr: o.has("override-expr"),
        tfo: o.opt_bool("tfo")?,
        mptcp: o.opt_bool("mptcp")?,
        udp: o.opt_bool("udp")?,
        udp_over_tcp: o.opt_bool("udp-over-tcp")?,
        up: opt_override(&mut o, "up")?,
        down: opt_override(&mut o, "down")?,
        dialer_proxy: opt_override(&mut o, "dialer-proxy")?,
        skip_cert_verify: o.opt_bool("skip-cert-verify")?,
        name_cert_verify: opt_override(&mut o, "name-cert-verify")?,
        interface_name: opt_override(&mut o, "interface-name")?,
        routing_mark: if o.has("routing-mark") {
            Some(o.mark("routing-mark")?)
        } else {
            None
        },
        ip_version: opt_override(&mut o, "ip-version")?,
        additional_prefix: opt_override(&mut o, "additional-prefix")?,
        additional_suffix: opt_override(&mut o, "additional-suffix")?,
        proxy_name: Vec::new(),
    };
    let rewrites = match o.raw("proxy-name") {
        Some(Value::Array(items)) => items.as_slice(),
        None | Some(Value::Null) => &[],
        Some(_) => return Err(ConfigError::new("'override.proxy-name' is not a slice")),
    };
    for item in rewrites {
        let Value::Object(entry) = item else {
            return Err(ConfigError::new("override.proxy-name entries must be maps"));
        };
        let mut e = Fields::new(entry, "override.proxy-name", false);
        let pattern = e.req_string("pattern")?;
        let target = e.req_string("target")?;
        e.finish()?;
        filter::compile_pattern(&pattern, false)?;
        def.proxy_name.push(NameRewrite { pattern, target });
    }
    Ok(def)
}

pub fn parse_proxy_provider(name: &str, map: &Map) -> Result<ProxyProviderDef> {
    let mut f = Fields::new(map, "", false);
    f.require("type");
    let type_name = f.string("type")?;
    let health_check = match f.sub("health-check")? {
        Some(mut h) => {
            let enable = h.boolean("enable")?;
            let mut check = HealthCheckDef {
                enable,
                url: h.string("url")?,
                interval: h.u32("interval")?,
                timeout: h.u32("timeout")?,
                lazy: h.opt_bool("lazy")?.unwrap_or(true),
                expected_status: h.string("expected-status")?,
            };
            if enable && check.interval == 0 {
                check.interval = 300;
            }
            check
        }
        None => HealthCheckDef {
            enable: false,
            url: String::new(),
            interval: 0,
            timeout: 0,
            lazy: true,
            expected_status: String::new(),
        },
    };
    parse_unsigned_ranges(&health_check.expected_status, u64::from(u16::MAX))?;
    let interval = f.u32("interval")?;
    let filter_text = f.string("filter")?;
    let exclude_filter = f.string("exclude-filter")?;
    let exclude_type = f.string("exclude-type")?;
    let dialer_proxy = f.string("dialer-proxy")?;
    let age_secret_key = f.string("age-secret-key")?;
    let override_ = parse_override(&mut f)?;
    let mut fallback = Vec::new();
    let payload = match f.raw("payload") {
        Some(Value::Array(items)) => items.as_slice(),
        None | Some(Value::Null) => &[],
        Some(_) => return Err(ConfigError::new("'payload' is not a slice")),
    };
    for item in payload {
        match item {
            Value::Object(entry) => fallback.push(entry.clone()),
            _ => return Err(ConfigError::new("payload entries must be maps")),
        }
    }
    let source = match type_name.as_str() {
        "file" => ProxySource::File {
            path: f.string("path")?,
        },
        "http" => ProxySource::Http(http_source(&mut f)?),
        "inline" => ProxySource::Inline {
            payload: std::mem::take(&mut fallback),
        },
        other => {
            return Err(ConfigError::new(format!("unsupport vehicle type: {other}")));
        }
    };
    f.finish()?;
    CompiledFilter::compile(&filter_text)
        .map_err(|err| ConfigError::new(format!("invalid filter regex: {}", err.message)))?;
    if !exclude_filter.is_empty() {
        CompiledFilter::compile(&exclude_filter).map_err(|err| {
            ConfigError::new(format!("invalid excludeFilter regex: {}", err.message))
        })?;
    }
    if !age_secret_key.is_empty() {
        crypt::verify_secret_key(&age_secret_key)
            .map_err(|err| ConfigError::new(format!("invalid age-secret-key: {}", err.message)))?;
    }
    Ok(ProxyProviderDef {
        name: name.to_string(),
        source,
        interval,
        filter: filter_text,
        exclude_filter,
        exclude_type,
        dialer_proxy,
        age_secret_key,
        health_check,
        override_,
        fallback,
        raw: map.clone(),
    })
}

impl ProxyProviderDef {
    pub fn select_proxies(&self, proxies: Vec<Map>) -> Result<Vec<Map>> {
        let include = CompiledFilter::compile(&self.filter)?;
        let exclude = if self.exclude_filter.is_empty() {
            None
        } else {
            Some(CompiledFilter::compile(&self.exclude_filter)?)
        };
        let excluded_types: Vec<&str> = if self.exclude_type.is_empty() {
            Vec::new()
        } else {
            self.exclude_type.split('|').collect()
        };
        let rewrites = self
            .override_
            .proxy_name
            .iter()
            .map(|r| filter::compile_pattern(&r.pattern, false).map(|m| (m, r.target.as_str())))
            .collect::<Result<Vec<_>>>()?;
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for mut mapping in proxies {
            let Some(Value::String(name)) = mapping.get("name") else {
                continue;
            };
            if !excluded_types.is_empty() {
                let Some(Value::String(kind)) = mapping.get("type") else {
                    continue;
                };
                if excluded_types.iter().any(|t| t.eq_ignore_ascii_case(kind)) {
                    continue;
                }
            }
            if exclude.as_ref().is_some_and(|re| re.is_match(name)) {
                continue;
            }
            if !self.filter.is_empty() && !include.is_match(name) {
                continue;
            }
            if !seen.insert(name.clone()) {
                continue;
            }
            if !self.dialer_proxy.is_empty() {
                put(
                    &mut mapping,
                    "dialer-proxy",
                    Value::String(self.dialer_proxy.clone()),
                );
            }
            self.apply_override(&mut mapping, &rewrites);
            out.push(mapping);
        }
        if out.is_empty() {
            return Err(ConfigError::new(if self.filter.is_empty() {
                "file doesn't have any proxy"
            } else {
                "doesn't match any proxy, please check your filter"
            }));
        }
        Ok(out)
    }

    fn apply_override(&self, mapping: &mut Map, rewrites: &[(filter::Matcher, &str)]) {
        let o = &self.override_;
        let flags = [
            ("tfo", o.tfo),
            ("mptcp", o.mptcp),
            ("udp", o.udp),
            ("udp-over-tcp", o.udp_over_tcp),
            ("skip-cert-verify", o.skip_cert_verify),
        ];
        for (key, value) in flags {
            if let Some(value) = value {
                put(mapping, key, Value::Bool(value));
            }
        }
        let texts = [
            ("up", &o.up),
            ("down", &o.down),
            ("dialer-proxy", &o.dialer_proxy),
            ("name-cert-verify", &o.name_cert_verify),
            ("interface-name", &o.interface_name),
            ("ip-version", &o.ip_version),
        ];
        for (key, value) in texts {
            if let Some(value) = value {
                put(mapping, key, Value::String(value.clone()));
            }
        }
        if let Some(mark) = o.routing_mark {
            put(mapping, "routing-mark", Value::from(mark));
        }
        let mut name = mapping
            .get("name")
            .and_then(scalar_text)
            .unwrap_or_default();
        for (matcher, target) in rewrites {
            name = matcher.replace_all(&name, target);
        }
        if let Some(prefix) = &o.additional_prefix {
            name = format!("{prefix}{name}");
        }
        if let Some(suffix) = &o.additional_suffix {
            name.push_str(suffix);
        }
        mapping.insert("name".into(), Value::String(name));
    }
}

pub fn parse_rule_provider(name: &str, map: &Map) -> Result<RuleProviderDef> {
    let mut f = Fields::new(map, "", false);
    f.require("type");
    f.require("behavior");
    let type_name = f.string("type")?;
    let behavior_text = f.string("behavior")?;
    let format_text = f.string("format")?;
    let interval = f.u32("interval")?;
    let path_in_bundle = f.string("path-in-bundle")?;
    let behavior = match behavior_text.as_str() {
        "domain" => RuleBehavior::Domain,
        "ipcidr" => RuleBehavior::IpCidr,
        "classical" => RuleBehavior::Classical,
        other => {
            f.finish()?;
            return Err(ConfigError::new(format!(
                "unsupported behavior type: {other}"
            )));
        }
    };
    let format = match format_text.as_str() {
        "" | "yaml" => RuleFormat::Yaml,
        "text" => RuleFormat::Text,
        "mrs" => RuleFormat::Mrs,
        "domain-set" if behavior == RuleBehavior::Domain => RuleFormat::DomainSet,
        "domain-set" => {
            return Err(ConfigError::new(
                "the domain-set format needs the domain behavior",
            ));
        }
        other => {
            return Err(ConfigError::new(format!(
                "unsupported format type: {other}"
            )));
        }
    };
    let mut fallback = Vec::new();
    let source = match type_name.as_str() {
        "file" => RuleSource::File {
            path: f.string("path")?,
        },
        "http" => RuleSource::Http(http_source(&mut f)?),
        "inline" => RuleSource::Inline {
            payload: f.strings("payload")?,
        },
        other => {
            return Err(ConfigError::new(format!(
                "unsupported vehicle type: {other}"
            )));
        }
    };
    if !matches!(source, RuleSource::Inline { .. }) {
        fallback = f.strings("payload")?;
        fallback.retain(|entry| !entry.is_empty());
    }
    f.finish()?;
    Ok(RuleProviderDef {
        name: name.to_string(),
        source,
        behavior,
        format,
        interval,
        fallback,
        path_in_bundle,
        raw: map.clone(),
    })
}

/// Node keys are read without case and with `_` for `-`, first spelling first, so a spelling the
/// node already has would win over the override.
fn put(mapping: &mut Map, key: &str, value: Value) {
    mapping.retain(|existing, _| !existing.replace('_', "-").eq_ignore_ascii_case(key));
    mapping.insert(key.into(), value);
}

pub fn parse_rule_providers(
    maps: &IndexMap<String, Map>,
    report: &mut LoadReport,
) -> Result<Vec<RuleProviderDef>> {
    let mut providers = Vec::with_capacity(maps.len());
    for (name, map) in maps {
        let provider = parse_rule_provider(name, map)
            .map_err(|err| err.prefixed(&format!("parse rule provider {name} error: ")))?;
        if !provider.path_in_bundle.is_empty()
            && !matches!(provider.source, RuleSource::Inline { .. })
        {
            report.warn(
                "not_applied",
                format!("rule-providers.{name}.path-in-bundle"),
                "BundleMRS.7z is not read by this core; the provider loads from its path or url",
            );
        }
        providers.push(provider);
    }
    Ok(providers)
}

pub fn parse_provider_content(bytes: &[u8], age_secret_key: Option<&str>) -> Result<Vec<Map>> {
    let keys: Vec<&str> = age_secret_key
        .filter(|k| !k.is_empty())
        .into_iter()
        .collect();
    let plain = crypt::decrypt_config(bytes, &keys)?;
    let parsed = std::str::from_utf8(&plain)
        .map_err(|_| ConfigError::new("yaml: invalid leading UTF-8 octet"))
        .and_then(|text| yaml::parse_document(text.strip_prefix('\u{feff}').unwrap_or(text)));
    let proxies = match parsed {
        Ok(mut doc) => doc.root.remove("proxies"),
        Err(yaml_err) => {
            return share_link::decode_subscription_bytes(&plain).map_err(|link_err| {
                ConfigError::new(format!("{}, {}", yaml_err.message, link_err.message))
            });
        }
    };
    match proxies {
        None | Some(Value::Null) => Err(ConfigError::new("file must have a `proxies` field")),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|item| match item {
                Value::Object(map) => Ok(map),
                _ => Err(ConfigError::new(
                    "yaml: unmarshal errors: cannot unmarshal a non-map into map[string]interface {}",
                )),
            })
            .collect(),
        Some(_) => Err(ConfigError::new(
            "yaml: unmarshal errors: cannot unmarshal a non-sequence into proxies",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(value: Value) -> Map {
        match value {
            Value::Object(map) => map,
            _ => Map::new(),
        }
    }

    #[test]
    fn proxy_providers_cover_the_three_vehicles() {
        let http = parse_proxy_provider(
            "p",
            &map(json!({"type": "http", "url": "https://x/sub", "path": "./p.yaml", "interval": 3600,
                "header": {"User-Agent": ["clash"]}, "health-check": {"enable": true, "url": "https://t"},
                "override": {"additional-prefix": "A-", "udp": true}})),
        )
        .unwrap();
        assert!(matches!(&http.source, ProxySource::Http(h) if h.url == "https://x/sub"));
        assert_eq!(http.health_check.interval, 300);
        assert!(http.health_check.lazy);
        assert_eq!(http.override_.additional_prefix.as_deref(), Some("A-"));
        let file =
            parse_proxy_provider("f", &map(json!({"type": "file", "path": "a.yaml"}))).unwrap();
        assert!(matches!(file.source, ProxySource::File { .. }));
        let inline = parse_proxy_provider(
            "i",
            &map(json!({"type": "inline", "payload": [{"name": "a", "type": "direct"}]})),
        )
        .unwrap();
        assert!(matches!(&inline.source, ProxySource::Inline { payload } if payload.len() == 1));
        assert!(inline.fallback.is_empty());
        let spare = parse_proxy_provider(
            "s",
            &map(json!({"type": "file", "path": "a.yaml", "payload": [{"name": "a", "type": "direct"}]})),
        )
        .unwrap();
        assert_eq!(spare.fallback.len(), 1);
        assert!(parse_proxy_provider("x", &map(json!({"type": "ftp"}))).is_err());
        assert!(parse_proxy_provider("x", &map(json!({}))).is_err());
        assert!(
            parse_proxy_provider(
                "x",
                &map(json!({"type": "file", "path": "a", "filter": "(x"}))
            )
            .is_err()
        );
    }

    #[test]
    fn a_payload_that_is_not_a_list_is_refused() {
        let err = parse_proxy_provider(
            "p",
            &map(json!({"type": "inline", "payload": {"name": "a", "type": "direct"}})),
        )
        .unwrap_err();
        assert_eq!(err.message, "'payload' is not a slice");
    }

    #[test]
    fn a_proxy_name_rewrite_that_is_not_a_list_is_refused() {
        let parsed = |rewrite: Value| {
            parse_proxy_provider(
                "p",
                &map(json!({"type": "file", "path": "a", "override": {"proxy-name": rewrite}})),
            )
        };
        let err = parsed(json!({"pattern": "a", "target": "b"})).unwrap_err();
        assert_eq!(err.message, "'override.proxy-name' is not a slice");
        assert!(parsed(Value::Null).unwrap().override_.proxy_name.is_empty());
        let listed = parsed(json!([{"pattern": "a", "target": "b"}])).unwrap();
        assert_eq!(listed.override_.proxy_name.len(), 1);
    }

    #[test]
    fn an_override_replaces_every_spelling_of_its_key() {
        let def = parse_proxy_provider(
            "p",
            &map(json!({"type": "file", "path": "a", "dialer-proxy": "relay",
                "override": {"skip-cert-verify": false}})),
        )
        .unwrap();
        let node = map(
            json!({"name": "a", "type": "trojan", "server": "s", "port": 443, "password": "p",
            "skip_cert_verify": true, "Dialer_Proxy": "other"}),
        );
        let out = def.select_proxies(vec![node]).unwrap();
        let Ok(crate::ProxyParse::Ok(parsed)) =
            crate::parse_proxy(&out[0], &crate::Capabilities::full())
        else {
            panic!("{out:?}");
        };
        assert_eq!(parsed.common.dialer_proxy, "relay");
        let crate::proxy::ProxyKind::Trojan(trojan) = &parsed.kind else {
            panic!("{parsed:?}");
        };
        assert!(!trojan.tls.skip_cert_verify);
    }

    #[test]
    fn selecting_proxies_applies_filters_and_overrides() {
        let def = parse_proxy_provider(
            "p",
            &map(json!({"type": "file", "path": "a", "filter": "hk", "exclude-type": "vmess|ss",
                "dialer-proxy": "chain", "override": {"additional-prefix": "P-", "additional-suffix": "-S", "udp": false}})),
        )
        .unwrap();
        let proxies = vec![
            map(json!({"name": "hk1", "type": "trojan"})),
            map(json!({"name": "hk1", "type": "trojan"})),
            map(json!({"name": "hk2", "type": "VMess"})),
            map(json!({"name": "jp1", "type": "trojan"})),
        ];
        let out = def.select_proxies(proxies).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["name"], "P-hk1-S");
        assert_eq!(out[0]["dialer-proxy"], "chain");
        assert_eq!(out[0]["udp"], false);
        assert!(
            def.select_proxies(vec![map(json!({"name": "us", "type": "ss"}))])
                .is_err()
        );
    }

    #[test]
    fn rule_providers() {
        let def = parse_rule_provider(
            "r",
            &map(json!({"type": "http", "url": "https://x", "behavior": "domain", "format": "mrs", "interval": 86400})),
        )
        .unwrap();
        assert_eq!(
            (def.behavior, def.format),
            (RuleBehavior::Domain, RuleFormat::Mrs)
        );
        let set = parse_rule_provider(
            "s",
            &map(json!({"type": "http", "url": "https://x", "behavior": "domain", "format": "domain-set"})),
        )
        .unwrap();
        assert_eq!(set.format, RuleFormat::DomainSet);
        assert!(
            parse_rule_provider(
                "s",
                &map(json!({"type": "http", "url": "https://x", "behavior": "classical", "format": "domain-set"})),
            )
            .is_err()
        );
        let inline = parse_rule_provider(
            "i",
            &map(json!({"type": "inline", "behavior": "classical", "payload": ["DOMAIN,a.com"]})),
        )
        .unwrap();
        assert!(matches!(&inline.source, RuleSource::Inline { payload } if payload.len() == 1));
        assert!(inline.fallback.is_empty());
        let file = parse_rule_provider(
            "f",
            &map(json!({"type": "file", "behavior": "classical", "path": "a", "payload": ["DOMAIN,a.com"]})),
        )
        .unwrap();
        assert_eq!(file.fallback, ["DOMAIN,a.com"]);
        assert!(
            parse_rule_provider(
                "x",
                &map(json!({"type": "file", "behavior": "weird", "path": "a"}))
            )
            .is_err()
        );
        assert!(
            parse_rule_provider(
                "x",
                &map(json!({"type": "file", "behavior": "domain", "format": "bin", "path": "a"}))
            )
            .is_err()
        );
        let bundled = parse_rule_provider(
            "b",
            &map(json!({"type": "file", "behavior": "domain", "path": "a", "path-in-bundle": "geo/cn.mrs"})),
        )
        .unwrap();
        assert_eq!(bundled.path_in_bundle, "geo/cn.mrs");
    }

    #[test]
    fn provider_content_is_yaml_or_a_share_link_list() {
        let yaml = b"proxies:\n  - {name: a, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: p}\n";
        assert_eq!(parse_provider_content(yaml, None).unwrap().len(), 1);
        assert!(parse_provider_content(b"mode: rule\n", None).is_err());
        let links = b"trojan://pw@a.example:443#one\nsocks5://b.example:1080#two\n";
        let proxies = parse_provider_content(links, None).unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0]["name"], "one");
        let encoded = base64_of(links);
        assert_eq!(
            parse_provider_content(encoded.as_bytes(), None)
                .unwrap()
                .len(),
            2
        );
        assert!(parse_provider_content(b"garbage without links", None).is_err());
    }

    fn base64_of(data: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(data)
    }
}
