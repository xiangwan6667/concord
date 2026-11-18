use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use serde_json::Value;

use crate::Map;
use crate::dns::DnsConfig;
use crate::error::{ConfigError, Result};
use crate::general::General;
use crate::geox::GeoConfig;
use crate::group::{GroupDef, GroupKind, find_group_cycle, parse_group};
use crate::hosts::{HostsConfig, parse_hosts};
use crate::ntp::NtpConfig;
use crate::provider::{
    ProxyProviderDef, ProxySource, RuleProviderDef, parse_proxy_provider, parse_rule_providers,
};
use crate::proxy::{Capabilities, ProxyDef, ProxyParse, Quarantined, parse_proxy, proxy_warnings};
use crate::raw::{RawConfig, parse_raw_with_key};
use crate::report::LoadReport;
use crate::rule::{Cond, RuleDef, RuleLines, parse_rule};
use crate::sniffer::SnifferConfig;
use crate::tls::TlsConfig;
use crate::tun::TunConfig;

const BUILTIN_TARGETS: [&str; 7] = [
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "PASS-RULE",
    "COMPATIBLE",
    "GLOBAL",
];
const RESERVED_PROVIDER: &str = "default";
const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";

#[derive(Clone, Debug, Default)]
pub struct LoadOptions {
    pub capabilities: Capabilities,
    pub android: bool,
    pub age_secret_key: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Profile {
    pub general: General,
    pub dns: DnsConfig,
    pub tun: TunConfig,
    pub sniffer: SnifferConfig,
    pub hosts: HostsConfig,
    pub geo: GeoConfig,
    pub ntp: NtpConfig,
    pub proxies: Vec<ProxyDef>,
    pub quarantined: Vec<Quarantined>,
    pub quarantined_names: HashSet<String>,
    pub groups: Vec<GroupDef>,
    pub refused_groups: Vec<String>,
    pub proxy_providers: Vec<ProxyProviderDef>,
    pub rule_providers: Vec<RuleProviderDef>,
    /// Checked lines, parsed one at a time when they are compiled. Definitions for all
    /// of them at once cost several times the text.
    pub rules: RuleLines,
    pub sub_rules: IndexMap<String, Vec<RuleDef>>,
    pub store_fake_ip: bool,
    pub dialer_ip4p_convert: bool,
    pub refuse_all: bool,
    pub mitm: crate::mitm::MitmDef,
    pub tls: TlsConfig,
    pub report: LoadReport,
}

impl Profile {
    pub fn rejected_empty() -> Profile {
        let raw = RawConfig::default();
        let mut profile =
            load_raw(raw, &LoadOptions::default()).unwrap_or_else(|_| Profile::bare());
        profile.refuse_all = true;
        profile
    }

    fn bare() -> Profile {
        Profile {
            general: General::default(),
            dns: DnsConfig::default(),
            tun: TunConfig::default(),
            sniffer: SnifferConfig::default(),
            hosts: HostsConfig::default(),
            geo: GeoConfig::from_map(&Map::new()).unwrap_or(GeoConfig {
                mmdb_url: String::new(),
                asn_url: String::new(),
                geosite_url: String::new(),
            }),
            ntp: NtpConfig {
                enable: false,
                server: String::new(),
                port: 0,
                interval: 0,
                dialer_proxy: String::new(),
                write_to_system: false,
            },
            proxies: Vec::new(),
            quarantined: Vec::new(),
            quarantined_names: HashSet::new(),
            groups: Vec::new(),
            refused_groups: Vec::new(),
            proxy_providers: Vec::new(),
            rule_providers: Vec::new(),
            rules: RuleLines::default(),
            sub_rules: IndexMap::new(),
            store_fake_ip: false,
            dialer_ip4p_convert: false,
            refuse_all: true,
            mitm: crate::mitm::MitmDef::default(),
            tls: TlsConfig::default(),
            report: LoadReport::default(),
        }
    }

    pub fn is_quarantined(&self, name: &str) -> bool {
        self.quarantined_names.contains(name)
    }
}

pub fn load(bytes: &[u8], options: &LoadOptions) -> Result<Profile> {
    let raw = parse_raw_with_key(bytes, options.age_secret_key.as_deref())?;
    load_raw(raw, options)
}

pub fn load_str(text: &str, options: &LoadOptions) -> Result<Profile> {
    load(text.as_bytes(), options)
}

struct Names {
    known: HashSet<String>,
    groups: HashSet<String>,
    quarantined: HashSet<String>,
}

impl Names {
    fn resolves(&self, name: &str) -> bool {
        self.known.contains(name) || self.quarantined.contains(name)
    }
}

fn parse_provider_proxies(
    providers: &[ProxyProviderDef],
    options: &LoadOptions,
    quarantined: &mut Vec<Quarantined>,
    report: &mut LoadReport,
) -> Result<()> {
    for provider in providers {
        let payload = match &provider.source {
            ProxySource::Inline { payload } => payload,
            _ => &provider.fallback,
        };
        if provider.override_.expr || payload.is_empty() {
            continue;
        }
        let selected = provider.select_proxies(payload.clone()).map_err(|err| {
            err.prefixed(&format!("parse proxy provider {} error: ", provider.name))
        })?;
        for (index, mapping) in selected.iter().enumerate() {
            let prefix = format!(
                "parse proxy provider {} error: proxy {index}: ",
                provider.name
            );
            match parse_proxy(mapping, &options.capabilities)
                .map_err(|err| err.prefixed(&prefix))?
            {
                ProxyParse::Ok(def) => {
                    for message in proxy_warnings(&def) {
                        report.warn(
                            "proxy_option",
                            format!("proxy-providers.{}[{index}]", provider.name),
                            format!("{}: {message}", def.name),
                        );
                    }
                }
                ProxyParse::Quarantined { name, kind, reason } => {
                    report.warn(
                        "proxy_quarantined",
                        format!("proxy-providers.{}[{index}]", provider.name),
                        format!("{name}: {reason}"),
                    );
                    quarantined.push(Quarantined {
                        index: Some(index),
                        provider: Some(provider.name.clone()),
                        name,
                        kind,
                        reason,
                    });
                }
            }
        }
    }
    Ok(())
}

fn quarantine_dependents(
    proxies: &mut Vec<ProxyDef>,
    quarantined: &mut Vec<Quarantined>,
    names: &mut Names,
    report: &mut LoadReport,
) {
    while let Some(position) = proxies.iter().position(|p| {
        !p.common.dialer_proxy.is_empty() && names.quarantined.contains(&p.common.dialer_proxy)
    }) {
        let def = proxies.remove(position);
        let reason = format!(
            "dialer-proxy '{}' is not supported by this core",
            def.common.dialer_proxy
        );
        report.warn(
            "proxy_quarantined",
            format!("proxies.{}", def.name),
            reason.clone(),
        );
        names.known.remove(&def.name);
        names.quarantined.insert(def.name.clone());
        quarantined.push(Quarantined {
            index: None,
            provider: None,
            name: def.name.clone(),
            kind: def.kind.type_name().to_string(),
            reason,
        });
    }
}

fn validate_dialers(proxies: &[ProxyDef], names: &Names) -> Result<()> {
    let mut graph: HashMap<&str, &str> = HashMap::new();
    for proxy in proxies {
        let dialer = proxy.common.dialer_proxy.as_str();
        if dialer.is_empty() {
            continue;
        }
        if !names.resolves(dialer) {
            return Err(ConfigError::new(format!(
                "proxy [{}] dialer-proxy [{dialer}] not found",
                proxy.name
            )));
        }
        graph.insert(proxy.name.as_str(), dialer);
    }
    let mut done: HashSet<&str> = HashSet::new();
    for start in graph.keys().copied() {
        let mut path: Vec<&str> = Vec::new();
        let mut current = Some(start);
        while let Some(name) = current {
            if done.contains(name) {
                break;
            }
            if path.contains(&name) {
                return Err(ConfigError::new(format!(
                    "proxy [{start}] has circular dialer-proxy dependency"
                )));
            }
            path.push(name);
            current = graph.get(name).copied();
        }
        done.extend(path);
    }
    Ok(())
}

fn resolve_groups(
    raw: &RawConfig,
    names: &mut Names,
    proxy_names: &[String],
    provider_defs: &[ProxyProviderDef],
    report: &mut LoadReport,
    quarantined_refs: &mut HashSet<String>,
) -> Result<(Vec<GroupDef>, Vec<String>)> {
    let mut groups = Vec::with_capacity(raw.proxy_groups.len());
    for (index, map) in raw.proxy_groups.iter().enumerate() {
        let line = raw.lines.proxy_groups.get(index).copied();
        if !matches!(map.get("name"), Some(Value::String(_))) {
            return Err(
                ConfigError::new(format!("proxy group {index}: missing name")).with_line(line),
            );
        }
        let group = parse_group(map).map_err(|err| {
            err.prefixed(&format!("proxy group[{index}]: "))
                .with_line(line)
        })?;
        if names.groups.contains(&group.name) || names.known.contains(&group.name) {
            return Err(ConfigError::new(format!(
                "proxy group {}: the duplicate name",
                group.name
            ))
            .with_line(line));
        }
        let prefix = format!("proxy-groups.{}.", group.name);
        report.warn_ignored(&prefix, &group.ignored);
        names.groups.insert(group.name.clone());
        groups.push(group);
    }
    if let Some(cycle) = find_group_cycle(&groups) {
        return Err(ConfigError::new(format!(
            "loop is detected in ProxyGroup, please check following ProxyGroups: [{}]",
            cycle.join(" ")
        )));
    }
    names.known.extend(names.groups.iter().cloned());

    let mut sorted_proxies: Vec<&str> = proxy_names.iter().map(String::as_str).collect();
    sorted_proxies.sort_unstable();
    let mut sorted_providers: Vec<&str> = provider_defs.iter().map(|p| p.name.as_str()).collect();
    sorted_providers.sort_unstable();

    let mut refused = Vec::new();
    for (index, group) in groups.iter_mut().enumerate() {
        let line = raw.lines.proxy_groups.get(index).copied();
        let fail = |message: String| {
            ConfigError::new(format!("proxy group[{index}]: {message}")).with_line(line)
        };
        if group.empty_fallback.is_empty() {
            group.empty_fallback = "COMPATIBLE".to_string();
        }
        let fallback = group.empty_fallback.clone();
        let fallback_ok = (BUILTIN_TARGETS.contains(&fallback.as_str()) && fallback != "GLOBAL")
            || (names.resolves(&fallback) && !names.groups.contains(&fallback));
        if !fallback_ok {
            return Err(fail(format!(
                "{}: empty fallback proxy '{fallback}' not found",
                group.name
            )));
        }
        if group.include_all_providers {
            group.use_providers = sorted_providers.iter().map(|s| (*s).to_string()).collect();
        }
        let mut dropped = Vec::new();
        if group.include_all_proxies {
            dropped = group
                .take_all_proxies(&sorted_proxies, &names.quarantined)
                .map_err(|err| fail(err.message))?;
            if group.proxies.is_empty() && group.use_providers.is_empty() {
                group.proxies = vec![fallback.clone()];
            }
        }
        if group.proxies.is_empty() && group.use_providers.is_empty() {
            return Err(fail(format!("{}: `use` or `proxies` missing", group.name)));
        }
        for provider in &group.use_providers {
            let defined = provider_defs.iter().any(|p| &p.name == provider);
            if provider == RESERVED_PROVIDER || (!defined && names.groups.contains(provider)) {
                return Err(fail(format!(
                    "proxy group {provider} can't contains in `use`"
                )));
            }
            if !defined {
                return Err(fail(format!("{}: '{provider}' not found", group.name)));
            }
        }
        let had_proxies = !group.proxies.is_empty();
        let mut kept = Vec::with_capacity(group.proxies.len());
        for proxy in std::mem::take(&mut group.proxies) {
            let builtin = BUILTIN_TARGETS.contains(&proxy.as_str()) && proxy != "GLOBAL";
            if names.known.contains(&proxy) || builtin {
                kept.push(proxy);
            } else if names.quarantined.contains(&proxy) {
                quarantined_refs.insert(proxy.clone());
                dropped.push(proxy);
            } else {
                return Err(fail(format!("{}: '{proxy}' not found", group.name)));
            }
        }
        group.proxies = kept;
        if !dropped.is_empty() {
            report.warn(
                "group_members_dropped",
                format!("proxy-groups.{}", group.name),
                format!("dropped quarantined members: {}", dropped.join(", ")),
            );
        }
        if had_proxies && group.proxies.is_empty() && group.use_providers.is_empty() {
            report.warn(
                "group_refused",
                format!("proxy-groups.{}", group.name),
                "every member is unsupported, connections through this group are refused",
            );
            refused.push(group.name.clone());
        }
        if names.quarantined.contains(&group.default_selected) {
            report.warn(
                "group_default_ignored",
                format!("proxy-groups.{}", group.name),
                format!(
                    "default-selected '{}' is unsupported and ignored",
                    group.default_selected
                ),
            );
            group.default_selected.clear();
        }
        if group.url.is_empty() {
            group.url = group
                .use_providers
                .iter()
                .filter_map(|name| provider_defs.iter().find(|p| &p.name == name))
                .map(|p| p.health_check.url.clone())
                .find(|url| !url.is_empty())
                .unwrap_or_else(|| DEFAULT_TEST_URL.to_string());
        }
        if group.kind != GroupKind::Select && had_proxies && group.interval == 0 {
            group.interval = 300;
        }
    }
    Ok((groups, refused))
}

fn cond_types(cond: &Cond, out: &mut Vec<&'static str>) {
    if let Cond::Flagged { cond: inner, .. } = cond {
        return cond_types(inner, out);
    }
    out.push(cond.type_name());
    match cond {
        Cond::And(items) | Cond::Or(items) => items.iter().for_each(|c| cond_types(c, out)),
        Cond::Not(inner) | Cond::SubRule(inner) => cond_types(inner, out),
        _ => {}
    }
}

struct RuleContext<'a> {
    names: &'a Names,
    sub_rules: &'a IndexMap<String, Vec<String>>,
    rule_providers: &'a HashSet<&'a str>,
    capabilities: &'a Capabilities,
}

/// `DOMAIN` and `DOMAIN-SUFFIX` compare literally, and no host has a `*` or `+` in it.
fn is_dead_domain(cond: &Cond) -> bool {
    match cond {
        Cond::Domain(payload) | Cond::DomainSuffix(payload) => payload.contains(['*', '+']),
        _ => false,
    }
}

fn report_dead_rules(report: &mut LoadReport, path: &str, after_match: usize, dead: &[String]) {
    if after_match > 0 {
        report.info(
            "rule_unreachable",
            path,
            format!("{after_match} rules after MATCH are never reached"),
        );
    }
    if let Some(first) = dead.first() {
        let more = match dead.len() {
            1 => String::new(),
            count => format!(" and {} more", count - 1),
        };
        report.info(
            "rule_never_matches",
            path,
            format!(
                "[{first}]{more} never match: DOMAIN and DOMAIN-SUFFIX take no wildcard, \
                 use DOMAIN-WILDCARD"
            ),
        );
    }
}

fn each_checked_rule<'a>(
    lines: impl Iterator<Item = &'a str>,
    source_lines: &[u32],
    format: &str,
    ctx: &RuleContext<'_>,
    report: &mut LoadReport,
    mut keep: impl FnMut(RuleDef),
) -> Result<()> {
    let mut types: Vec<&'static str> = Vec::new();
    let mut matched = false;
    let mut after_match = 0;
    let mut dead = Vec::new();
    for (index, line) in lines.enumerate() {
        let fail = |message: &str| {
            ConfigError::new(format!("{format}[{index}] [{line}] error: {message}"))
                .with_line(source_lines.get(index).copied())
        };
        let rule = parse_rule(line).map_err(|err| fail(&err.message))?;
        types.clear();
        cond_types(&rule.cond, &mut types);
        if let Some(unsupported) = types
            .iter()
            .find(|t| !ctx.capabilities.rule_types.contains(t))
        {
            if *unsupported == "UID" {
                return Err(fail("uid rule not support this platform"));
            }
            return Err(fail(&format!(
                "rule type {unsupported} is not supported by this core"
            )));
        }
        let proxy =
            BUILTIN_TARGETS.contains(&rule.target.as_str()) || ctx.names.resolves(&rule.target);
        if !matches!(rule.cond, Cond::SubRule(_)) {
            if !proxy {
                return Err(fail(&format!("proxy [{}] not found", rule.target)));
            }
        } else if !ctx.sub_rules.contains_key(&rule.target) {
            if !proxy || format != "rules" {
                return Err(fail(&format!("sub-rule [{}] not found", rule.target)));
            }
            let message = format!(
                "SUB-RULE target {} is not a sub-rule, so the rule never matches",
                rule.target
            );
            report.info("rule_never_matches", format!("rules[{index}]"), message);
        }
        let mut sets = Vec::new();
        rule.cond.rule_sets(&mut sets);
        if let Some(missing) = sets
            .into_iter()
            .find(|name| !ctx.rule_providers.contains(name))
        {
            return Err(fail(&format!("rule set [{missing}] not found")));
        }
        if matched {
            after_match += 1;
        } else if is_dead_domain(&rule.cond) {
            dead.push(rule.text.clone());
        }
        matched |= rule.cond == Cond::Match;
        keep(rule);
    }
    report_dead_rules(report, format, after_match, &dead);
    Ok(())
}

fn find_sub_rule_cycle(sub_rules: &IndexMap<String, Vec<RuleDef>>) -> Option<Vec<String>> {
    fn visit<'a>(
        name: &'a str,
        graph: &HashMap<&'a str, Vec<&'a str>>,
        path: &mut Vec<&'a str>,
        done: &mut HashSet<&'a str>,
    ) -> Option<Vec<String>> {
        if done.contains(name) {
            return None;
        }
        if let Some(at) = path.iter().position(|p| *p == name) {
            let mut cycle: Vec<String> = path.iter().skip(at).map(|s| (*s).to_string()).collect();
            cycle.push(name.to_string());
            return Some(cycle);
        }
        path.push(name);
        for next in graph.get(name).into_iter().flatten() {
            if let Some(cycle) = visit(next, graph, path, done) {
                return Some(cycle);
            }
        }
        path.pop();
        done.insert(name);
        None
    }
    let graph: HashMap<&str, Vec<&str>> = sub_rules
        .iter()
        .map(|(name, rules)| {
            let targets = rules
                .iter()
                .filter(|r| matches!(r.cond, Cond::SubRule(_)))
                .map(|r| r.target.as_str())
                .collect();
            (name.as_str(), targets)
        })
        .collect();
    let mut done = HashSet::new();
    for name in sub_rules.keys() {
        if let Some(cycle) = visit(name, &graph, &mut Vec::new(), &mut done) {
            return Some(cycle);
        }
    }
    None
}

fn warn_tun_settings(tun: &TunConfig, report: &mut LoadReport) {
    if !tun.enable {
        return;
    }
    match tun.stack_name.to_ascii_lowercase().as_str() {
        "mixed" => report.warn(
            "tun_stack_fallback",
            "tun.stack",
            "mixed runs as the userspace stack",
        ),
        "system" => report.warn(
            "tun_stack_fallback",
            "tun.stack",
            "the system stack is not available, so the userspace stack runs instead",
        ),
        _ => {}
    }
}

fn warn_ignored_sections(raw: &RawConfig, report: &mut LoadReport) {
    let differs = |map: &Map, key: &str, default: bool| {
        map.get(key)
            .and_then(crate::lenient::to_bool)
            .is_some_and(|value| value != default)
    };
    if differs(&raw.experimental, "quic-go-disable-gso", false)
        || differs(&raw.experimental, "quic-go-disable-ecn", true)
    {
        report.warn(
            "not_applied",
            "experimental",
            "quic-go-disable-gso and quic-go-disable-ecn are not applied by this core",
        );
    }
    for key in [
        "certificate",
        "private-key",
        "client-auth-type",
        "client-auth-cert",
        "ech-key",
    ] {
        if raw.tls.get(key).is_some_and(|value| {
            value
                .as_str()
                .map_or(!value.is_null(), |text| !text.is_empty())
        }) {
            report.warn(
                "not_applied",
                format!("tls.{key}"),
                "inbound TLS settings are not used by this core",
            );
        }
    }
}

pub fn load_raw(mut raw: RawConfig, options: &LoadOptions) -> Result<Profile> {
    let mut report = std::mem::take(&mut raw.report);
    let (general, general_notes) = General::read(&raw.general)?;
    let (dns, dns_notes) =
        DnsConfig::read(&raw.dns, general.ipv6).map_err(|err| err.within("dns"))?;
    let tun = TunConfig::from_map(&raw.tun).map_err(|err| err.within("tun"))?;
    let sniffer = SnifferConfig::from_map(&raw.sniffer).map_err(|err| err.within("sniffer"))?;
    let (ntp, ntp_notes) = NtpConfig::read(&raw.ntp)?;
    let notes = [general_notes, dns_notes, ntp_notes].concat();
    report.warn_ignored("", &notes);
    let geo = GeoConfig::from_map(&raw.geox_url)?;
    let hosts = parse_hosts(&raw.hosts, &mut report)?;

    if !options.android {
        warn_tun_settings(&tun, &mut report);
    }
    warn_ignored_sections(&raw, &mut report);
    if dns.enable {
        for (key, iface) in dns.dhcp_interfaces() {
            report.warn(
                "dhcp_as_system",
                key,
                format!(
                    "dhcp://{iface} is treated as system://: no DHCP client runs and the \
                     servers are not bound to {iface}"
                ),
            );
        }
    }

    let mut names = Names {
        known: BUILTIN_TARGETS
            .iter()
            .filter(|name| **name != "GLOBAL")
            .map(|s| (*s).to_string())
            .collect(),
        groups: HashSet::new(),
        quarantined: HashSet::new(),
    };
    let mut proxies: Vec<ProxyDef> = Vec::with_capacity(raw.proxies.len());
    let mut quarantined: Vec<Quarantined> = Vec::new();
    for (index, map) in std::mem::take(&mut raw.proxies).into_iter().enumerate() {
        let line = raw.lines.proxies.get(index).copied();
        let parsed = parse_proxy(&map, &options.capabilities)
            .map_err(|err| err.prefixed(&format!("proxy {index}: ")).with_line(line))?;
        let name = match &parsed {
            ProxyParse::Ok(def) => def.name.clone(),
            ProxyParse::Quarantined { name, .. } => name.clone(),
        };
        if names.known.contains(&name) && !BUILTIN_TARGETS.contains(&name.as_str())
            || names.quarantined.contains(&name)
        {
            return Err(
                ConfigError::new(format!("proxy {name} is the duplicate name")).with_line(line),
            );
        }
        match parsed {
            ProxyParse::Ok(def) => {
                for message in proxy_warnings(&def) {
                    report.warn(
                        "proxy_option",
                        format!("proxies[{index}]"),
                        format!("{name}: {message}"),
                    );
                }
                names.known.insert(name);
                proxies.push(*def);
            }
            ProxyParse::Quarantined { name, kind, reason } => {
                report.warn(
                    "proxy_quarantined",
                    format!("proxies[{index}]"),
                    format!("{name}: {reason}"),
                );
                names.quarantined.insert(name.clone());
                quarantined.push(Quarantined {
                    index: Some(index),
                    provider: None,
                    name,
                    kind,
                    reason,
                });
            }
        }
    }
    quarantine_dependents(&mut proxies, &mut quarantined, &mut names, &mut report);

    let mut proxy_providers = Vec::with_capacity(raw.proxy_providers.len());
    for (name, map) in &raw.proxy_providers {
        if name == RESERVED_PROVIDER {
            return Err(ConfigError::new(format!(
                "can not defined a provider called `{RESERVED_PROVIDER}`"
            )));
        }
        let mut provider = parse_proxy_provider(name, map)
            .map_err(|err| err.prefixed(&format!("parse proxy provider {name} error: ")))?;
        // The expressions can set `dialer-proxy` or `skip-cert-verify`, so its nodes must not run
        // without them.
        if provider.override_.expr {
            report.warn(
                "provider_emptied",
                format!("proxy-providers.{name}"),
                "override.override-expr is not supported by this core; the provider has no proxies",
            );
            provider.source = ProxySource::Inline {
                payload: Vec::new(),
            };
        }
        proxy_providers.push(provider);
    }
    parse_provider_proxies(&proxy_providers, options, &mut quarantined, &mut report)?;
    let rule_providers = parse_rule_providers(&raw.rule_providers, &mut report)?;

    let proxy_names: Vec<String> = proxies.iter().map(|p| p.name.clone()).collect();
    let mut referenced_quarantined = HashSet::new();
    let (mut groups, refused_groups) = resolve_groups(
        &raw,
        &mut names,
        &proxy_names,
        &proxy_providers,
        &mut report,
        &mut referenced_quarantined,
    )?;
    validate_dialers(&proxies, &names)?;
    if !names.groups.contains("GLOBAL") {
        let global = GroupDef::global(&proxies, &groups, DEFAULT_TEST_URL);
        groups.push(global);
    }

    let provider_names: HashSet<&str> = rule_providers.iter().map(|p| p.name.as_str()).collect();
    let ctx = RuleContext {
        names: &names,
        sub_rules: &raw.sub_rules,
        rule_providers: &provider_names,
        capabilities: &options.capabilities,
    };
    each_checked_rule(
        raw.rules.iter(),
        &raw.lines.rules,
        "rules",
        &ctx,
        &mut report,
        drop,
    )?;
    let mut sub_rules = IndexMap::with_capacity(raw.sub_rules.len());
    for (name, lines) in &raw.sub_rules {
        let mut defs = Vec::with_capacity(lines.len());
        each_checked_rule(
            lines.iter().map(String::as_str),
            &[],
            &format!("sub-rules[{name}]"),
            &ctx,
            &mut report,
            |rule| defs.push(rule),
        )?;
        sub_rules.insert(name.clone(), defs);
    }
    if let Some(cycle) = find_sub_rule_cycle(&sub_rules) {
        return Err(ConfigError::new(format!(
            "sub-rule error: circular references [{}]",
            cycle.join("->")
        )));
    }
    for rule in &dns.fake_ip_filter_rules {
        let mut sets = Vec::new();
        rule.cond.rule_sets(&mut sets);
        if let Some(missing) = sets.into_iter().find(|name| !provider_names.contains(name)) {
            return Err(ConfigError::new(format!(
                "dns.fake-ip-filter [{}] error: rule-set '{missing}' not found",
                rule.text
            )));
        }
    }

    let flag = |map: &Map, key: &str| {
        map.get(key)
            .and_then(crate::lenient::to_bool)
            .unwrap_or(false)
    };
    Ok(Profile {
        general,
        dns,
        tun,
        sniffer,
        hosts,
        geo,
        ntp,
        proxies,
        quarantined_names: names.quarantined,
        quarantined,
        groups,
        refused_groups,
        proxy_providers,
        rule_providers,
        sub_rules,
        store_fake_ip: flag(&raw.profile, "store-fake-ip"),
        dialer_ip4p_convert: flag(&raw.experimental, "dialer-ip4p-convert"),
        refuse_all: false,
        rules: std::mem::take(&mut raw.rules),
        mitm: crate::mitm::load(&raw.mitm, &raw.lines.mitm, &mut report),
        tls: TlsConfig::from_map(&raw.tls),
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "\
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: b, type: trojan, server: example.com, port: 443, password: p}
proxy-groups:
  - {name: g, type: select, proxies: [a, b]}
rules:
  - DOMAIN-SUFFIX,example.com,g
  - MATCH,DIRECT
";

    fn load_text(text: &str) -> Result<Profile> {
        load_str(text, &LoadOptions::default())
    }

    fn error(text: &str) -> String {
        load_text(text).unwrap_err().message
    }

    #[test]
    fn a_plain_profile_loads() {
        let profile = load_text(BASE).unwrap();
        assert_eq!(profile.proxies.len(), 2);
        assert_eq!(profile.rules.len(), 2);
        assert_eq!(profile.groups.len(), 2);
        assert_eq!(profile.groups[1].name, "GLOBAL");
        assert_eq!(
            profile.groups[1].proxies,
            ["DIRECT", "REJECT", "a", "b", "g"]
        );
        assert_eq!(profile.groups[0].url, DEFAULT_TEST_URL);
        assert!(!profile.report.has_warnings());
    }

    #[test]
    fn the_empty_document_loads_on_defaults() {
        let profile = load_text("").unwrap();
        assert!(profile.rules.is_empty());
        assert!(profile.dns.default_nameserver.len() > 1);
        assert!(Profile::rejected_empty().refuse_all);
    }

    #[test]
    fn unsupported_nodes_are_quarantined_and_their_references_dropped() {
        let text = "\
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: ts, type: tailscale}
  - {name: kcp, type: vmess, server: x, port: 1, uuid: u, cipher: auto, network: mkcp}
proxy-groups:
  - {name: mixed, type: select, proxies: [a, ts]}
  - {name: only, type: select, proxies: [ts, kcp]}
rules:
  - MATCH,ts
";
        let profile = load_text(text).unwrap();
        assert_eq!(profile.proxies.len(), 1);
        assert_eq!(profile.quarantined.len(), 2);
        assert!(profile.is_quarantined("ts") && profile.is_quarantined("kcp"));
        assert_eq!(profile.groups[0].proxies, ["a"]);
        assert_eq!(profile.refused_groups, ["only"]);
        assert_eq!(profile.rules.get(0), Some("MATCH,ts"));
        assert!(profile.report.has_warnings());
    }

    #[test]
    fn names_that_never_existed_are_hard_errors() {
        let message = error("proxy-groups:\n  - {name: g, type: select, proxies: [missing]}\n");
        assert!(message.contains("'missing' not found"), "{message}");
        let message = error("rules:\n  - MATCH,nowhere\n");
        assert_eq!(
            message,
            "rules[0] [MATCH,nowhere] error: proxy [nowhere] not found"
        );
        let message = error("rules:\n  - RULE-SET,none,DIRECT\n");
        assert!(message.contains("rule set [none] not found"), "{message}");
        let message = error("rules:\n  - SUB-RULE,(DOMAIN,a.com),nothing\n");
        assert!(
            message.contains("sub-rule [nothing] not found"),
            "{message}"
        );
        let message = error("sub-rules:\n  s:\n    - SUB-RULE,(DOMAIN,a.com),DIRECT\n");
        assert!(message.contains("sub-rule [DIRECT] not found"), "{message}");
        assert!(error("proxies:\n  - {type: direct}\n").contains("proxy 0"));
    }

    #[test]
    fn a_group_in_use_or_global_as_a_member_is_refused_when_loading() {
        let message = error(
            "proxy-groups:\n  - {name: a, type: select, proxies: [DIRECT]}\n  - {name: b, type: select, use: [a]}\n",
        );
        assert!(
            message.ends_with("proxy group a can't contains in `use`"),
            "{message}"
        );
        let message = error("proxy-groups:\n  - {name: g, type: select, proxies: [GLOBAL]}\n");
        assert!(message.ends_with("g: 'GLOBAL' not found"), "{message}");
        assert!(
            load_text(
                "proxy-groups:\n  - {name: GLOBAL, type: select, proxies: [DIRECT]}\n  - {name: g, type: select, proxies: [GLOBAL]}\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn a_value_that_is_refused_names_its_key() {
        let cases = [
            (
                "mode: sideways\n",
                "yaml: unmarshal errors: mode: invalid mode \"sideways\"",
            ),
            (
                "dns: {enhanced-mode: odd}\n",
                "dns.enhanced-mode: invalid mode \"odd\"",
            ),
            (
                "dns: {fake-ip-filter-mode: odd}\n",
                "dns.fake-ip-filter-mode: invalid mode \"odd\"",
            ),
            (
                "dns: {default-nameserver: [1.1.1.1, dns.google]}\n",
                "dns.default-nameserver[1]: default nameserver should be pure IP: dns.google",
            ),
            ("dns: {fake-ip-range: x}\n", "dns.fake-ip-range: "),
            (
                "dns: {nameserver-policy: {'+.a.test': 'gopher://node'}}\n",
                "dns.nameserver-policy[+.a.test]: DNS NameServer[0] format error: unsupport scheme: gopher",
            ),
            ("dns: {enable: x}\n", "'dns.enable' expected type"),
            ("tun: {route-address: [x]}\n", "tun.route-address[0]: "),
            ("hosts: {a.com: [1.1.1.1, x]}\n", "hosts[a.com]: "),
            (
                "sniffer: {sniff: {HTTP: {ports: [abc]}}}\n",
                "sniffer.sniff.HTTP.ports: intRanges error",
            ),
        ];
        for (text, expected) in cases {
            let message = error(text);
            assert!(message.starts_with(expected), "{text}: {message}");
        }
    }

    #[test]
    fn a_tailscale_dns_server_is_skipped_and_a_list_of_only_those_answers_refused() {
        let profile = load_text(
            "dns:\n  nameserver: ['ts://node', 8.8.8.8]\n  nameserver-policy: {'+.ts.net': 'tailscale://node'}\n",
        )
        .unwrap();
        let texts: Vec<&str> = profile
            .dns
            .nameserver
            .iter()
            .map(|ns| ns.text.as_str())
            .collect();
        assert_eq!(texts, ["8.8.8.8"]);
        let policy = &profile.dns.nameserver_policy[0].servers;
        assert_eq!(policy.len(), 1);
        assert_eq!(
            policy[0].scheme,
            crate::dns::UpstreamScheme::Rcode(crate::dns::Rcode::Refused)
        );
        let warned: Vec<(&str, &str)> = profile
            .report
            .warnings
            .iter()
            .map(|w| (w.code, w.path.as_str()))
            .collect();
        assert_eq!(
            warned,
            [
                ("not_applied", "dns.nameserver[0]"),
                ("not_applied", "dns.nameserver-policy[+.ts.net][0]"),
            ]
        );
    }

    #[test]
    fn a_sub_rule_aimed_at_a_proxy_loads_and_never_matches() {
        let profile =
            load_text("rules:\n  - SUB-RULE,(DOMAIN,a.com),DIRECT\n  - MATCH,DIRECT\n").unwrap();
        let noted = profile
            .report
            .warnings
            .iter()
            .find(|w| w.path == "rules[0]")
            .unwrap();
        assert_eq!(noted.code, "rule_never_matches");
        assert_eq!(
            noted.message,
            "SUB-RULE target DIRECT is not a sub-rule, so the rule never matches"
        );
    }

    #[test]
    fn unknown_and_malformed_rules_are_hard_errors() {
        assert!(error("rules:\n  - UNKNOWN-RULE,x,DIRECT\n").contains("rules[0]"));
        assert!(error("rules:\n  - DOMAIN,only\n").contains("format invalid"));
    }

    #[test]
    fn duplicates_and_cycles_are_rejected() {
        let two = "proxies:\n  - {name: a, type: direct}\n  - {name: a, type: direct}\n";
        assert_eq!(error(two), "proxy a is the duplicate name");
        let cycle = "proxy-groups:\n  - {name: a, type: select, proxies: [b]}\n  - {name: b, type: select, proxies: [a]}\n";
        assert!(error(cycle).starts_with("loop is detected in ProxyGroup"));
        let subs = "sub-rules:\n  a: [\"SUB-RULE,(DOMAIN,x.com),b\"]\n  b: [\"SUB-RULE,(DOMAIN,y.com),a\"]\n";
        assert!(error(subs).starts_with("sub-rule error: circular references"));
        let dialer = "proxies:\n  - {name: a, type: direct, dialer-proxy: b}\n  - {name: b, type: direct, dialer-proxy: a}\n";
        assert!(error(dialer).contains("circular dialer-proxy"));
        let missing = "proxies:\n  - {name: a, type: direct, dialer-proxy: zz}\n";
        assert!(error(missing).contains("dialer-proxy [zz] not found"));
    }

    #[test]
    fn dialer_proxy_can_name_a_group() {
        let text = "\
proxies:
  - {name: a, type: direct, dialer-proxy: hop}
  - {name: b, type: direct}
proxy-groups:
  - {name: hop, type: select, proxies: [b]}
";
        let profile = load_text(text).unwrap();
        assert_eq!(profile.proxies[0].common.dialer_proxy, "hop");
    }

    #[test]
    fn include_all_expands_in_sorted_order_with_filters() {
        let text = "\
proxies:
  - {name: hk-2, type: direct}
  - {name: hk-1, type: direct}
  - {name: us-1, type: direct}
proxy-groups:
  - {name: all, type: url-test, include-all-proxies: true, filter: hk}
";
        let profile = load_text(text).unwrap();
        assert_eq!(profile.groups[0].proxies, ["hk-1", "hk-2"]);
        assert_eq!(profile.groups[0].interval, 300);
    }

    fn warned_paths(text: &str, android: bool) -> Vec<String> {
        let options = LoadOptions {
            android,
            ..LoadOptions::default()
        };
        let profile = load_str(text, &options).unwrap();
        profile
            .report
            .warnings
            .iter()
            .map(|warning| warning.path.clone())
            .collect()
    }

    #[test]
    fn a_tun_stack_that_is_not_run_as_named_is_warned() {
        for stack in ["mixed", "System"] {
            let text = format!("tun:\n  enable: true\n  stack: {stack}\n");
            assert_eq!(warned_paths(&text, false), ["tun.stack"], "{stack}");
            assert!(warned_paths(&text, true).is_empty(), "{stack} on android");
        }
        assert!(warned_paths("tun:\n  enable: true\n  stack: mips\n", false).is_empty());
        assert!(warned_paths("tun:\n  enable: false\n  stack: system\n", false).is_empty());
        assert!(warned_paths("tun:\n  enable: true\n  gso: true\n", false).is_empty());
    }

    #[test]
    fn a_rule_provider_path_in_bundle_is_warned_and_the_provider_kept() {
        let text = "rule-providers:\n  cn: {type: http, behavior: domain, format: mrs, url: \"https://a.test/cn.mrs\", path: ./cn.mrs, path-in-bundle: geo/geosite/cn.mrs}\n  \
                    own: {type: inline, behavior: domain, payload: [a.test], path-in-bundle: x}\n\
                    rules:\n  - RULE-SET,cn,DIRECT\n  - RULE-SET,own,DIRECT\n  - MATCH,DIRECT\n";
        let profile = load_text(text).unwrap();
        assert_eq!(profile.rule_providers.len(), 2);
        let warned: Vec<_> = profile
            .report
            .warnings
            .iter()
            .map(|w| (w.code, w.path.as_str()))
            .collect();
        assert_eq!(
            warned,
            [("not_applied", "rule-providers.cn.path-in-bundle")]
        );
    }

    #[test]
    fn a_key_written_with_no_value_reads_as_mihomo_reads_it() {
        let text = "tun:\n  enable: true\n  auto-route:\n  route-exclude-address:\n\
                    dns:\n  enable: true\n  nameserver: [8.8.8.8]\n  enhanced-mode: fake-ip\n  fake-ip-range:\n\
                    proxies:\n  - {name: n, type: ss, server: s.test, port: 8388, cipher: none, password: }\n";
        let profile = load_text(text).unwrap();
        assert!(profile.tun.auto_route);
        assert!(profile.tun.route_exclude_address.is_empty());
        assert_eq!(
            profile
                .dns
                .fake_ip_range
                .map(|range| range.to_string())
                .as_deref(),
            Some("198.18.0.1/16")
        );
        assert_eq!(profile.proxies.len(), 1);
    }

    #[test]
    fn a_number_out_of_range_falls_back_with_a_warning() {
        let text = "mixed-port: 70000\nport: -1\nkeep-alive-idle: -1\ngeo-update-interval: -1\n\
                    ntp: {enable: true, port: 70000, interval: -5}\n\
                    dns: {fake-ip-ttl: -1, cache-max-size: 3000000000, listen-routing-mark: -1, ipv6-timeout: 5000000000}\n";
        let profile = load_text(text).unwrap();
        let general = &profile.general;
        assert_eq!((general.mixed_port, general.port), (0, 0));
        assert_eq!(
            (general.keep_alive_idle, general.geo_update_interval),
            (0, 24)
        );
        assert_eq!((profile.ntp.port, profile.ntp.interval), (123, 30));
        let dns = &profile.dns;
        assert_eq!(
            (dns.fake_ip_ttl, dns.ipv6_timeout, dns.cache_max_size),
            (1, 100, 0)
        );
        assert_eq!(dns.listen_routing_mark, u32::MAX);
        let warned: Vec<(&str, &str)> = profile
            .report
            .warnings
            .iter()
            .map(|warning| (warning.code, warning.path.as_str()))
            .collect();
        for path in [
            "port",
            "mixed-port",
            "keep-alive-idle",
            "geo-update-interval",
            "dns.ipv6-timeout",
            "dns.fake-ip-ttl",
            "dns.cache-max-size",
            "ntp.port",
            "ntp.interval",
        ] {
            assert!(
                warned.contains(&("out_of_range", path)),
                "{path}: {warned:?}"
            );
        }
        let message = &profile
            .report
            .warnings
            .iter()
            .find(|w| w.path == "mixed-port")
            .unwrap()
            .message;
        assert_eq!(message, "mixed-port is ignored: 70000 is out of range");
    }

    #[test]
    fn an_include_all_group_names_the_set_aside_nodes_it_lost() {
        let profile = load_text(
            "proxies:\n  - {name: hk-a, type: socks5, server: 127.0.0.1, port: 1}\n  - {name: hk-b, type: tailscale}\n\
             proxy-groups:\n  - {name: HK, type: select, include-all-proxies: true, filter: hk}\n  \
             - {name: TS, type: select, include-all-proxies: true, filter: hk-b, empty-fallback: DIRECT}\n",
        )
        .unwrap();
        let dropped: Vec<(&str, &str)> = profile
            .report
            .warnings
            .iter()
            .filter(|w| w.code == "group_members_dropped")
            .map(|w| (w.path.as_str(), w.message.as_str()))
            .collect();
        assert_eq!(
            dropped,
            [
                ("proxy-groups.HK", "dropped quarantined members: hk-b"),
                ("proxy-groups.TS", "dropped quarantined members: hk-b"),
            ]
        );
        let ts = profile.groups.iter().find(|g| g.name == "TS").unwrap();
        assert_eq!(ts.proxies, ["DIRECT"]);
    }

    #[test]
    fn a_dialing_key_on_a_group_is_ignored_with_a_warning() {
        let profile = load_text(
            "proxy-groups:\n  - {name: g, type: select, proxies: [DIRECT], routing-mark: 7, dialer-proxy: x, interface-name: ''}\n",
        )
        .unwrap();
        let warned: Vec<(&str, &str, &str)> = profile
            .report
            .warnings
            .iter()
            .map(|w| (w.code, w.path.as_str(), w.message.as_str()))
            .collect();
        assert_eq!(
            warned,
            [
                (
                    "not_applied",
                    "proxy-groups.g.routing-mark",
                    "routing-mark is ignored: a group does not dial, so set it on the nodes"
                ),
                (
                    "not_applied",
                    "proxy-groups.g.dialer-proxy",
                    "dialer-proxy is ignored: a group does not dial, so set it on the nodes"
                ),
            ]
        );
    }

    #[test]
    fn inbound_tfo_asks_for_something_the_core_does_not_do() {
        assert!(
            warned_paths(
                "skip-auth-prefixes: [127.0.0.1/8]\ninbound-tfo: null\n",
                false
            )
            .is_empty()
        );
        assert_eq!(warned_paths("inbound-tfo: true\n", false), ["inbound-tfo"]);
    }

    #[test]
    fn a_dhcp_interface_upstream_is_warned_once_per_key() {
        let text = "dns:\n  enable: true\n  nameserver: [\"dhcp://en0\", \"dhcp://en0\", 8.8.8.8]\n  fallback: [\"dhcp://en1\"]\n";
        let profile = load_str(text, &LoadOptions::default()).unwrap();
        let warned: Vec<_> = profile
            .report
            .warnings
            .iter()
            .map(|w| (w.path.as_str(), w.message.as_str()))
            .collect();
        assert_eq!(
            warned,
            [
                (
                    "dns.nameserver",
                    "dhcp://en0 is treated as system://: no DHCP client runs and the servers are not bound to en0"
                ),
                (
                    "dns.fallback",
                    "dhcp://en1 is treated as system://: no DHCP client runs and the servers are not bound to en1"
                ),
            ]
        );
        assert!(
            warned_paths(
                "dns:\n  enable: false\n  nameserver: [\"dhcp://en0\"]\n",
                false
            )
            .is_empty()
        );
    }

    #[test]
    fn rules_that_can_never_match_are_noted_once_per_list() {
        let text = "sub-rules:\n  s:\n    - DOMAIN,a.test,DIRECT\n\
                    rules:\n  - DOMAIN,*.a.test,DIRECT\n  - DOMAIN-SUFFIX,+.b.test,DIRECT\n  - DOMAIN-WILDCARD,*.c.test,DIRECT\n  - DOMAIN,d.test,DIRECT\n  - MATCH,DIRECT\n  - DOMAIN,e.test,DIRECT\n  - DOMAIN,*.f.test,DIRECT\n";
        let profile = load_text(text).unwrap();
        let notes: Vec<(&str, &str)> = profile
            .report
            .warnings
            .iter()
            .filter(|warning| warning.level == crate::report::Level::Info)
            .map(|warning| (warning.path.as_str(), warning.message.as_str()))
            .collect();
        assert_eq!(
            notes,
            [
                ("rules", "2 rules after MATCH are never reached"),
                (
                    "rules",
                    "[DOMAIN,*.a.test,DIRECT] and 1 more never match: DOMAIN and DOMAIN-SUFFIX take \
                     no wildcard, use DOMAIN-WILDCARD"
                ),
            ]
        );
    }

    #[test]
    fn a_node_option_the_core_reads_differently_is_warned_under_its_node() {
        let text = "proxies:\n  - {name: a, type: trojan, server: h.test, port: 443, password: p, client-fingerprint: chrome_pq}\n";
        let profile = load_text(text).unwrap();
        assert_eq!(profile.proxies.len(), 1);
        let warning = &profile.report.warnings[0];
        assert_eq!(
            (warning.code, warning.path.as_str()),
            ("proxy_option", "proxies[0]")
        );
        assert_eq!(
            warning.message,
            "a: client-fingerprint `chrome_pq` is deprecated and is treated as `chrome`"
        );
    }

    #[test]
    fn settings_that_are_not_applied_are_warned_unless_they_are_the_defaults() {
        assert!(
            warned_paths(
                "experimental:\n  quic-go-disable-gso: false\n  quic-go-disable-ecn: true\ntls:\n  certificate: \"\"\n  custom-certifactes: []\n",
                false
            )
            .is_empty()
        );
        assert_eq!(
            warned_paths("experimental:\n  quic-go-disable-ecn: false\n", false),
            ["experimental"]
        );
        assert_eq!(
            warned_paths("tls:\n  certificate: server.crt\n  ech-key: k\n", false),
            ["tls.certificate", "tls.ech-key"]
        );
    }

    #[test]
    fn an_inline_provider_is_read_after_its_filters_and_overrides() {
        let text = "proxy-providers:\n  p:\n    type: inline\n    exclude-type: ssh\n    \
                    override: {up: 50 Mbps, down: 200 Mbps}\n    payload:\n      \
                    - {name: h, type: hysteria, server: s.test, port: 443}\n      \
                    - {name: bad, type: ssh, server: s.test}\n      \
                    - {type: ss, server: s.test}\n\
                    proxy-groups:\n  - {name: G, type: select, use: [p]}\nrules:\n  - MATCH,G\n";
        let profile = load_text(text).unwrap();
        assert!(profile.report.warnings.is_empty(), "{:?}", profile.report);
    }

    #[test]
    fn a_provider_with_override_expr_is_emptied_and_the_profile_still_loads() {
        let profile = load_text(
            "proxy-providers:\n  sub:\n    type: http\n    url: https://example.com/s\n    path: s.yaml\n    override:\n      override-expr:\n        - '.udp = true'\nproxy-groups:\n  - {name: G, type: select, use: [sub]}\nrules:\n  - MATCH,G\n",
        )
        .unwrap();
        assert_eq!(
            profile.proxy_providers[0].source,
            ProxySource::Inline {
                payload: Vec::new()
            }
        );
        assert!(
            warned_paths(
                "proxy-providers:\n  sub:\n    type: inline\n    override:\n      override-expr: ['.udp = true']\n",
                false
            )
            .contains(&"proxy-providers.sub".to_string())
        );
    }

    #[test]
    fn a_restricted_lan_loads_without_a_warning() {
        let text = "allow-lan: true\nbind-address: 192.168.1.2\nlan-allowed-ips: [192.168.0.0/16]\nlan-disallowed-ips: [192.168.1.1/32]\n";
        assert!(warned_paths(text, false).is_empty());
        assert_eq!(load_text(text).unwrap().general.lan_allowed_ips.len(), 1);
    }

    #[test]
    fn asking_for_geoip_dat_warns() {
        let warned = |text: &str| -> Vec<String> {
            load_text(text)
                .unwrap()
                .report
                .warnings
                .iter()
                .map(|warning| warning.path.clone())
                .collect()
        };
        assert_eq!(warned("geodata-mode: true\n"), ["geodata-mode"]);
        assert!(warned("geodata-mode: false\n").is_empty());
        assert_eq!(
            warned("geox-url:\n  geoip: http://x/geoip.dat\n"),
            ["geox-url.geoip"]
        );
    }

    #[test]
    fn tier_two_sections_warn_and_are_never_opened() {
        let profile =
            load_text("listeners:\n  - {name: l, type: socks, port: 1}\ntunnels: [tcp]\n").unwrap();
        let report = profile.report.to_json();
        let warned: Vec<&str> = report
            .as_array()
            .map(|items| items.iter().filter_map(|w| w["path"].as_str()).collect())
            .unwrap_or_default();
        assert!(
            warned.contains(&"listeners") && warned.contains(&"tunnels"),
            "{warned:?}"
        );
    }

    #[test]
    fn providers_and_the_reserved_name() {
        let text = "\
proxy-providers:
  sub: {type: http, url: 'https://x/sub', path: ./sub.yaml}
  inline:
    type: inline
    payload:
      - {name: c, type: socks5, server: 127.0.0.3, port: 1080}
      - {name: d, type: tailscale}
proxy-groups:
  - {name: g, type: select, use: [sub]}
";
        let profile = load_text(text).unwrap();
        assert_eq!(profile.proxy_providers.len(), 2);
        assert_eq!(profile.quarantined[0].provider.as_deref(), Some("inline"));
        assert!(
            error("proxy-groups:\n  - {name: g, type: select, use: [none]}\n")
                .contains("'none' not found")
        );
    }

    #[test]
    fn default_is_the_reserved_provider_name_as_in_mihomo() {
        assert!(
            error("proxy-providers:\n  default: {type: file, path: a}\n")
                .contains("can not defined a provider called `default`")
        );
        assert!(
            error("proxy-groups:\n  - {name: g, type: select, use: [default]}\n")
                .contains("proxy group default can't contains in `use`")
        );
        let profile = load_text(
            "proxy-providers:\n  COMPATIBLE:\n    type: inline\n    payload:\n      \
             - {name: c, type: socks5, server: 127.0.0.3, port: 1080}\n\
             proxy-groups:\n  - {name: g, type: select, use: [COMPATIBLE]}\n",
        )
        .unwrap();
        assert_eq!(profile.proxy_providers[0].name, "COMPATIBLE");
    }

    #[test]
    fn a_dns_section_with_a_proxy_pointing_nowhere_still_loads() {
        let profile = load_text(
            "dns:\n  enable: true\n  nameserver: ['https://dns.google/dns-query#proxy-x']\n",
        )
        .unwrap();
        assert_eq!(
            profile.dns.upstream_proxy_names().collect::<Vec<_>>(),
            ["proxy-x"]
        );
    }
}
