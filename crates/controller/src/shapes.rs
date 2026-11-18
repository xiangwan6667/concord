//! Concord's API types in the JSON shapes of the Clash API, as mihomo's controller writes them.

use std::collections::HashMap;

use concord_api::local_utc_offset;
use concord_proto::types::{
    ConnectionInfo, DelayRecord, DnsQueryResult, DnsRecord, GeneralState, GroupInfo, LogLevel,
    NodeInfo, ProviderInfo, ProxyGroups, ProxyState, RuleEntry,
};
use serde_json::{Map, Value, json};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// Go's zero `time.Time`, which mihomo writes for a provider never updated.
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

pub fn time(millis: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .ok()
        .and_then(|at| at.format(&Rfc3339).ok())
        .unwrap_or_else(|| ZERO_TIME.to_string())
}

fn history(records: &[DelayRecord]) -> Value {
    Value::Array(
        records
            .iter()
            .map(|record| json!({ "time": time(record.time), "delay": record.delay }))
            .collect(),
    )
}

/// `adapter.go` `Proxy.MarshalJSON` over the adapter's own fields.
fn base(
    name: &str,
    kind: &str,
    provider: Option<&str>,
    state: Option<&ProxyState>,
) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("name".into(), json!(name));
    map.insert("type".into(), json!(kind));
    map.insert("udp".into(), json!(state.is_some_and(|state| state.udp)));
    map.insert("uot".into(), json!(false));
    map.insert("xudp".into(), json!(false));
    map.insert("tfo".into(), json!(false));
    map.insert("mptcp".into(), json!(false));
    map.insert("smux".into(), json!(false));
    map.insert("interface".into(), json!(""));
    map.insert("routing-mark".into(), json!(0));
    map.insert("provider-name".into(), json!(provider.unwrap_or_default()));
    map.insert("dialer-proxy".into(), json!(""));
    map.insert("alive".into(), json!(state.is_none_or(|state| state.alive)));
    map.insert(
        "history".into(),
        state.map_or(json!([]), |state| history(&state.history)),
    );
    let extra: Map<String, Value> = state
        .map(|state| {
            state
                .extra
                .iter()
                .map(|url| {
                    (
                        url.url.clone(),
                        json!({ "alive": url.alive, "history": history(&url.history) }),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    map.insert("extra".into(), Value::Object(extra));
    map
}

/// `outbound/base.go:131` adds `id` for a node; groups write none.
pub fn node(info: &NodeInfo, state: Option<&ProxyState>) -> Value {
    let mut map = base(&info.name, &info.kind, info.provider.as_deref(), state);
    map.insert("id".into(), json!(""));
    Value::Object(map)
}

/// `selector.go` and `urltest.go` `MarshalJSON`: `fixed` and `expectedStatus`
/// only on the kinds that have them.
pub fn group(info: &GroupInfo, state: Option<&ProxyState>) -> Value {
    let mut map = base(&info.name, &info.kind, None, state);
    map.insert("now".into(), json!(info.now.clone().unwrap_or_default()));
    map.insert("all".into(), json!(info.all.clone().unwrap_or_default()));
    map.insert("testUrl".into(), json!(info.test_url));
    map.insert("hidden".into(), json!(info.hidden));
    map.insert("icon".into(), json!(info.icon));
    map.insert("emptyFallback".into(), json!(info.empty_fallback));
    if let Some(expected) = &info.expected_status {
        map.insert("expectedStatus".into(), json!(expected));
    }
    if let Some(fixed) = &info.fixed {
        map.insert("fixed".into(), json!(fixed));
    }
    Value::Object(map)
}

/// Every name `proxies` can answer for, as mihomo's `tunnel.Proxies()`.
pub struct Catalog {
    pub groups: ProxyGroups,
    pub states: HashMap<String, ProxyState>,
}

impl Catalog {
    pub fn new(groups: ProxyGroups, states: Vec<ProxyState>) -> Self {
        Catalog {
            groups,
            states: states
                .into_iter()
                .map(|state| (state.name.clone(), state))
                .collect(),
        }
    }

    pub fn group(&self, name: &str) -> Option<&GroupInfo> {
        self.groups.groups.iter().find(|group| group.name == name)
    }

    pub fn get(&self, name: &str) -> Option<Value> {
        if let Some(info) = self.group(name) {
            return Some(group(info, self.states.get(name)));
        }
        let info = self.groups.nodes.iter().find(|node| node.name == name)?;
        Some(node(info, self.states.get(name)))
    }

    pub fn all(&self) -> Value {
        let mut map = Map::new();
        for info in &self.groups.nodes {
            map.insert(info.name.clone(), node(info, self.states.get(&info.name)));
        }
        for info in &self.groups.groups {
            map.insert(info.name.clone(), group(info, self.states.get(&info.name)));
        }
        json!({ "proxies": map })
    }

    pub fn groups_only(&self) -> Value {
        let list: Vec<Value> = self
            .groups
            .groups
            .iter()
            .map(|info| group(info, self.states.get(&info.name)))
            .collect();
        json!({ "proxies": list })
    }

    /// A member of `default_provider`.
    pub fn default_member(&self, name: &str) -> Option<Value> {
        if name == "GLOBAL" {
            return None;
        }
        if let Some(info) = self.group(name) {
            return Some(group(info, self.states.get(name)));
        }
        let info = self
            .groups
            .nodes
            .iter()
            .find(|node| node.name == name && node.provider.is_none())?;
        Some(node(info, self.states.get(name)))
    }

    fn provider_nodes(&self, provider: Option<&str>) -> Vec<Value> {
        self.groups
            .nodes
            .iter()
            .filter(|info| info.provider.as_deref() == provider)
            .map(|info| node(info, self.states.get(&info.name)))
            .collect()
    }

    pub fn provider(&self, info: &ProviderInfo) -> Value {
        let mut map = Map::new();
        map.insert("name".into(), json!(info.name));
        map.insert("type".into(), json!("Proxy"));
        map.insert("vehicleType".into(), json!(info.vehicle_type));
        map.insert(
            "proxies".into(),
            Value::Array(self.provider_nodes(Some(&info.name))),
        );
        map.insert(
            "testUrl".into(),
            json!(info.test_url.clone().unwrap_or_default()),
        );
        map.insert(
            "expectedStatus".into(),
            json!(info.expected_status.clone().unwrap_or_default()),
        );
        map.insert(
            "updatedAt".into(),
            json!(info.updated_at.map_or_else(|| ZERO_TIME.to_string(), time)),
        );
        if let Some(sub) = &info.subscription_info {
            map.insert(
                "subscriptionInfo".into(),
                json!({
                    "Upload": sub.upload,
                    "Download": sub.download,
                    "Total": sub.total,
                    "Expire": sub.expire,
                }),
            );
        }
        Value::Object(map)
    }

    /// mihomo's reserved `default` provider: the profile's own proxies and groups
    /// (`config/config.go:967-976`).
    pub fn default_provider(&self) -> Value {
        let mut proxies = self.provider_nodes(None);
        proxies.extend(
            self.groups
                .groups
                .iter()
                .filter(|info| info.name != "GLOBAL")
                .map(|info| group(info, self.states.get(&info.name))),
        );
        json!({
            "name": "default",
            "type": "Proxy",
            "vehicleType": "Compatible",
            "proxies": proxies,
            "testUrl": "",
            "expectedStatus": "*",
            "updatedAt": ZERO_TIME,
        })
    }
}

pub fn rule_provider(info: &ProviderInfo) -> Value {
    let behavior = match info.behavior.as_deref() {
        Some("domain") => "Domain",
        Some("ipcidr") => "IPCIDR",
        Some("classical") => "Classical",
        _ => "Unknown",
    };
    let format = match info.format.as_deref() {
        Some("yaml") => "YamlRule",
        Some("text" | "domain-set") => "TextRule",
        Some("mrs") => "MrsRule",
        _ => "Unknown",
    };
    json!({
        "behavior": behavior,
        "format": format,
        "name": info.name,
        "ruleCount": info.count,
        "type": "Rule",
        "vehicleType": info.vehicle_type,
        "updatedAt": info.updated_at.map_or_else(|| ZERO_TIME.to_string(), time),
    })
}

pub fn rules(rules: &[RuleEntry]) -> Value {
    let list: Vec<Value> = rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            json!({
                "index": index,
                "type": rule.kind,
                "payload": rule.payload,
                "proxy": rule.target,
                "size": -1,
            })
        })
        .collect();
    json!({ "rules": list })
}

fn level(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warning => "warning",
        LogLevel::Error => "error",
        LogLevel::Silent => "silent",
    }
}

pub fn parse_level(text: &str) -> Option<LogLevel> {
    match text {
        "debug" => Some(LogLevel::Debug),
        "info" => Some(LogLevel::Info),
        "warning" => Some(LogLevel::Warning),
        "error" => Some(LogLevel::Error),
        "silent" => Some(LogLevel::Silent),
        _ => None,
    }
}

/// The structured form's `time` is local, as `hub/route/server.go:549` writes it.
pub fn log(entry_level: LogLevel, millis: i64, text: &str, structured: bool) -> Value {
    if !structured {
        return json!({ "type": level(entry_level), "payload": text });
    }
    let at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let offset = UtcOffset::from_whole_seconds(local_utc_offset(at.unix_timestamp()))
        .unwrap_or(UtcOffset::UTC);
    let at = at.to_offset(offset);
    let name = match entry_level {
        LogLevel::Warning => "warn",
        other => level(other),
    };
    json!({
        "time": format!("{:02}:{:02}:{:02}", at.hour(), at.minute(), at.second()),
        "level": name,
        "message": text,
        "fields": [],
    })
}

/// `hub/executor.GetGeneral` with mihomo's names; what Concord has no setting
/// for keeps mihomo's zero value.
pub fn configs(state: &GeneralState) -> Value {
    let geo = |key: &str| state.geox_url.get(key).cloned().unwrap_or_default();
    let mut general = json!({
        "port": state.port,
        "socks-port": state.socks_port,
        "redir-port": state.redir_port,
        "tproxy-port": state.tproxy_port,
        "mixed-port": state.mixed_port,
        "tun": {
            "enable": state.tun.enable,
            "device": state.tun.device,
            "stack": state.tun.stack,
            "dns-hijack": state.tun.dns_hijack,
            "auto-route": state.tun.auto_route,
            "auto-detect-interface": state.tun.auto_detect_interface,
            "dns-mode": "",
            "file-descriptor": 0,
        },
        "tuic-server": {
            "enable": false,
            "listen": "",
            "certificate": "",
            "private-key": "",
            "ech-key": "",
            "mux-option": { "brutal": { "enabled": false } },
        },
        "ss-config": "",
        "vmess-config": "",
        "authentication": state.authentication,
        "skip-auth-prefixes": state.skip_auth_prefixes,
        "lan-allowed-ips": state.lan_allowed_ips,
        "lan-disallowed-ips": state.lan_disallowed_ips,
        "allow-lan": state.allow_lan,
        "bind-address": state.bind_address,
        "inbound-tfo": false,
        "inbound-mptcp": false,
        "mode": state.mode,
        "unified-delay": state.unified_delay,
        "log-level": level(state.log_level),
        "ipv6": state.ipv6,
        "interface-name": state.interface_name,
        "routing-mark": state.routing_mark,
        "geox-url": {
            "geo-ip": "",
            "mmdb": geo("mmdb"),
            "asn": geo("asn"),
            "geo-site": geo("geosite"),
        },
        "geo-auto-update": state.geo_auto_update,
        "geo-update-interval": state.geo_update_interval,
        "geodata-mode": false,
        "geodata-loader": "memconservative",
        "geosite-matcher": "",
        "tcp-concurrent": state.tcp_concurrent,
        "find-process-mode": state.find_process_mode,
        "sniffing": state.sniffing,
        "global-ua": state.global_ua,
        "etag-support": false,
        "keep-alive-idle": state.keep_alive_idle,
        "keep-alive-interval": state.keep_alive_interval,
        "disable-keep-alive": state.disable_keep_alive,
    });
    if state.tun.mtu != 0 {
        general["tun"]["mtu"] = json!(state.tun.mtu);
    }
    general
}

/// `statistic.TrackerInfo` with `C.Metadata`: ports are strings, as mihomo
/// keeps them for old dashboards (`constant/metadata.go:199-202`).
pub fn connection(info: &ConnectionInfo) -> Value {
    json!({
        "id": info.id.to_string(),
        "metadata": {
            "network": info.network,
            "type": info.inbound_type,
            "sourceIP": info.source_ip,
            "destinationIP": info.destination_ip.clone().unwrap_or_default(),
            "sourceGeoIP": info.source_geo_ip,
            "destinationGeoIP": info.destination_geo_ip,
            "sourceIPASN": info.source_asn.clone().unwrap_or_default(),
            "destinationIPASN": info.destination_asn.clone().unwrap_or_default(),
            "sourcePort": info.source_port.to_string(),
            "destinationPort": info.destination_port.to_string(),
            "inboundIP": info.inbound_ip.clone().unwrap_or_default(),
            "inboundPort": info.inbound_port.unwrap_or_default().to_string(),
            "inboundName": info.inbound_name.clone().unwrap_or_default(),
            "inboundUser": info.inbound_user.clone().unwrap_or_default(),
            "rematchName": info.rematch_name.clone().unwrap_or_default(),
            "host": info.host.clone().unwrap_or_default(),
            "dnsMode": info.dns_mode.clone().unwrap_or_else(|| "normal".to_string()),
            "uid": info.uid.unwrap_or_default(),
            "process": info.process.clone().unwrap_or_default(),
            "processPath": info.process_path.clone().unwrap_or_default(),
            "specialProxy": info.special_proxy.clone().unwrap_or_default(),
            "specialRules": info.special_rules.clone().unwrap_or_default(),
            "remoteDestination": info.remote_destination.clone().unwrap_or_default(),
            "dscp": 0,
            "sniffHost": info.sniff_host.clone().unwrap_or_default(),
        },
        "upload": info.upload,
        "download": info.download,
        "start": time(info.start),
        "chains": info.chains,
        "providerChains": info.provider_chains,
        "rule": info.rule,
        "rulePayload": info.rule_payload,
    })
}

pub fn snapshot<'a>(
    connections: impl Iterator<Item = &'a ConnectionInfo>,
    upload_total: i64,
    download_total: i64,
    memory: u64,
) -> Value {
    let list: Vec<Value> = connections.map(connection).collect();
    json!({
        "downloadTotal": download_total,
        "uploadTotal": upload_total,
        "connections": list,
        "memory": memory,
    })
}

fn dns_records(records: &[DnsRecord]) -> Value {
    Value::Array(
        records
            .iter()
            .map(|record| {
                json!({
                    "name": record.name,
                    "type": record.rtype,
                    "TTL": record.ttl,
                    "data": record.data,
                })
            })
            .collect(),
    )
}

/// `hub/route/dns.go`: the sections appear only when they hold records.
pub fn dns(result: &DnsQueryResult) -> Value {
    let mut map = Map::new();
    map.insert("Status".into(), json!(result.rcode));
    map.insert(
        "Question".into(),
        Value::Array(
            result
                .questions
                .iter()
                .map(|q| json!({ "Name": q.name, "Qtype": q.qtype, "Qclass": q.qclass }))
                .collect(),
        ),
    );
    map.insert("TC".into(), json!(result.truncated));
    map.insert("RD".into(), json!(result.recursion_desired));
    map.insert("RA".into(), json!(result.recursion_available));
    map.insert("AD".into(), json!(result.authentic_data));
    map.insert("CD".into(), json!(result.checking_disabled));
    for (key, records) in [
        ("Answer", &result.answers),
        ("Authority", &result.authorities),
        ("Additional", &result.additionals),
    ] {
        if !records.is_empty() {
            map.insert(key.into(), dns_records(records));
        }
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rematch_name_reaches_clash_connection_metadata() {
        let mut info: ConnectionInfo = serde_json::from_value(json!({
            "id": 1, "start": 0, "network": "tcp", "sourceIp": "127.0.0.1",
            "sourcePort": 1, "destinationPort": 443, "inboundType": "socks5",
            "chains": ["DIRECT"], "rule": "RematchName", "upload": 0, "download": 0,
            "rematchName": "Next"
        }))
        .unwrap();
        assert_eq!(connection(&info)["metadata"]["rematchName"], "Next");
        info.rematch_name = None;
        assert_eq!(connection(&info)["metadata"]["rematchName"], "");
    }

    #[test]
    fn times_are_rfc3339_in_utc() {
        assert_eq!(time(0), "1970-01-01T00:00:00Z");
        assert_eq!(time(1_500), "1970-01-01T00:00:01.5Z");
    }

    #[test]
    fn rule_provider_names_follow_mihomo() {
        let info = ProviderInfo {
            name: "r".into(),
            kind: concord_proto::types::ProviderKind::Rule,
            vehicle_type: "HTTP".into(),
            count: 3,
            path: String::new(),
            updated_at: None,
            subscription_info: None,
            test_url: None,
            expected_status: None,
            behavior: Some("ipcidr".into()),
            format: Some("mrs".into()),
        };
        let value = rule_provider(&info);
        assert_eq!(value["behavior"], "IPCIDR");
        assert_eq!(value["format"], "MrsRule");
        assert_eq!(value["ruleCount"], 3);
        assert_eq!(value["updatedAt"], ZERO_TIME);
    }

    #[test]
    fn a_structured_log_says_warn_at_the_local_time_of_day() {
        let millis = 1_700_000_000_123;
        let value = log(LogLevel::Warning, millis, "x", true);
        assert_eq!(value["level"], "warn");
        assert_eq!(value["fields"], json!([]));
        let local = 1_700_000_000 + i64::from(local_utc_offset(1_700_000_000));
        let seconds = local.rem_euclid(86_400);
        let expected = format!(
            "{:02}:{:02}:{:02}",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        );
        assert_eq!(value["time"], expected);
        assert_eq!(
            log(LogLevel::Warning, millis, "x", false)["type"],
            "warning"
        );
    }
}
