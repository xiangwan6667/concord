use serde_json::{Value, json};

use crate::Map;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    T0,
    T1,
    T2,
    Inert,
}

pub struct Tiers {
    pub t0: &'static [&'static str],
    pub t1: &'static [&'static str],
    pub t2: &'static [&'static str],
    pub inert: &'static [&'static str],
}

impl Tiers {
    pub fn of(&self, key: &str) -> Option<Tier> {
        [
            (self.t0, Tier::T0),
            (self.t1, Tier::T1),
            (self.t2, Tier::T2),
            (self.inert, Tier::Inert),
        ]
        .into_iter()
        .find(|(keys, _)| keys.contains(&key))
        .map(|(_, tier)| tier)
    }
}

const fn tiers(
    t0: &'static [&'static str],
    t1: &'static [&'static str],
    t2: &'static [&'static str],
    inert: &'static [&'static str],
) -> Tiers {
    Tiers { t0, t1, t2, inert }
}

/// mihomo's `geodata.SetLoader` only picks how much of a `.dat` file stays in memory.
const TOP_INERT: &[&str] = &["geodata-loader"];

/// The host saves the selected nodes and hands them back with each profile it applies.
const PROFILE_INERT: &[&str] = &["store-selected"];

pub const TOP: Tiers = tiers(TOP_T0, TOP_T1, TOP_T2, TOP_INERT);
pub const DNS: Tiers = tiers(DNS_T0, DNS_T1, &[], &[]);
pub const FALLBACK_FILTER_TIERS: Tiers = tiers(FALLBACK_FILTER, &[], &[], &[]);
pub const TUN: Tiers = tiers(TUN_T0, TUN_T1, TUN_T2, &[]);
pub const SNIFFER: Tiers = tiers(SNIFFER_T0, SNIFFER_T1, SNIFFER_T2, &[]);
pub const NTP: Tiers = tiers(NTP_KEYS, &[], &[], &[]);
pub const GEOX: Tiers = tiers(GEOX_KEYS, &[], GEOX_T2, &[]);
pub const PROFILE: Tiers = tiers(&["store-fake-ip"], &[], &[], PROFILE_INERT);
pub const GROUP: Tiers = tiers(
    GROUP_T0,
    &[],
    &["routing-mark", "interface-name", "dialer-proxy"],
    &[],
);

pub const GROUP_T0: &[&str] = &[
    "name",
    "type",
    "proxies",
    "use",
    "use-position",
    "url",
    "interval",
    "timeout",
    "max-failed-times",
    "empty-fallback",
    "lazy",
    "disable-udp",
    "filter",
    "exclude-filter",
    "exclude-type",
    "expected-status",
    "include-all",
    "include-all-proxies",
    "include-all-providers",
    "hidden",
    "icon",
    "tolerance",
    "default-selected",
    "strategy",
    "hash-key",
];

pub const SECTIONS: [(&str, &Tiers); 8] = [
    ("", &TOP),
    ("dns", &DNS),
    ("dns.fallback-filter", &FALLBACK_FILTER_TIERS),
    ("tun", &TUN),
    ("sniffer", &SNIFFER),
    ("ntp", &NTP),
    ("geox-url", &GEOX),
    ("profile", &PROFILE),
];

pub const TOP_T0: &[&str] = &[
    "mixed-port",
    "port",
    "socks-port",
    "allow-lan",
    "authentication",
    "skip-auth-prefixes",
    "mode",
    "log-level",
    "ipv6",
    "unified-delay",
    "tcp-concurrent",
    "find-process-mode",
    "interface-name",
    "routing-mark",
    "keep-alive-idle",
    "keep-alive-interval",
    "disable-keep-alive",
    "global-ua",
    "proxies",
    "proxy-groups",
    "proxy-providers",
    "rule-providers",
    "rules",
    "dns",
    "tun",
    "sniffer",
    "hosts",
    "geox-url",
    "geo-auto-update",
    "geo-update-interval",
    "profile",
    "mitm",
];

pub const TOP_T1: &[&str] = &[
    "redir-port",
    "tproxy-port",
    "sub-rules",
    "ntp",
    "tls",
    "experimental",
    "external-controller",
    "secret",
    "external-controller-cors",
    "bind-address",
    "lan-allowed-ips",
    "lan-disallowed-ips",
];

pub const TOP_T2: &[&str] = &[
    "geodata-mode",
    "listeners",
    "tunnels",
    "ss-config",
    "vmess-config",
    "tuic-server",
    "iptables",
    "clash-for-android",
    "inbound-tfo",
    "inbound-mptcp",
    "external-controller-pipe",
    "external-controller-unix",
    "external-controller-tls",
    "external-controller-routing-mark",
    "external-ui",
    "external-ui-url",
    "external-ui-name",
    "external-doh-server",
    "geosite-matcher",
    "etag-support",
    "global-client-fingerprint",
];

pub const DNS_T0: &[&str] = &[
    "enable",
    "enhanced-mode",
    "nameserver",
    "default-nameserver",
    "nameserver-policy",
    "proxy-server-nameserver",
    "direct-nameserver",
    "direct-nameserver-follow-policy",
    "use-hosts",
    "use-system-hosts",
    "respect-rules",
    "fake-ip-range",
    "fake-ip-filter",
    "fake-ip-filter-mode",
    "fake-ip-ttl",
    "ipv6",
];

pub const DNS_T1: &[&str] = &[
    "fallback",
    "fallback-lazy-query",
    "fallback-filter",
    "ipv6-timeout",
    "prefer-h3",
    "cache-algorithm",
    "cache-max-size",
    "fake-ip-range6",
    "proxy-server-nameserver-policy",
    "listen",
    "listen-routing-mark",
];

pub const FALLBACK_FILTER: &[&str] = &["geoip", "geoip-code", "geosite", "ipcidr", "domain"];

pub const TUN_T0: &[&str] = &[
    "enable",
    "device",
    "stack",
    "auto-route",
    "auto-detect-interface",
    "dns-hijack",
    "route-address",
    "route-exclude-address",
    "strict-route",
    "mtu",
];

pub const TUN_T1: &[&str] = &[
    "congestion-controller",
    "udp-timeout",
    "disable-icmp-forwarding",
    "gso",
    "include-interface",
    "exclude-interface",
    "include-uid",
    "exclude-uid",
    "exclude-src-port",
    "exclude-dst-port",
    "inet4-route-address",
    "inet6-route-address",
    "inet4-route-exclude-address",
    "inet6-route-exclude-address",
];

pub const TUN_T2: &[&str] = &[
    "dns-mode",
    "gso-max-size",
    "inet6-address",
    "iproute2-table-index",
    "iproute2-rule-index",
    "auto-redirect",
    "auto-redirect-input-mark",
    "auto-redirect-output-mark",
    "auto-redirect-iproute2-fallback-rule-index",
    "loopback-address",
    "route-address-set",
    "route-exclude-address-set",
    "include-uid-range",
    "exclude-uid-range",
    "exclude-src-port-range",
    "exclude-dst-port-range",
    "include-android-user",
    "include-package",
    "exclude-package",
    "include-mac-address",
    "exclude-mac-address",
    "endpoint-independent-nat",
    "icmp-timeout",
    "file-descriptor",
    "recvmsgx",
    "sendmsgx",
    "processors-per-channel",
];

/// TUN_T2 keys that narrow or widen what the TUN captures.
pub const TUN_SCOPE: &[&str] = &[
    "route-address-set",
    "route-exclude-address-set",
    "include-uid-range",
    "exclude-uid-range",
    "exclude-src-port-range",
    "exclude-dst-port-range",
    "include-android-user",
    "include-package",
    "exclude-package",
    "include-mac-address",
    "exclude-mac-address",
];

pub const SNIFFER_T0: &[&str] = &[
    "enable",
    "sniff",
    "override-destination",
    "force-domain",
    "skip-domain",
    "sniffing",
    "port-whitelist",
];

pub const SNIFFER_T1: &[&str] = &[
    "force-dns-mapping",
    "parse-pure-ip",
    "skip-src-address",
    "skip-dst-address",
];

pub const SNIFFER_T2: &[&str] = &[];

pub const NTP_KEYS: &[&str] = &[
    "enable",
    "server",
    "port",
    "interval",
    "dialer-proxy",
    "write-to-system",
];

pub const GEOX_KEYS: &[&str] = &["mmdb", "asn", "geosite"];
pub const GEOX_T2: &[&str] = &["geoip"];

pub const DEFAULT_GLOBAL_UA: &str = "clash.meta/1.10.0";

pub fn general_defaults() -> Map {
    let value = json!({
        "port": 0,
        "socks-port": 0,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": 0,
        "authentication": [],
        "skip-auth-prefixes": null,
        "allow-lan": false,
        "bind-address": "*",
        "lan-allowed-ips": ["0.0.0.0/0", "::/0"],
        "lan-disallowed-ips": null,
        "mode": "rule",
        "unified-delay": false,
        "log-level": "info",
        "ipv6": true,
        "external-controller": "",
        "secret": "",
        "interface-name": "",
        "routing-mark": 0,
        "geo-auto-update": false,
        "geo-update-interval": 24,
        "geodata-loader": "memconservative",
        "tcp-concurrent": false,
        "find-process-mode": "strict",
        "global-ua": DEFAULT_GLOBAL_UA,
        "keep-alive-idle": 0,
        "keep-alive-interval": 0,
        "disable-keep-alive": false,
        "proxy-providers": null,
        "rule-providers": null,
        "sub-rules": null,
    });
    into_map(value)
}

pub fn dns_defaults() -> Map {
    into_map(json!({
        "enable": false,
        "prefer-h3": false,
        "ipv6": false,
        "ipv6-timeout": 100,
        "use-hosts": true,
        "use-system-hosts": true,
        "respect-rules": false,
        "nameserver": ["https://doh.pub/dns-query", "tls://223.5.5.5:853"],
        "fallback": null,
        "fallback-filter": {
            "geoip": false,
            "geoip-code": "",
            "ipcidr": [],
            "domain": null,
            "geosite": [],
        },
        "fallback-lazy-query": false,
        "listen": "",
        "listen-routing-mark": 0,
        "enhanced-mode": "redir-host",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-range6": "",
        "fake-ip-filter": ["dns.msftnsci.com", "www.msftnsci.com", "www.msftconnecttest.com"],
        "fake-ip-filter-mode": "blacklist",
        "fake-ip-ttl": 1,
        "default-nameserver": ["114.114.114.114", "223.5.5.5", "8.8.8.8", "1.0.0.1"],
        "cache-algorithm": "",
        "cache-max-size": 0,
        "nameserver-policy": null,
        "proxy-server-nameserver": null,
        "proxy-server-nameserver-policy": null,
        "direct-nameserver": null,
        "direct-nameserver-follow-policy": false,
    }))
}

pub fn tun_defaults() -> Map {
    into_map(json!({
        "enable": false,
        "device": "",
        "stack": "Mips",
        "dns-mode": "",
        "dns-hijack": ["0.0.0.0:53"],
        "auto-route": true,
        "auto-detect-interface": true,
    }))
}

pub fn sniffer_defaults() -> Map {
    into_map(json!({
        "enable": false,
        "override-destination": true,
        "sniffing": null,
        "force-domain": [],
        "skip-src-address": null,
        "skip-dst-address": null,
        "skip-domain": [],
        "port-whitelist": [],
        "force-dns-mapping": true,
        "parse-pure-ip": true,
        "sniff": {},
    }))
}

pub fn default_number<T: TryFrom<i128> + Default>(defaults: &Map, key: &str) -> T {
    defaults
        .get(key)
        .and_then(crate::lenient::to_i128)
        .and_then(|number| T::try_from(number).ok())
        .unwrap_or_default()
}

pub fn ntp_defaults() -> Map {
    into_map(json!({
        "enable": false,
        "server": "time.apple.com",
        "port": 123,
        "interval": 30,
        "dialer-proxy": "",
        "write-to-system": false,
    }))
}

pub fn geox_defaults() -> Map {
    let base = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest";
    into_map(json!({
        "mmdb": format!("{base}/geoip.metadb"),
        "asn": format!("{base}/GeoLite2-ASN.mmdb"),
        "geosite": format!("{base}/geosite.dat"),
    }))
}

pub fn profile_defaults() -> Map {
    into_map(json!({
        "store-selected": true,
        "store-fake-ip": false,
    }))
}

pub fn experimental_defaults() -> Map {
    into_map(json!({
        "fingerprints": null,
        "quic-go-disable-gso": false,
        "quic-go-disable-ecn": true,
        "dialer-ip4p-convert": false,
    }))
}

pub fn tls_defaults() -> Map {
    into_map(json!({
        "certificate": "",
        "private-key": "",
        "client-auth-type": "",
        "client-auth-cert": "",
        "ech-key": "",
        "custom-certifactes": null,
    }))
}

pub fn mitm_defaults() -> Map {
    into_map(json!({
        "enable": false,
        "hostname": null,
        "skip-server-cert-verify": false,
        "url-rewrite": null,
        "header-rewrite": null,
        "body-rewrite": null,
        "map-local": null,
        "script": null,
        "h2": false,
        "limits": {},
    }))
}

fn into_map(value: Value) -> Map {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// A null keeps any default but a list, as go-yaml leaves a scalar or struct field alone and clears a slice.
pub fn overlay(defaults: &Map, user: Map) -> Map {
    let mut out = defaults.clone();
    for (key, value) in user {
        match value {
            Value::Object(top) => match out.get_mut(&key) {
                Some(Value::Object(base)) => {
                    let merged = overlay(base, top);
                    *base = merged;
                }
                _ => {
                    out.insert(key, Value::Object(top));
                }
            },
            Value::Null
                if out
                    .get(&key)
                    .is_some_and(|default| !matches!(default, Value::Array(_) | Value::Null)) => {}
            value => {
                out.insert(key, value);
            }
        }
    }
    out
}
