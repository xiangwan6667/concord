//! The tiers in `keys.rs` are claims about behaviour: a T0 or T1 key changes what loads, a T2 key
//! is warned about, an inert key does neither, and anything else is unknown. A key added to a
//! tier without a sample here fails the test.

use concord_config::keys::{SECTIONS, Tier};
use concord_config::{LoadOptions, Profile, load_str};

/// A value for each T0 and T1 key that differs from its default, written as YAML under its
/// section. Some keys need a neighbour to be read at all, and carry it in the same text.
const SAMPLES: &[(&str, &str)] = &[
    ("mixed-port", "mixed-port: 7891"),
    ("port", "port: 7892"),
    ("socks-port", "socks-port: 7893"),
    ("redir-port", "redir-port: 7894"),
    ("tproxy-port", "tproxy-port: 7895"),
    ("allow-lan", "allow-lan: true"),
    ("bind-address", "bind-address: 192.168.1.2"),
    ("lan-allowed-ips", "lan-allowed-ips: [192.168.0.0/16]"),
    ("lan-disallowed-ips", "lan-disallowed-ips: [192.168.1.1/32]"),
    ("authentication", "authentication: [\"user:pass\"]"),
    ("skip-auth-prefixes", "skip-auth-prefixes: [10.0.0.0/8]"),
    ("mode", "mode: global"),
    ("log-level", "log-level: debug"),
    ("ipv6", "ipv6: false"),
    ("unified-delay", "unified-delay: true"),
    ("tcp-concurrent", "tcp-concurrent: true"),
    ("find-process-mode", "find-process-mode: always"),
    ("interface-name", "interface-name: en9"),
    ("routing-mark", "routing-mark: 6666"),
    ("keep-alive-idle", "keep-alive-idle: 30"),
    ("keep-alive-interval", "keep-alive-interval: 10"),
    ("disable-keep-alive", "disable-keep-alive: true"),
    ("global-ua", "global-ua: sample/1.0"),
    ("geo-auto-update", "geo-auto-update: true"),
    ("geo-update-interval", "geo-update-interval: 48"),
    ("external-controller", "external-controller: 127.0.0.1:9090"),
    ("secret", "secret: sample"),
    (
        "external-controller-cors",
        "external-controller-cors: {allow-origins: [\"https://a.test\"]}",
    ),
    ("proxies", "proxies: [{name: a, type: direct}]"),
    (
        "proxy-groups",
        "proxy-groups: [{name: g, type: select, proxies: [DIRECT]}]",
    ),
    (
        "proxy-providers",
        "proxy-providers: {p: {type: http, url: \"https://a.test/p.yaml\", path: ./p.yaml}}",
    ),
    (
        "rule-providers",
        "rule-providers: {r: {type: http, behavior: domain, url: \"https://a.test/r.yaml\", path: ./r.yaml}}",
    ),
    ("rules", "rules: [\"DOMAIN,a.test,REJECT\"]"),
    ("sub-rules", "sub-rules: {s: [\"MATCH,DIRECT\"]}"),
    ("hosts", "hosts: {a.test: 10.0.0.1}"),
    ("dns", "dns: {enable: true}"),
    ("tun", "tun: {enable: true}"),
    ("sniffer", "sniffer: {enable: true}"),
    ("ntp", "ntp: {enable: true}"),
    ("geox-url", "geox-url: {mmdb: \"https://a.test/m.mmdb\"}"),
    ("profile", "profile: {store-fake-ip: true}"),
    ("experimental", "experimental: {dialer-ip4p-convert: true}"),
    ("tls", "tls: {custom-certificates: [./ca.pem]}"),
    ("mitm", "mitm: {enable: true}"),
    ("dns.enable", "dns: {enable: true}"),
    ("dns.enhanced-mode", "dns: {enhanced-mode: fake-ip}"),
    ("dns.nameserver", "dns: {nameserver: [\"1.1.1.1\"]}"),
    (
        "dns.default-nameserver",
        "dns: {default-nameserver: [\"9.9.9.9\"]}",
    ),
    (
        "dns.nameserver-policy",
        "dns: {nameserver-policy: {a.test: \"8.8.8.8\"}}",
    ),
    (
        "dns.proxy-server-nameserver",
        "dns: {proxy-server-nameserver: [\"8.8.8.8\"]}",
    ),
    (
        "dns.direct-nameserver",
        "dns: {direct-nameserver: [\"8.8.8.8\"]}",
    ),
    (
        "dns.direct-nameserver-follow-policy",
        "dns: {direct-nameserver-follow-policy: true}",
    ),
    ("dns.use-hosts", "dns: {use-hosts: false}"),
    ("dns.use-system-hosts", "dns: {use-system-hosts: false}"),
    (
        "dns.respect-rules",
        "dns: {respect-rules: true, proxy-server-nameserver: [\"8.8.8.8\"]}",
    ),
    ("dns.fake-ip-range", "dns: {fake-ip-range: 198.19.0.1/16}"),
    ("dns.fake-ip-filter", "dns: {fake-ip-filter: [a.test]}"),
    (
        "dns.fake-ip-filter-mode",
        "dns: {fake-ip-filter-mode: whitelist}",
    ),
    ("dns.fake-ip-ttl", "dns: {fake-ip-ttl: 5}"),
    ("dns.ipv6", "dns: {ipv6: true}"),
    ("dns.fallback", "dns: {fallback: [\"8.8.4.4\"]}"),
    (
        "dns.fallback-lazy-query",
        "dns: {fallback-lazy-query: true}",
    ),
    (
        "dns.fallback-filter",
        "dns: {fallback: [\"8.8.4.4\"], fallback-filter: {geoip-code: US}}",
    ),
    ("dns.ipv6-timeout", "dns: {ipv6-timeout: 300}"),
    ("dns.prefer-h3", "dns: {prefer-h3: true}"),
    ("dns.cache-algorithm", "dns: {cache-algorithm: arc}"),
    ("dns.cache-max-size", "dns: {cache-max-size: 1000}"),
    (
        "dns.fake-ip-range6",
        "dns: {fake-ip-range6: \"fdfe:dcba:9876::1/64\"}",
    ),
    (
        "dns.proxy-server-nameserver-policy",
        "dns: {proxy-server-nameserver: [\"8.8.8.8\"], proxy-server-nameserver-policy: {a.test: \"1.1.1.1\"}}",
    ),
    ("dns.listen", "dns: {listen: \"127.0.0.1:1053\"}"),
    (
        "dns.listen-routing-mark",
        "dns: {listen-routing-mark: 6666}",
    ),
    (
        "dns.fallback-filter.geoip",
        "dns: {fallback: [\"8.8.4.4\"], fallback-filter: {geoip: true}}",
    ),
    (
        "dns.fallback-filter.geoip-code",
        "dns: {fallback: [\"8.8.4.4\"], fallback-filter: {geoip-code: US}}",
    ),
    (
        "dns.fallback-filter.geosite",
        "dns: {fallback: [\"8.8.4.4\"], fallback-filter: {geosite: [gfw]}}",
    ),
    (
        "dns.fallback-filter.ipcidr",
        "dns: {fallback: [\"8.8.4.4\"], fallback-filter: {ipcidr: [240.0.0.0/4]}}",
    ),
    (
        "dns.fallback-filter.domain",
        "dns: {fallback: [\"8.8.4.4\"], fallback-filter: {domain: [+.a.test]}}",
    ),
    ("tun.enable", "tun: {enable: true}"),
    ("tun.device", "tun: {device: utun9}"),
    ("tun.stack", "tun: {stack: gvisor}"),
    ("tun.auto-route", "tun: {auto-route: false}"),
    (
        "tun.auto-detect-interface",
        "tun: {auto-detect-interface: false}",
    ),
    ("tun.dns-hijack", "tun: {dns-hijack: [\"any:53\"]}"),
    ("tun.route-address", "tun: {route-address: [10.0.0.0/8]}"),
    (
        "tun.route-exclude-address",
        "tun: {route-exclude-address: [10.0.0.0/8]}",
    ),
    ("tun.strict-route", "tun: {strict-route: true}"),
    ("tun.mtu", "tun: {mtu: 1400}"),
    (
        "tun.congestion-controller",
        "tun: {congestion-controller: reno}",
    ),
    ("tun.udp-timeout", "tun: {udp-timeout: 60}"),
    (
        "tun.disable-icmp-forwarding",
        "tun: {disable-icmp-forwarding: true}",
    ),
    ("tun.gso", "tun: {gso: true}"),
    ("tun.include-interface", "tun: {include-interface: [eth9]}"),
    ("tun.exclude-interface", "tun: {exclude-interface: [eth9]}"),
    ("tun.include-uid", "tun: {include-uid: [1000]}"),
    ("tun.exclude-uid", "tun: {exclude-uid: [1000]}"),
    ("tun.exclude-src-port", "tun: {exclude-src-port: [5000]}"),
    ("tun.exclude-dst-port", "tun: {exclude-dst-port: [5000]}"),
    (
        "tun.inet4-route-address",
        "tun: {inet4-route-address: [10.0.0.0/8]}",
    ),
    (
        "tun.inet6-route-address",
        "tun: {inet6-route-address: [\"fd00::/8\"]}",
    ),
    (
        "tun.inet4-route-exclude-address",
        "tun: {inet4-route-exclude-address: [10.0.0.0/8]}",
    ),
    (
        "tun.inet6-route-exclude-address",
        "tun: {inet6-route-exclude-address: [\"fd00::/8\"]}",
    ),
    ("sniffer.enable", "sniffer: {enable: true}"),
    ("sniffer.sniff", "sniffer: {sniff: {TLS: {ports: [8443]}}}"),
    (
        "sniffer.override-destination",
        "sniffer: {override-destination: false}",
    ),
    ("sniffer.force-domain", "sniffer: {force-domain: [a.test]}"),
    ("sniffer.skip-domain", "sniffer: {skip-domain: [a.test]}"),
    ("sniffer.sniffing", "sniffer: {sniffing: [tls]}"),
    (
        "sniffer.port-whitelist",
        "sniffer: {sniffing: [tls], port-whitelist: [8443]}",
    ),
    (
        "sniffer.force-dns-mapping",
        "sniffer: {force-dns-mapping: false}",
    ),
    ("sniffer.parse-pure-ip", "sniffer: {parse-pure-ip: false}"),
    (
        "sniffer.skip-src-address",
        "sniffer: {skip-src-address: [10.0.0.0/8]}",
    ),
    (
        "sniffer.skip-dst-address",
        "sniffer: {skip-dst-address: [10.0.0.0/8]}",
    ),
    ("ntp.enable", "ntp: {enable: true}"),
    ("ntp.server", "ntp: {server: ntp.a.test}"),
    ("ntp.port", "ntp: {port: 1123}"),
    ("ntp.interval", "ntp: {interval: 60}"),
    ("ntp.dialer-proxy", "ntp: {dialer-proxy: DIRECT}"),
    ("ntp.write-to-system", "ntp: {write-to-system: true}"),
    (
        "geox-url.mmdb",
        "geox-url: {mmdb: \"https://a.test/m.mmdb\"}",
    ),
    ("geox-url.asn", "geox-url: {asn: \"https://a.test/a.mmdb\"}"),
    (
        "geox-url.geosite",
        "geox-url: {geosite: \"https://a.test/s.dat\"}",
    ),
    ("profile.store-fake-ip", "profile: {store-fake-ip: true}"),
    ("geodata-loader", "geodata-loader: standard"),
    ("profile.store-selected", "profile: {store-selected: false}"),
];

/// What a sample is compared with when its key is read only beside another, which the sample
/// then also carries; any other sample is compared with an empty profile.
const BASELINES: &[(&str, &str)] = &[
    ("dns.fallback-filter", "dns: {fallback: [\"8.8.4.4\"]}"),
    (
        "dns.respect-rules",
        "dns: {proxy-server-nameserver: [\"8.8.8.8\"]}",
    ),
    (
        "dns.proxy-server-nameserver-policy",
        "dns: {proxy-server-nameserver: [\"8.8.8.8\"]}",
    ),
    ("sniffer.port-whitelist", "sniffer: {sniffing: [tls]}"),
];

fn baseline(path: &str) -> &'static str {
    BASELINES
        .iter()
        .find(|(prefix, _)| path == *prefix || path.starts_with(&format!("{prefix}.")))
        .map_or("", |(_, text)| text)
}

fn path(section: &str, key: &str) -> String {
    if section.is_empty() {
        key.to_string()
    } else {
        format!("{section}.{key}")
    }
}

/// `key: value` nested under the sections its path names.
fn nested(path: &str, value: &str) -> String {
    let parts: Vec<&str> = path.split('.').collect();
    let (leaf, sections) = parts.split_last().unwrap();
    let mut text = String::new();
    for (depth, section) in sections.iter().enumerate() {
        text.push_str(&format!("{}{section}:\n", "  ".repeat(depth)));
    }
    text.push_str(&format!("{}{leaf}: {value}\n", "  ".repeat(sections.len())));
    text
}

type Loaded = (String, Vec<(String, &'static str)>);

/// What loads, without the report, and the report's codes by path.
fn loaded(text: &str) -> Result<Loaded, String> {
    let mut profile: Profile =
        load_str(text, &LoadOptions::default()).map_err(|err| format!("does not load: {err}"))?;
    let report = std::mem::take(&mut profile.report);
    let warnings = report
        .warnings
        .into_iter()
        .map(|warning| (warning.path, warning.code))
        .collect();
    Ok((format!("{profile:?}"), warnings))
}

fn sample(path: &str) -> Result<&'static str, String> {
    SAMPLES
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, text)| *text)
        .ok_or_else(|| "no sample".to_string())
}

#[test]
fn every_applied_key_changes_what_loads() {
    let mut failures = Vec::new();
    for (section, tiers) in SECTIONS {
        for key in tiers.t0.iter().chain(tiers.t1) {
            let path = path(section, key);
            let (empty, _) = loaded(baseline(&path)).unwrap();
            let (applied, warnings) = match sample(&path).and_then(loaded) {
                Ok(loaded) => loaded,
                Err(err) => {
                    failures.push(format!("{path}: {err}"));
                    continue;
                }
            };
            if applied == empty {
                failures.push(format!("{path}: loads the same as without it"));
            }
            if let Some((_, code)) = warnings
                .iter()
                .find(|(_, code)| matches!(*code, "unknown_key" | "unsupported_key"))
            {
                failures.push(format!("{path}: warned {code}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn every_unsupported_key_is_warned_and_every_inert_key_is_not() {
    let (empty, _) = loaded("").unwrap();
    let mut failures = Vec::new();
    for (section, tiers) in SECTIONS {
        for key in tiers.t2 {
            let path = path(section, key);
            match loaded(&nested(&path, "true")) {
                Ok((_, warnings)) if warnings.contains(&(path.clone(), "unsupported_key")) => {}
                other => failures.push(format!("{path}: not warned ({other:?})")),
            }
        }
        for key in tiers.inert {
            let path = path(section, key);
            match sample(&path).and_then(loaded) {
                Ok((applied, warnings)) if applied == empty && warnings.is_empty() => {}
                other => failures.push(format!("{path}: has an effect or a warning ({other:?})")),
            }
        }
        let path = path(section, "no-such-key");
        match loaded(&nested(&path, "true")) {
            Ok((_, warnings)) if warnings.contains(&(path.clone(), "unknown_key")) => {}
            other => failures.push(format!("{path}: not reported unknown ({other:?})")),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn every_tier_is_listed_once() {
    for (section, tiers) in SECTIONS {
        let all: Vec<&str> = [tiers.t0, tiers.t1, tiers.t2, tiers.inert].concat();
        for key in &all {
            let tier = tiers.of(key);
            assert!(tier.is_some(), "{section}.{key}");
            assert_eq!(
                all.iter().filter(|other| *other == key).count(),
                1,
                "{section}.{key}"
            );
        }
    }
    assert_eq!(SECTIONS[0].1.of("geodata-loader"), Some(Tier::Inert));
}

#[test]
fn group_health_keys_have_applied_tiers_and_change_typed_definitions() {
    let schema = concord_config::config_schema();
    let text = |options: &str| {
        format!("proxy-groups: [{{name: g, type: url-test, proxies: [DIRECT], {options}}}]")
    };
    let base = load_str(&text(""), &LoadOptions::default()).unwrap();
    for (key, value) in [
        ("url", "https://probe.test/"),
        ("interval", "90"),
        ("empty-fallback", "DIRECT"),
    ] {
        assert_eq!(concord_config::keys::GROUP.of(key), Some(Tier::T0));
        assert!(
            schema["proxy-groups"]["t0"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == key)
        );
        let changed = load_str(&text(&format!("{key}: {value}")), &LoadOptions::default()).unwrap();
        assert_ne!(changed.groups[0], base.groups[0], "{key}");
        assert!(changed.report.warnings.is_empty(), "{key}");
    }
}
