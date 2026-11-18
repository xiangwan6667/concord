use std::sync::Arc;

use super::*;
use crate::geo::{GeoFile, GeoStore};

fn env() -> CompileEnv {
    CompileEnv::new(
        Arc::new(GeoStore::new(
            std::env::temp_dir().join("concord-rules-no-geo"),
        )),
        Arc::new(RuleSetStore::new()),
    )
}

type DumpCase<'a> = (&'a [&'a str], &'a [&'a str], &'a [(&'a str, bool)]);

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn domain_set(domains: &[&str]) -> RuleSet {
    RuleSet::from_entries(Behavior::Domain, &strings(domains), &env()).set
}

fn host_matches(set: &RuleSet, host: &str) -> bool {
    set.match_domain(host, &GeoStore::new("."))
}

#[test]
fn dump_groups_exact_and_suffix_entries() {
    let cases: [DumpCase<'_>; 6] = [
        (
            &[".example.com"],
            &[".example.com"],
            &[("example.com", false), ("www.example.com", true)],
        ),
        (
            &["example.com"],
            &["example.com"],
            &[("example.com", true), ("www.example.com", false)],
        ),
        (
            &["example.com", ".example.com"],
            &["+.example.com"],
            &[("example.com", true), ("www.example.com", true)],
        ),
        (
            &[
                "+.example.com",
                "+.example.com",
                "example.com",
                ".example.com",
            ],
            &["+.example.com"],
            &[("example.com", true), ("www.example.com", true)],
        ),
        (
            &[".example.com", "example.net", "example.org", ".example.org"],
            &["+.example.org", ".example.com", "example.net"],
            &[
                ("example.com", false),
                ("www.example.com", true),
                ("example.net", true),
                ("www.example.net", false),
                ("example.org", true),
                ("www.example.org", true),
            ],
        ),
        (
            &[
                "*.example.com",
                "+.example.org",
                "test.*.google.com",
                ".test.*.google.com",
                ".example.net",
            ],
            &[
                "*.example.com",
                "+.example.org",
                "+.test.*.google.com",
                ".example.net",
            ],
            &[
                ("example.com", false),
                ("www.example.com", true),
                ("example.org", true),
                ("test.www.google.com", true),
                ("www.test.www.google.com", true),
                ("example.net", false),
                ("www.example.net", true),
            ],
        ),
    ];
    for (inputs, expected, queries) in cases {
        let set = domain_set(inputs);
        let compiled = compile_rule_set(inputs.join("\n").as_bytes(), false).unwrap();
        let bytes = compiled.mrs.unwrap();
        let dumped = dump_mrs(&bytes).unwrap();
        let lines: Vec<&str> = dumped.lines().collect();
        assert_eq!(lines, expected, "{inputs:?}");
        let rebuilt = domain_set(&lines);
        for (host, want) in queries {
            assert_eq!(host_matches(&set, host), *want, "{inputs:?} {host}");
            assert_eq!(
                host_matches(&rebuilt, host),
                *want,
                "{inputs:?} rebuilt {host}"
            );
        }
    }
}

#[test]
fn classification_picks_the_behavior_the_entries_fit() {
    let cases: [(&str, &[&str], Behavior, &[&str]); 9] = [
        (
            "domains",
            &["example.com", "+.example.org", "*.example.net"],
            Behavior::Domain,
            &["example.com", "+.example.org", "*.example.net"],
        ),
        (
            "ranges and bare addresses",
            &["10.0.0.0/8", "1.1.1.1", "2001:db8::1"],
            Behavior::IpCidr,
            &["10.0.0.0/8", "1.1.1.1/32", "2001:db8::1/128"],
        ),
        (
            "domain rules",
            &["DOMAIN,example.com", "domain-suffix, example.org"],
            Behavior::Domain,
            &["example.com", "+.example.org"],
        ),
        (
            "range rules",
            &["IP-CIDR,10.0.0.0/8", "IP-CIDR6,2001:db8::/32"],
            Behavior::IpCidr,
            &["10.0.0.0/8", "2001:db8::/32"],
        ),
        (
            "a keyword rule",
            &["DOMAIN,example.com", "DOMAIN-KEYWORD,example"],
            Behavior::Classical,
            &[],
        ),
        (
            "a rule with an option",
            &["IP-CIDR,10.0.0.0/8,no-resolve"],
            Behavior::Classical,
            &[],
        ),
        (
            "domain and range rules together",
            &["DOMAIN,example.com", "IP-CIDR,10.0.0.0/8"],
            Behavior::Classical,
            &[],
        ),
        (
            "a wildcard in a literal domain rule",
            &["DOMAIN-SUFFIX,.example.com"],
            Behavior::Classical,
            &[],
        ),
        (
            "a stray line among rules",
            &["DOMAIN,example.com", "example.org"],
            Behavior::Classical,
            &[],
        ),
    ];
    for (name, entries, behavior, keys) in cases {
        let (got, got_keys) = classify(&strings(entries)).unwrap();
        assert_eq!((got, got_keys), (behavior, strings(keys)), "{name}");
    }
    assert_eq!(classify(&[]).unwrap_err(), CompileSetError::Empty);
    assert_eq!(
        classify(&strings(&["example.com", "10.0.0.0/8"])).unwrap_err(),
        CompileSetError::Mixed
    );
}

use super::convert::classify;

#[test]
fn compile_reads_each_source_format() {
    let domain_mrs = compile_rule_set(b"example.com\n", false)
        .unwrap()
        .mrs
        .unwrap();
    let cases: [(&str, &[u8], Behavior, Format, bool); 5] = [
        (
            "yaml domains",
            b"payload:\n  - '+.example.com'\n",
            Behavior::Domain,
            Format::Yaml,
            true,
        ),
        (
            "text ranges with comments",
            b"# ranges\n10.0.0.0/8\n\n// more\n192.168.0.0/16\n",
            Behavior::IpCidr,
            Format::Text,
            true,
        ),
        (
            "yaml classical",
            b"payload:\n  - DOMAIN-KEYWORD,example\n",
            Behavior::Classical,
            Format::Yaml,
            false,
        ),
        (
            "text classical",
            b"PROCESS-NAME,curl\n",
            Behavior::Classical,
            Format::Text,
            false,
        ),
        ("mrs", &domain_mrs, Behavior::Domain, Format::Mrs, false),
    ];
    for (name, source, behavior, format, writes) in cases {
        let compiled = compile_rule_set(source, false).unwrap();
        assert_eq!(
            (compiled.info.behavior, compiled.info.format),
            (behavior, format),
            "{name}"
        );
        assert_eq!(compiled.mrs.is_some(), writes, "{name}");
    }
}

#[test]
fn compile_rejects_unusable_sources() {
    let cases: [(&str, &[u8], CompileSetError); 4] = [
        ("empty yaml", b"payload: []\n", CompileSetError::Empty),
        ("only invalid names", b"bad/name\n", CompileSetError::Empty),
        (
            "mixed lines",
            b"example.com\n10.0.0.0/8\n",
            CompileSetError::Mixed,
        ),
        (
            "broken mrs",
            b"\x28\xB5\x2F\xFDgarbage",
            CompileSetError::Invalid,
        ),
    ];
    for (name, source, want) in cases {
        assert_eq!(compile_rule_set(source, false).unwrap_err(), want, "{name}");
    }
}

#[test]
fn an_empty_source_stays_classical_when_allowed() {
    for (source, format) in [
        (&b""[..], Format::Text),
        (&b"# nothing yet\n"[..], Format::Text),
        (&b"payload: []\n"[..], Format::Yaml),
    ] {
        let compiled = compile_rule_set(source, true).unwrap();
        assert_eq!(
            compiled.info,
            SetInfo {
                behavior: Behavior::Classical,
                format
            }
        );
        assert!(compiled.mrs.is_none());
    }
    assert_eq!(
        compile_rule_set(b"bad/name\n", true).unwrap_err(),
        CompileSetError::Empty
    );
}

#[test]
fn a_compiled_file_loads_back_into_a_set() {
    let compiled = compile_rule_set(b"10.0.0.0/8\n192.168.0.0/16\n1.1.1.1\n", false).unwrap();
    let parsed = RuleSet::parse(
        Behavior::IpCidr,
        Format::Mrs,
        &compiled.mrs.unwrap(),
        &env(),
    )
    .unwrap();
    assert_eq!(parsed.set.count(), 3);
    let geo = GeoStore::new(".");
    assert!(parsed.set.match_ip("10.2.3.4".parse().unwrap(), &geo));
    assert!(parsed.set.match_ip("1.1.1.1".parse().unwrap(), &geo));
    assert!(!parsed.set.match_ip("8.8.8.8".parse().unwrap(), &geo));
    assert_eq!(
        RuleSet::parse(
            Behavior::Domain,
            Format::Mrs,
            &compile_rule_set(b"10.0.0.0/8\n", false)
                .unwrap()
                .mrs
                .unwrap(),
            &env()
        )
        .err()
        .map(|e| e.to_string()),
        Some("invalid behavior".to_string())
    );
}

#[test]
fn dumping_a_non_mrs_file_reports_both_attempts() {
    let errors = dump_mrs(b"hello").unwrap_err();
    assert_eq!(errors.len(), 2);
}

#[test]
fn a_domain_set_covers_the_domain_a_leading_dot_names() {
    let surge = b"# Surge DOMAIN-SET\n.example.com\nexact.test\n+.plus.test\n";
    let parsed = RuleSet::parse(Behavior::Domain, Format::DomainSet, surge, &env()).unwrap();
    for (host, matched) in [
        ("example.com", true),
        ("a.b.example.com", true),
        ("exact.test", true),
        ("sub.exact.test", false),
        ("plus.test", true),
    ] {
        assert_eq!(host_matches(&parsed.set, host), matched, "{host}");
    }
    let text = RuleSet::parse(Behavior::Domain, Format::Text, surge, &env()).unwrap();
    assert!(
        !host_matches(&text.set, "example.com"),
        "mihomo's text leaves the domain out"
    );
}

#[test]
fn providers_parse_text_and_yaml_and_report_skips() {
    let parsed = RuleSet::parse(
        Behavior::Domain,
        Format::Yaml,
        b"payload:\n  - '+.example.com'\n  - 'bad/domain'\n  - 'a..b'\n  - plain.org\n",
        &env(),
    )
    .unwrap();
    assert_eq!(parsed.set.count(), 2);
    assert_eq!(parsed.warnings.len(), 2);
    assert!(host_matches(&parsed.set, "www.example.com") && host_matches(&parsed.set, "plain.org"));

    let ip = RuleSet::parse(
        Behavior::IpCidr,
        Format::Text,
        b"10.0.0.0/8\nnot-a-cidr\n",
        &env(),
    )
    .unwrap();
    assert_eq!(ip.set.count(), 1);
    assert_eq!(ip.warnings, ["invalid Ipcidr:[not-a-cidr]"]);

    assert_eq!(
        RuleSet::parse(Behavior::Domain, Format::Yaml, b"- a.com", &env()).err(),
        Some(RuleSetError::NoPayload)
    );
    assert_eq!(
        RuleSet::parse(Behavior::Classical, Format::Mrs, b"x", &env()).err(),
        Some(RuleSetError::InvalidFormat)
    );
}

#[test]
fn classical_entries_lost_to_a_missing_geo_file_are_reported() {
    let entries = strings(&[
        "GEOIP,CN",
        "AND,((GEOSITE,cn),(DOMAIN,a.com))",
        "DOMAIN,b.com",
    ]);
    let parsed = RuleSet::from_entries(Behavior::Classical, &entries, &env());
    assert_eq!(parsed.set.count(), 1);
    assert_eq!(
        parsed.geo_faults,
        [
            GeoFault::Missing(GeoFile::Mmdb),
            GeoFault::Missing(GeoFile::GeoSite)
        ]
    );
}

#[test]
fn classical_sets_skip_what_does_not_parse() {
    let parsed = RuleSet::parse(
        Behavior::Classical,
        Format::Text,
        b"DOMAIN-SUFFIX,example.com\nIP-CIDR,10.0.0.0/8,no-resolve\nMATCH,DIRECT\nFOO,bar\nDOMAIN,\nPROCESS-NAME,curl\nDOMAIN-REGEX,^a{1,3}\\.org$\n",
        &env(),
    )
    .unwrap();
    assert_eq!(parsed.set.count(), 4);
    assert_eq!(parsed.warnings.len(), 3);
    assert!(
        parsed
            .warnings
            .iter()
            .any(|w| w.contains("unsupported rule type on classical rule-set: MATCH"))
    );
    assert!(
        parsed
            .warnings
            .iter()
            .any(|w| w.contains("unsupported rule type: FOO"))
    );
    assert!(
        parsed
            .warnings
            .iter()
            .any(|w| w.contains("missing subsequent parameters: DOMAIN"))
    );
    assert!(host_matches(&parsed.set, "a.example.com"));
    assert!(host_matches(&parsed.set, "aa.org") && !host_matches(&parsed.set, "aaaa.org"));
    let geo = GeoStore::new(".");
    assert!(parsed.set.match_ip("10.1.1.1".parse().unwrap(), &geo));
    assert!(parsed.set.demands().process);
}

#[test]
fn handles_swap_without_new_references() {
    let store = RuleSetStore::new();
    let handle = store.declare("ads", Behavior::Domain);
    assert!(Arc::ptr_eq(
        &handle,
        &store.declare("ads", Behavior::IpCidr)
    ));
    assert_eq!(handle.behavior(), Behavior::Domain);
    let geo = GeoStore::new(".");
    assert!(!handle.match_domain("ads.example.com", &geo));
    assert!(handle.store(domain_set(&["+.example.com"])));
    assert!(handle.match_domain("ads.example.com", &geo));
    assert!(!handle.store(RuleSet::empty(Behavior::IpCidr)));
    assert!(handle.match_domain("ads.example.com", &geo));
    assert_eq!(store.names(), ["ads"]);
}
