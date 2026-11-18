use concord_common::Network;
use indexmap::IndexMap;

use crate::geo::GeoFile;
use crate::geo::dat::testing::site;
use crate::geo::test_mmdb::{Value, build};
use crate::testkit::{Flow, Kit, defs, drive};
use crate::{Behavior, CompileError, Cond, Demands, RouteProgram, RuleDef, RuleSet};

const MERGES: [usize; 2] = [2, 1000];

fn accepted(kit: &Kit, program: &RouteProgram, flow: &Flow) -> Option<(usize, String)> {
    drive(program, &kit.geo, flow, true).accepted
}

fn pick(index: usize, target: &str) -> Option<(usize, String)> {
    Some((index, target.to_string()))
}

fn resolving(host: &'static str, ip: &str) -> Flow {
    Flow {
        resolves_to: Some(ip.parse().unwrap()),
        ..Flow::domain(host)
    }
}

fn udp(host: &'static str) -> Flow {
    Flow {
        network: Network::Udp,
        ..Flow::domain(host)
    }
}

fn fill(kit: &Kit, name: &str, behavior: Behavior, entries: &[&str]) {
    let handle = kit.sets.declare(name, behavior);
    let entries: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
    handle.store(RuleSet::from_entries(behavior, &entries, &kit.env(8)).set);
}

fn compile_err(kit: &Kit, lines: &[&str], subs: &[(&str, &[&str])]) -> CompileError {
    let sub_rules = subs
        .iter()
        .map(|(name, lines)| (name.to_string(), defs(lines)))
        .collect();
    match RouteProgram::compile(&defs(lines), &sub_rules, &kit.env(8)) {
        Ok(_) => panic!("compiled"),
        Err(err) => err,
    }
}

#[test]
fn first_match_keeps_rule_order_across_runs_and_kinds() {
    let kit = Kit::new();
    let lines = [
        "DOMAIN-SUFFIX,a.com,P0",
        "DOMAIN,x.a.com,P1",
        "DOMAIN-KEYWORD,zzz,P2",
        "NETWORK,udp,P3",
        "DOMAIN-SUFFIX,b.com,P4",
        "DOMAIN-SUFFIX,a.com,P5",
        "DOMAIN-WILDCARD,*.c.com,P6",
        "MATCH,P7",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("x.a.com")),
            pick(0, "P0")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("zzz.b.com")),
            pick(2, "P2")
        );
        assert_eq!(accepted(&kit, &program, &udp("q.b.com")), pick(3, "P3"));
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("q.b.com")),
            pick(4, "P4")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("q.c.com")),
            pick(6, "P6")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("other.org")),
            pick(7, "P7")
        );
        let all = drive(&program, &kit.geo, &Flow::domain("x.a.com"), false);
        let order: Vec<usize> = all.candidates.iter().map(|c| c.0).collect();
        assert_eq!(order, [0, 1, 5, 7], "merge {merge}");
    }
}

#[test]
fn skip_continues_inside_a_merged_run() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "DOMAIN-SUFFIX,a.com,PASS",
            "DOMAIN-KEYWORD,a.c,PASS",
            "DOMAIN,www.a.com,PASS",
            "DOMAIN-SUFFIX,a.com,FINAL",
        ],
        2,
    );
    let trace = drive(&program, &kit.geo, &Flow::domain("www.a.com"), true);
    let order: Vec<usize> = trace.candidates.iter().map(|c| c.0).collect();
    assert_eq!(order, [0, 1, 2, 3]);
    assert_eq!(trace.accepted, pick(3, "FINAL"));
}

#[test]
fn the_destination_is_resolved_once_and_only_when_needed() {
    let kit = Kit::new();
    let lines = [
        "DOMAIN-SUFFIX,x.com,X",
        "IP-CIDR,10.0.0.0/8,TEN",
        "IP-CIDR,20.0.0.0/8,TWENTY",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        let flow = resolving("y.net", "20.1.1.1");
        let trace = drive(&program, &kit.geo, &flow, true);
        assert_eq!(trace.accepted, pick(2, "TWENTY"));
        assert_eq!(trace.ip_lookups, 1);

        let trace = drive(&program, &kit.geo, &Flow::domain("a.x.com"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "X"), 0));

        let trace = drive(&program, &kit.geo, &Flow::domain("unresolvable.net"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (None, 1));

        let trace = drive(&program, &kit.geo, &Flow::ip("10.9.9.9"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(1, "TEN"), 0));
    }
}

#[test]
fn no_resolve_never_asks_for_the_address() {
    let kit = Kit::new();
    for merge in MERGES {
        let program = kit.compile(&["IP-CIDR,10.0.0.0/8,TEN,no-resolve"], merge);
        let trace = drive(&program, &kit.geo, &resolving("a.net", "10.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (None, 0));
        let trace = drive(&program, &kit.geo, &Flow::ip("10.1.1.1"), true);
        assert_eq!(trace.accepted, pick(0, "TEN"));
        assert!(!program.demands().resolve_ip && program.demands().ip);
    }
}

#[test]
fn a_no_resolve_rule_after_a_resolving_one_sees_the_address() {
    let kit = Kit::new();
    for merge in MERGES {
        let program = kit.compile(
            &["IP-CIDR,20.0.0.0/8,A", "IP-CIDR,10.0.0.0/8,B,no-resolve"],
            merge,
        );
        let trace = drive(&program, &kit.geo, &resolving("a.net", "10.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(1, "B"), 1));
    }
}

#[test]
fn source_rules_use_the_client_address() {
    let kit = Kit::new();
    for merge in MERGES {
        let program = kit.compile(
            &[
                "SRC-IP-CIDR,192.168.1.0/24,LAN",
                "IP-CIDR,192.168.1.0/24,DST,src",
                "MATCH,X",
            ],
            merge,
        );
        let trace = drive(&program, &kit.geo, &Flow::domain("a.net"), false);
        assert_eq!(trace.ip_lookups, 0);
        assert_eq!(
            trace.candidates.iter().map(|c| c.0).collect::<Vec<_>>(),
            [0, 1, 2]
        );
    }
}

#[test]
fn processes_are_looked_up_on_demand() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "DOMAIN,a.com,A",
            "PROCESS-NAME,curl,CURL",
            "UID,1000-1010,USER",
            "MATCH,M",
        ],
        8,
    );
    let trace = drive(&program, &kit.geo, &Flow::domain("a.com"), true);
    assert_eq!((trace.accepted, trace.process_lookups), (pick(0, "A"), 0));

    let mut flow = Flow::domain("b.com");
    flow.process = Some(("curl", "/usr/bin/curl", 501));
    let trace = drive(&program, &kit.geo, &flow, true);
    assert_eq!(
        (trace.accepted, trace.process_lookups),
        (pick(1, "CURL"), 1)
    );

    flow.process = Some(("wget", "/usr/bin/wget", 1005));
    let trace = drive(&program, &kit.geo, &flow, true);
    assert_eq!(
        (trace.accepted, trace.process_lookups),
        (pick(2, "USER"), 1)
    );

    flow.process = Some(("wget", "/usr/bin/wget", 0));
    let trace = drive(&program, &kit.geo, &flow, true);
    assert_eq!(trace.accepted, pick(3, "M"));

    flow.process = None;
    let trace = drive(&program, &kit.geo, &flow, true);
    assert_eq!((trace.accepted, trace.process_lookups), (pick(3, "M"), 1));
    assert!(program.demands().process);
}

#[test]
fn process_matching_folds_case_and_supports_wildcards() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "PROCESS-NAME,Chrome.EXE,A",
            "PROCESS-PATH-WILDCARD,/opt/*/bin/tool,B",
            "PROCESS-NAME-REGEX,^fire,C",
        ],
        8,
    );
    let mut flow = Flow::domain("a.com");
    flow.process = Some(("chrome.exe", "/x", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(0, "A"));
    flow.process = Some(("t", "/OPT/app/bin/tool", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(1, "B"));
    flow.process = Some(("firefox", "/x", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(2, "C"));
}

#[test]
fn process_wildcards_lowercase_like_go() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "PROCESS-NAME-WILDCARD,\u{e9}t\u{e9}*,A",
            "PROCESS-NAME-WILDCARD,\u{3c3}*,B",
        ],
        8,
    );
    let mut flow = Flow::domain("a.com");
    flow.process = Some(("\u{c9}T\u{c9}.exe", "/x", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(0, "A"));
    flow.process = Some(("\u{3a3}\u{3a3}", "/x", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(1, "B"));
}

#[test]
fn sub_rule_lists_pass_or_fall_through() {
    let kit = Kit::new();
    let subs: &[(&str, &[&str])] = &[
        ("one", &["DOMAIN,x.a.com,PASS", "DOMAIN-KEYWORD,x,KEYWORD"]),
        (
            "two",
            &["DOMAIN,x.a.com,PASS-RULE", "DOMAIN-KEYWORD,x,KEYWORD"],
        ),
    ];
    for merge in MERGES {
        let program = kit.compile_with(
            &[
                "SUB-RULE,(DOMAIN-SUFFIX,a.com),one",
                "SUB-RULE,(NETWORK,tcp),two",
                "MATCH,Z",
            ],
            subs,
            merge,
        );
        let flow = Flow::domain("x.a.com");
        assert_eq!(accepted(&kit, &program, &flow), pick(1, "KEYWORD"));
        let all = drive(&program, &kit.geo, &flow, false);
        assert_eq!(
            all.candidates,
            [
                (0, "PASS".to_string()),
                (1, "PASS-RULE".to_string()),
                (1, "KEYWORD".to_string()),
                (2, "Z".to_string()),
            ]
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("next.org")),
            pick(1, "KEYWORD")
        );
        assert_eq!(accepted(&kit, &program, &udp("other.org")), pick(2, "Z"));
    }
}

#[test]
fn nested_sub_rules_report_the_outermost_rule() {
    let kit = Kit::new();
    let subs: &[(&str, &[&str])] = &[
        (
            "outer",
            &[
                "DOMAIN,skip.com,A",
                "SUB-RULE,(DOMAIN-SUFFIX,a.com),inner",
                "MATCH,OUTER",
            ],
        ),
        (
            "inner",
            &["DOMAIN,x.a.com,PASS-RULE", "DOMAIN-SUFFIX,a.com,INNER"],
        ),
    ];
    let program = kit.compile_with(&["SUB-RULE,(NETWORK,tcp),outer", "MATCH,Z"], subs, 8);
    let trace = drive(&program, &kit.geo, &Flow::domain("x.a.com"), false);
    assert_eq!(
        trace.candidates,
        [
            (0, "PASS-RULE".to_string()),
            (0, "INNER".to_string()),
            (1, "Z".to_string()),
        ]
    );
    assert_eq!(
        accepted(&kit, &program, &Flow::domain("b.org")),
        pick(0, "OUTER")
    );
    let info = program.rule_at(crate::RuleRef(0, 0));
    assert_eq!(info.type_name, "SubRules");
}

#[test]
fn nested_sub_rule_without_a_hit_lets_the_enclosing_list_go_on() {
    let kit = Kit::new();
    let subs: &[(&str, &[&str])] = &[
        (
            "outer",
            &["SUB-RULE,(DOMAIN-SUFFIX,a.com),inner", "MATCH,OUTER"],
        ),
        ("inner", &["DOMAIN,x.a.com,PASS-RULE"]),
    ];
    let program = kit.compile_with(&["SUB-RULE,(NETWORK,tcp),outer", "MATCH,Z"], subs, 8);
    let trace = drive(&program, &kit.geo, &Flow::domain("x.a.com"), false);
    assert_eq!(
        trace.candidates,
        [
            (0, "PASS-RULE".to_string()),
            (0, "OUTER".to_string()),
            (1, "Z".to_string()),
        ]
    );
}

#[test]
fn a_top_level_sub_rule_aimed_at_a_proxy_never_matches() {
    let kit = Kit::new();
    let subs: &[(&str, &[&str])] = &[("one", &["MATCH,ONE"])];
    for merge in MERGES {
        let program = kit.compile_with(
            &[
                "SUB-RULE,(NETWORK,tcp),DIRECT",
                "SUB-RULE,(NETWORK,tcp),one",
                "MATCH,Z",
            ],
            subs,
            merge,
        );
        let flow = Flow::domain("x.a.com");
        assert_eq!(accepted(&kit, &program, &flow), pick(1, "ONE"));
        let trace = drive(&program, &kit.geo, &flow, false);
        assert_eq!(
            trace.candidates,
            [(1, "ONE".to_string()), (2, "Z".to_string())]
        );
    }
    let nested = IndexMap::from([("one".to_string(), defs(&["SUB-RULE,(NETWORK,tcp),DIRECT"]))]);
    let refused = RouteProgram::compile(&defs(&["MATCH,Z"]), &nested, &kit.env(8));
    assert!(matches!(refused, Err(CompileError::UnknownSubRule { .. })));
}

#[test]
fn logic_rules_combine_conditions() {
    let kit = Kit::new();
    let lines = [
        "AND,((DOMAIN-SUFFIX,a.com),(NETWORK,udp)),UDP-A",
        "OR,((DOMAIN,b.com),(DST-PORT,8443)),B-OR-PORT",
        "NOT,((DOMAIN-SUFFIX,c.com)),NOT-C",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        assert_eq!(accepted(&kit, &program, &udp("x.a.com")), pick(0, "UDP-A"));
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("x.a.com")),
            pick(2, "NOT-C")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("b.com")),
            pick(1, "B-OR-PORT")
        );
        let mut flow = Flow::domain("z.c.com");
        assert_eq!(accepted(&kit, &program, &flow), None);
        flow.dst_port = 8443;
        assert_eq!(accepted(&kit, &program, &flow), pick(1, "B-OR-PORT"));
    }
}

#[test]
fn logic_children_honour_their_own_flags() {
    let kit = Kit::new();
    let quiet = kit.compile(
        &["AND,((IP-CIDR,10.0.0.0/8,no-resolve),(DOMAIN,a.com)),Q"],
        8,
    );
    let trace = drive(&quiet, &kit.geo, &resolving("a.com", "10.1.1.1"), true);
    assert_eq!((trace.accepted, trace.ip_lookups), (None, 0));
    assert!(!quiet.demands().resolve_ip);

    let loud = kit.compile(&["AND,((IP-CIDR,10.0.0.0/8),(DOMAIN,a.com)),L"], 8);
    let trace = drive(&loud, &kit.geo, &resolving("a.com", "10.1.1.1"), true);
    assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "L"), 1));
    assert!(loud.demands().resolve_ip);

    let source = kit.compile(&["AND,((IP-CIDR,192.168.1.0/24,src),(DOMAIN,a.com)),S"], 8);
    let trace = drive(&source, &kit.geo, &Flow::domain("a.com"), true);
    assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "S"), 0));
}

#[test]
fn rule_sets_follow_updates_without_recompiling() {
    let kit = Kit::new();
    fill(&kit, "dom", Behavior::Domain, &["+.a.com"]);
    fill(&kit, "ips", Behavior::IpCidr, &["10.0.0.0/8"]);
    fill(
        &kit,
        "cls",
        Behavior::Classical,
        &["DOMAIN-KEYWORD,kw", "IP-CIDR,30.0.0.0/8,no-resolve"],
    );
    for merge in MERGES {
        let program = kit.compile(
            &["RULE-SET,dom,D", "RULE-SET,ips,I", "RULE-SET,cls,C"],
            merge,
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("x.a.com")),
            pick(0, "D")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("kw.org")),
            pick(2, "C")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::ip("10.2.2.2")),
            pick(1, "I")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::ip("30.2.2.2")),
            pick(2, "C")
        );
        let trace = drive(&program, &kit.geo, &resolving("q.org", "10.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(1, "I"), 1));

        fill(&kit, "dom", Behavior::Domain, &["+.b.com"]);
        assert_eq!(accepted(&kit, &program, &Flow::domain("x.a.com")), None);
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("x.b.com")),
            pick(0, "D")
        );
        fill(&kit, "dom", Behavior::Domain, &["+.a.com"]);
    }
}

#[test]
fn rule_set_modifiers() {
    let kit = Kit::new();
    fill(
        &kit,
        "ips",
        Behavior::IpCidr,
        &["10.0.0.0/8", "192.168.1.0/24"],
    );
    let program = kit.compile(
        &["RULE-SET,ips,SRC,src", "RULE-SET,ips,QUIET,no-resolve"],
        8,
    );
    let trace = drive(&program, &kit.geo, &resolving("a.net", "10.1.1.1"), false);
    assert_eq!(trace.ip_lookups, 0);
    assert_eq!(
        trace
            .candidates
            .iter()
            .map(|c| c.1.as_str())
            .collect::<Vec<_>>(),
        ["SRC"]
    );
    let trace = drive(&program, &kit.geo, &Flow::ip("10.1.1.1"), false);
    assert_eq!(
        trace
            .candidates
            .iter()
            .map(|c| c.1.as_str())
            .collect::<Vec<_>>(),
        ["SRC", "QUIET"]
    );
}

#[test]
fn a_no_resolve_check_before_the_lookup_stays_unanswered() {
    let kit = Kit::new();
    fill(
        &kit,
        "cls",
        Behavior::Classical,
        &["IP-CIDR,10.0.0.0/8,no-resolve", "IP-CIDR,99.0.0.0/8"],
    );
    for merge in MERGES {
        let program = kit.compile(&["RULE-SET,cls,C"], merge);
        let trace = drive(&program, &kit.geo, &resolving("a.net", "10.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (None, 1));
        let trace = drive(&program, &kit.geo, &resolving("a.net", "99.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "C"), 1));
        let trace = drive(&program, &kit.geo, &Flow::ip("10.1.1.1"), true);
        assert_eq!(trace.accepted, pick(0, "C"));
    }
}

#[test]
fn geoip_lan_needs_no_database() {
    let kit = Kit::new();
    let program = kit.compile(&["GEOIP,LAN,L", "MATCH,W"], 8);
    let trace = drive(
        &program,
        &kit.geo,
        &resolving("home.test", "192.168.0.9"),
        true,
    );
    assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "L"), 1));
    assert_eq!(
        accepted(&kit, &program, &resolving("far.test", "8.8.8.8")),
        pick(1, "W")
    );
}

#[test]
fn geoip_reads_the_mmdb_or_the_dat() {
    let kit = Kit::new();
    let line = ["GEOIP,CN,CN", "MATCH,W"];
    let missing = compile_err(&kit, &line, &[]);
    assert_eq!(missing.missing_geo_file(), Some(GeoFile::Mmdb));
    assert!(matches!(missing, CompileError::Geo { .. }));

    let country = Value::map(vec![(
        "country",
        Value::map(vec![("iso_code", Value::s("CN"))]),
    )]);
    std::fs::write(
        kit.dir.path().join("geoip.metadb"),
        build("GeoLite2-Country", &[("1.0.0.0", 8, country)]),
    )
    .unwrap();
    let program = kit.compile(&line, 8);
    assert_eq!(
        accepted(&kit, &program, &Flow::ip("1.2.3.4")),
        pick(0, "CN")
    );
    assert_eq!(accepted(&kit, &program, &Flow::ip("9.2.3.4")), pick(1, "W"));
}

fn write_geoip(kit: &Kit, entries: &[(&str, u8, &str)]) {
    let rows: Vec<_> = entries
        .iter()
        .map(|(net, bits, code)| {
            let country = Value::map(vec![(
                "country",
                Value::map(vec![("iso_code", Value::s(code))]),
            )]);
            (*net, *bits, country)
        })
        .collect();
    std::fs::write(
        kit.dir.path().join("geoip.metadb"),
        build("GeoLite2-Country", &rows),
    )
    .unwrap();
}

fn write_asn(kit: &Kit) {
    let record = Value::map(vec![
        ("autonomous_system_number", Value::U32(13335)),
        (
            "autonomous_system_organization",
            Value::s("Cloudflare, Inc."),
        ),
    ]);
    std::fs::write(
        kit.dir.path().join("ASN.mmdb"),
        build("GeoLite2-ASN", &[("1.1.1.0", 24, record)]),
    )
    .unwrap();
}

fn observed(kit: &Kit, lines: &[&str], flow: &Flow) -> crate::Observed {
    drive(&kit.compile(lines, 8), &kit.geo, flow, false).observed
}

#[test]
fn geoip_rules_leave_the_codes_they_looked_up() {
    let kit = Kit::new();
    write_geoip(&kit, &[("1.0.0.0", 8, "CN"), ("192.168.0.0", 16, "XX")]);
    let seen = observed(
        &kit,
        &["GEOIP,US,A", "SRC-GEOIP,XX,B", "GEOIP,LAN,C", "MATCH,W"],
        &Flow::ip("1.2.3.4"),
    );
    assert_eq!(seen.dst_geoip, Some(vec!["cn".to_string()]));
    assert_eq!(seen.src_geoip, Some(vec!["xx".to_string()]));
    assert_eq!((seen.src_asn.as_str(), seen.dst_asn.as_str()), ("", ""));

    let seen = observed(&kit, &["GEOIP,US,A", "MATCH,W"], &Flow::ip("9.9.9.9"));
    assert_eq!(seen.dst_geoip, Some(Vec::new()));
    assert_eq!(seen.src_geoip, None);
}

#[test]
fn lan_geoip_and_unresolved_destinations_leave_nothing() {
    let kit = Kit::new();
    write_geoip(&kit, &[("1.0.0.0", 8, "CN")]);
    let seen = observed(&kit, &["GEOIP,LAN,A", "MATCH,W"], &Flow::ip("1.2.3.4"));
    assert_eq!(seen, crate::Observed::default());
    let seen = observed(
        &kit,
        &["GEOIP,CN,A,no-resolve", "MATCH,W"],
        &Flow::domain("a.test"),
    );
    assert_eq!(seen, crate::Observed::default());
}

#[test]
fn a_rule_set_with_a_source_swaps_where_the_codes_land() {
    let kit = Kit::new();
    write_geoip(&kit, &[("1.0.0.0", 8, "CN"), ("192.168.0.0", 16, "XX")]);
    fill(&kit, "inner", Behavior::Classical, &["GEOIP,CN,no-resolve"]);
    let seen = observed(
        &kit,
        &["SRC-IP-CIDR,192.168.0.0/16,A", "MATCH,W"],
        &Flow::ip("1.2.3.4"),
    );
    assert_eq!(seen, crate::Observed::default());
    let seen = observed(
        &kit,
        &["RULE-SET,inner,A,src", "MATCH,W"],
        &Flow::ip("1.2.3.4"),
    );
    assert_eq!(seen.src_geoip, Some(vec!["xx".to_string()]));
    assert_eq!(seen.dst_geoip, None);
}

#[test]
fn a_negated_geoip_matches_every_other_country() {
    let kit = Kit::new();
    write_geoip(&kit, &[("1.0.0.0", 8, "CN"), ("8.0.0.0", 8, "US")]);
    let program = kit.compile(&["GEOIP,!cn,A", "MATCH,W"], 8);
    assert_eq!(accepted(&kit, &program, &Flow::ip("1.2.3.4")), pick(1, "W"));
    assert_eq!(accepted(&kit, &program, &Flow::ip("8.2.3.4")), pick(0, "A"));
    assert_eq!(accepted(&kit, &program, &Flow::ip("9.2.3.4")), pick(0, "A"));
}

#[test]
fn asn_rules_leave_the_number_and_the_organisation() {
    let kit = Kit::new();
    write_asn(&kit);
    let lines = ["IP-ASN,1,A", "MATCH,W"];
    let seen = observed(&kit, &lines, &Flow::ip("1.1.1.1"));
    assert_eq!(seen.dst_asn, "13335 Cloudflare, Inc.");
    let program = kit.compile(&["IP-ASN,13335,A", "MATCH,W"], 8);
    assert_eq!(
        drive(&program, &kit.geo, &Flow::ip("1.1.1.1"), true).accepted,
        pick(0, "A")
    );
    let seen = observed(&kit, &["SRC-IP-ASN,1,A", "MATCH,W"], &Flow::ip("1.1.1.1"));
    assert_eq!(seen.src_asn, "0 ");
    assert_eq!(seen.dst_asn, "");
}

#[test]
fn asn_rules_wait_for_a_missing_database_without_a_recompile() {
    let kit = Kit::new();
    let program = kit.compile(&["IP-ASN,13335,A", "MATCH,W"], 8);
    assert_eq!(program.deferred_geo(), [GeoFile::Asn]);
    assert_eq!(accepted(&kit, &program, &Flow::ip("1.1.1.1")), pick(1, "W"));
    write_asn(&kit);
    kit.geo.reload(GeoFile::Asn).unwrap();
    assert_eq!(accepted(&kit, &program, &Flow::ip("1.1.1.1")), pick(0, "A"));
    assert!(
        kit.compile(&["IP-ASN,13335,A"], 8)
            .deferred_geo()
            .is_empty()
    );
}

#[test]
fn logic_rules_do_not_turn_a_missing_asn_database_into_a_match() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "NOT,((IP-ASN,13335)),N",
            "NOT,((OR,((IP-ASN,13335),(DOMAIN,never.test)))),O",
            "NOT,((AND,((IP-ASN,13335),(DOMAIN,never.test)))),A",
            "MATCH,W",
        ],
        8,
    );
    assert_eq!(accepted(&kit, &program, &Flow::ip("8.8.8.8")), pick(2, "A"));
    write_asn(&kit);
    kit.geo.reload(GeoFile::Asn).unwrap();
    assert_eq!(accepted(&kit, &program, &Flow::ip("8.8.8.8")), pick(0, "N"));
    assert_eq!(accepted(&kit, &program, &Flow::ip("1.1.1.1")), pick(2, "A"));
}

#[test]
fn geosite_reads_the_dat() {
    let kit = Kit::new();
    let line = ["GEOSITE,cn,CN", "MATCH,W"];
    assert_eq!(
        compile_err(&kit, &line, &[]).missing_geo_file(),
        Some(GeoFile::GeoSite)
    );
    std::fs::write(
        kit.dir.path().join("GeoSite.dat"),
        site("cn", &[(2, "baidu.com", &[])]),
    )
    .unwrap();
    let program = kit.compile(&line, 8);
    assert_eq!(
        accepted(&kit, &program, &Flow::domain("www.baidu.com")),
        pick(0, "CN")
    );
    assert_eq!(
        accepted(&kit, &program, &Flow::domain("google.com")),
        pick(1, "W")
    );
    assert!(program.demands().domain && !program.demands().ip);
}

#[test]
fn compile_errors_read_like_mihomo() {
    let kit = Kit::new();
    let err = compile_err(&kit, &["RULE-SET,nope,X"], &[]);
    assert!(matches!(err, CompileError::UnknownRuleSet { .. }), "{err}");
    assert_eq!(
        err.to_string(),
        "rules[0] [RULE-SET,nope,X] error: rule set [nope] not found"
    );

    let err = compile_err(
        &kit,
        &["SUB-RULE,(DOMAIN,a.com),a"],
        &[
            ("a", &["SUB-RULE,(DOMAIN,a.com),b"]),
            ("b", &["SUB-RULE,(DOMAIN,a.com),a"]),
        ],
    );
    assert!(matches!(err, CompileError::SubRuleCycle(_)), "{err}");

    let bad = RuleDef {
        cond: Cond::DomainRegex("(".into()),
        target: "X".into(),
        no_resolve: false,
        src: false,
        text: "DOMAIN-REGEX,(,X".into(),
    };
    let err = RouteProgram::compile(&[bad], &Default::default(), &kit.env(8))
        .err()
        .unwrap();
    assert!(matches!(err, CompileError::Invalid { .. }), "{err}");

    let mut env = kit.env(8);
    env.known_target = Some(Box::new(|name| name == "DIRECT"));
    let rules = defs(&["DOMAIN,a.com,DIRECT", "DOMAIN,b.com,GHOST"]);
    let err = RouteProgram::compile(&rules, &Default::default(), &env)
        .err()
        .unwrap();
    assert!(
        matches!(err, CompileError::UnknownTarget { index: 1, .. }),
        "{err}"
    );
    let sub = defs(&["SUB-RULE,(DOMAIN,a.com),missing"]);
    let err = RouteProgram::compile(&sub, &Default::default(), &env)
        .err()
        .unwrap();
    assert!(matches!(err, CompileError::UnknownSubRule { .. }), "{err}");
}

#[test]
fn demands_and_rule_info() {
    let kit = Kit::new();
    let program = kit.compile(&["DOMAIN-SUFFIX,a.com,A", "NETWORK,udp,B"], 8);
    assert_eq!(
        program.demands(),
        Demands {
            domain: true,
            ..Demands::default()
        }
    );
    let program = kit.compile(
        &[
            "IP-CIDR,10.0.0.0/8,A",
            "PROCESS-NAME,x,B",
            "GEOIP,LAN,C,no-resolve",
        ],
        8,
    );
    assert_eq!(
        program.demands(),
        Demands {
            domain: false,
            ip: true,
            resolve_ip: true,
            process: true,
        }
    );
    assert_eq!(program.len(), 3);
    let info = program.rule_at(crate::RuleRef(0, 0));
    assert_eq!((info.type_name, info.payload), ("IPCIDR", "10.0.0.0/8"));
    let info = program.rule_at(crate::RuleRef(1, 0));
    assert_eq!((info.type_name, info.payload), ("ProcessName", "x"));
    assert!(program.memory_estimate() > 0);

    fill(&kit, "ips", Behavior::IpCidr, &["10.0.0.0/8"]);
    let program = kit.compile(&["RULE-SET,ips,A"], 8);
    assert!(program.demands().resolve_ip);
    let program = kit.compile(&["RULE-SET,ips,A,no-resolve"], 8);
    assert!(program.demands().ip && !program.demands().resolve_ip);
}

#[test]
fn inbound_conditions() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "IN-TYPE,SOCKS,S",
            "IN-NAME,special,N",
            "IN-USER,alice,U",
            "IN-PORT,9000-9100,P",
            "SRC-PORT,50000,SP",
        ],
        8,
    );
    let mut flow = Flow::domain("a.com");
    assert_eq!(accepted(&kit, &program, &flow), pick(4, "SP"));
    flow.kind = concord_common::InboundKind::Socks5;
    assert_eq!(accepted(&kit, &program, &flow), pick(0, "S"));
    flow.kind = concord_common::InboundKind::Http;
    flow.inbound_name = "special";
    assert_eq!(accepted(&kit, &program, &flow), pick(1, "N"));
    flow.inbound_name = "in";
    flow.user = Some("alice");
    assert_eq!(accepted(&kit, &program, &flow), pick(2, "U"));
    flow.user = None;
    flow.in_port = 9050;
    assert_eq!(accepted(&kit, &program, &flow), pick(3, "P"));
}

#[test]
fn rematch_restarts_a_named_list_and_keeps_its_rule_identity() {
    use crate::{MatchCtx, Step};
    use concord_common::RouteState;
    let kit = Kit::new();
    let program = kit.compile_with(
        &["REMATCH-NAME,Next,MAIN", "MATCH,FALLBACK"],
        &[
            ("inner", &["REMATCH-NAME,Next/Other,SUB", "MATCH,MISS"]),
            ("outer", &["SUB-RULE,(NETWORK,tcp),inner"]),
        ],
        8,
    );
    let meta = Flow::domain("example.com").meta();
    let mut state = RouteState::seed(&meta.dst);
    let ctx = MatchCtx::new(&kit.geo);
    let mut run = program.start();
    assert!(matches!(
        run.step(&meta, &state, &ctx),
        Step::Candidate {
            target: "FALLBACK",
            ..
        }
    ));
    state.rematch_name = Some("next".into());
    run.restart(Some("inner"));
    assert!(matches!(
        run.step(&meta, &state, &ctx),
        Step::Candidate { target: "MISS", .. }
    ));
    state.rematch_name = Some("Next".into());
    run.restart(Some("inner"));
    let Step::Candidate { target, rule } = run.step(&meta, &state, &ctx) else {
        panic!("no sub-rule candidate")
    };
    assert_eq!(target, "SUB");
    assert_eq!(program.rule_at(rule).type_name, "RematchName");
    assert_eq!(program.rule_at(rule).payload, "Next/Other");
    run.restart(Some("outer"));
    let Step::Candidate { target, rule } = run.step(&meta, &state, &ctx) else {
        panic!("no nested candidate")
    };
    assert_eq!(target, "SUB");
    assert_eq!(program.rule_at(rule).type_name, "SubRules");
    for name in [None, Some(""), Some("unknown")] {
        run.restart(name);
        let Step::Candidate { target, rule } = run.step(&meta, &state, &ctx) else {
            panic!("no main candidate")
        };
        assert_eq!(target, "MAIN");
        assert_eq!(program.rule_at(rule).payload, "Next");
    }
}
