use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::*;
use crate::{GroupError, Policy};

const NODES: &str = "proxies:
  - {name: a, type: direct}
  - {name: b, type: direct}
  - {name: c, type: direct}
";

fn config(groups: &str) -> String {
    format!("{NODES}proxy-groups:\n{groups}")
}

fn members(rig: &Rig, group: &str) -> Vec<String> {
    let group = rig.out.group(group).expect("group");
    group
        .members()
        .nodes()
        .iter()
        .map(|node| node.name().to_string())
        .collect()
}

const PROVIDER: &str = "proxy-providers:
  p:
    type: inline
    payload:
      - {name: HK-01, type: direct}
      - {name: HK-02, type: direct}
      - {name: US-01, type: direct}
      - {name: JP-01, type: direct}
";

fn with_provider(groups: &str) -> String {
    format!("{PROVIDER}proxy-groups:\n{groups}")
}

#[tokio::test]
async fn a_selector_starts_on_its_first_member_and_follows_select() {
    let rig = Rig::new(&config("  - {name: g, type: select, proxies: [a, b, c]}\n"));
    assert_eq!(rig.leaf("g"), "a");
    let outcome = rig.out.select("g", "c").await;
    assert!(outcome.changed && outcome.message.is_empty());
    assert_eq!(rig.leaf("g"), "c");
    assert_eq!(rig.store.get("g").as_deref(), Some("c"));
}

#[tokio::test]
async fn select_reports_the_go_messages() {
    let rig = Rig::new(&config(
        "  - {name: g, type: select, proxies: [a, b]}\n  - {name: lb, type: load-balance, proxies: [a, b]}\n",
    ));
    assert_eq!(rig.out.select("g", "zzz").await.message, "proxy not exist");
    assert_eq!(rig.out.select("nope", "a").await.message, "Not found group");
    assert_eq!(
        rig.out.select("lb", "a").await.message,
        "Group is not selectable"
    );
    assert_eq!(
        rig.out.select("a", "a").await.message,
        "Group is not selectable"
    );
    assert_eq!(rig.store.get("g"), None);
}

#[tokio::test]
async fn clearing_a_selector_stores_an_empty_pick_and_lands_on_the_first_member() {
    let rig = Rig::new(&config("  - {name: g, type: select, proxies: [a, b]}\n"));
    rig.out.select("g", "b").await;
    let outcome = rig.out.select("g", "").await;
    assert!(outcome.changed);
    assert_eq!(rig.store.get("g").as_deref(), Some(""));
    assert_eq!(rig.leaf("g"), "a");
}

#[tokio::test]
async fn select_moves_the_route_once_per_change() {
    let rig = Rig::new(&config("  - {name: g, type: select, proxies: [a, b]}\n"));
    rig.out.select("g", "b").await;
    let after_first = rig.moved.count();
    assert!(after_first >= 1);
    rig.out.select("g", "b").await;
    assert_eq!(rig.moved.count(), after_first);
}

#[tokio::test]
async fn a_stored_pick_of_a_removed_member_falls_back_to_the_first() {
    let rig = Rig::new(&config("  - {name: g, type: select, proxies: [a, b]}\n"));
    rig.store.set("g", "gone");
    assert_eq!(rig.leaf("g"), "a");
}

#[tokio::test]
async fn nested_groups_resolve_to_a_leaf_with_the_chain() {
    let rig = Rig::new(&config(
        "  - {name: inner, type: select, proxies: [b, c]}\n  - {name: outer, type: select, proxies: [inner, a]}\n",
    ));
    assert_eq!(rig.leaf("outer"), "b");
    assert_eq!(rig.chain("outer"), ["b", "inner", "outer"]);
}

#[tokio::test]
async fn a_cycle_is_refused_at_build() {
    let mut profile = profile(&config(
        "  - {name: g1, type: select, proxies: [a]}\n  - {name: g2, type: select, proxies: [a]}\n",
    ));
    for def in &mut profile.groups {
        match def.name.as_str() {
            "g1" => def.proxies = vec!["g2".into()],
            "g2" => def.proxies = vec!["g1".into()],
            _ => {}
        }
    }
    let built = Rig::try_with(&profile, Arc::new(SelectionStore::new()), None);
    assert!(matches!(built, Err(GroupError::Cycle(_))));
}

#[tokio::test]
async fn a_fallback_takes_the_first_alive_member() {
    let rig = Rig::new(&config(&format!(
        "  - {{name: f, type: fallback, proxies: [a, b, c], url: '{TEST_URL}'}}\n"
    )));
    assert_eq!(rig.leaf("f"), "a");
    rig.book.get("a").fail.store(true, Ordering::SeqCst);
    assert_eq!(rig.test("a").await, -2);
    assert_eq!(rig.leaf("f"), "b");
    rig.book.get("b").fail.store(true, Ordering::SeqCst);
    rig.test("b").await;
    assert_eq!(rig.leaf("f"), "c");
}

#[tokio::test]
async fn a_pinned_fallback_member_is_dropped_once_it_dies() {
    let rig = Rig::new(&config(&format!(
        "  - {{name: f, type: fallback, proxies: [a, b], url: '{TEST_URL}'}}\n"
    )));
    rig.out.select("f", "b").await;
    assert_eq!(rig.leaf("f"), "b");
    rig.book.get("b").fail.store(true, Ordering::SeqCst);
    rig.test("b").await;
    let before = rig.moved.count();
    assert_eq!(rig.leaf("f"), "a");
    assert_eq!(rig.store.get("f"), None);
    assert!(rig.moved.count() > before);
}

#[tokio::test(start_paused = true)]
async fn selecting_a_dead_fallback_member_probes_it_first() {
    let rig = Rig::new(&config(&format!(
        "  - {{name: f, type: fallback, proxies: [a, b], url: '{TEST_URL}'}}\n"
    )));
    rig.book.get("b").fail.store(true, Ordering::SeqCst);
    let node = rig.out.node("b").unwrap();
    node.health()
        .record(TEST_URL, 0, true, false, &rig.out.shared.health_epoch);
    let outcome = rig.out.select("f", "b").await;
    assert!(outcome.message.is_empty());
    assert_eq!(rig.book.get("b").connects.load(Ordering::SeqCst), 1);
    assert_eq!(rig.leaf("f"), "a");
}

#[tokio::test(start_paused = true)]
async fn routing_before_the_probe_of_a_dead_pick_leaves_the_pick_to_the_probe() {
    let rig = Rig::new(&config(&format!(
        "  - {{name: f, type: fallback, proxies: [a, b], url: '{TEST_URL}'}}\n"
    )));
    let node = rig.out.node("b").unwrap();
    node.health()
        .record(TEST_URL, 0, true, false, &rig.out.shared.health_epoch);
    let staged = rig.out.stage_selection("f", "b").unwrap();
    assert_eq!(rig.leaf("f"), "a");
    rig.out.probe_selection(&staged).await;
    let outcome = rig.out.settle_selection(staged);
    assert!(outcome.changed);
    assert_eq!(rig.leaf("f"), "b");
    assert_eq!(rig.store.get("f").as_deref(), Some("b"));
}

#[tokio::test(start_paused = true)]
async fn a_url_test_group_picks_the_fastest_and_keeps_it_within_tolerance() {
    let rig = Rig::new(&config(&format!(
        "  - {{name: wide, type: url-test, proxies: [a, b], url: '{TEST_URL}', tolerance: 100}}\n  - {{name: tight, type: url-test, proxies: [a, b], url: '{TEST_URL}', tolerance: 10}}\n"
    )));
    assert_eq!(
        (rig.leaf("wide").as_str(), rig.leaf("tight").as_str()),
        ("a", "a")
    );
    rig.book.get("a").set_delay(100);
    rig.book.get("b").set_delay(50);
    rig.test("a").await;
    rig.test("b").await;
    assert_eq!(
        (rig.leaf("wide").as_str(), rig.leaf("tight").as_str()),
        ("a", "b")
    );
    rig.book.get("a").set_delay(300);
    rig.test("a").await;
    assert_eq!(
        (rig.leaf("wide").as_str(), rig.leaf("tight").as_str()),
        ("b", "b")
    );
    rig.book.get("a").set_delay(20);
    rig.test("a").await;
    assert_eq!(
        (rig.leaf("wide").as_str(), rig.leaf("tight").as_str()),
        ("b", "a")
    );
}

#[tokio::test(start_paused = true)]
async fn a_url_test_group_skips_dead_members_and_honors_a_pin() {
    let rig = Rig::new(&config(&format!(
        "  - {{name: u, type: url-test, proxies: [a, b, c], url: '{TEST_URL}'}}\n"
    )));
    rig.book.get("a").fail.store(true, Ordering::SeqCst);
    rig.book.get("b").set_delay(80);
    rig.book.get("c").set_delay(30);
    for name in ["a", "b", "c"] {
        rig.test(name).await;
    }
    assert_eq!(rig.leaf("u"), "c");
    rig.out.select("u", "b").await;
    assert_eq!(rig.leaf("u"), "b");
    assert_eq!(rig.out.group("u").unwrap().fixed(), "b");
}

#[tokio::test]
async fn round_robin_alternates_between_members() {
    let rig = Rig::new(&config(
        "  - {name: lb, type: load-balance, strategy: round-robin, proxies: [a, b]}\n",
    ));
    let picks: Vec<String> = (0..4).map(|_| rig.leaf("lb")).collect();
    assert_ne!(picks[0], picks[1]);
    assert_eq!(picks[0], picks[2]);
    assert_eq!(picks[1], picks[3]);
}

#[tokio::test]
async fn consistent_hashing_sticks_to_the_host_and_prefers_the_override() {
    let rig = Rig::new(&config(
        "  - {name: lb, type: load-balance, strategy: consistent-hashing, proxies: [a, b, c]}\n",
    ));
    let at = |dst: &str, host: Option<&str>| match rig.out.resolve(
        "lb",
        &Rig::flow(dst),
        host,
        Touch::Yes,
    ) {
        Resolved::Route { leaf, .. } => leaf.info().name.to_string(),
        _ => String::new(),
    };
    let first = at("www.example.com", None);
    for _ in 0..5 {
        assert_eq!(at("www.example.com", None), first);
    }
    let by_host = at("www.example.com", Some("www.example.com"));
    assert_eq!(by_host, first);
    assert_eq!(at("198.18.0.7", Some("www.example.com")), first);
}

#[tokio::test]
async fn a_load_balancer_is_its_own_exit_identity_and_stops_udp_consulting() {
    let rig = Rig::new(&config(
        "  - {name: lb, type: load-balance, proxies: [a, b]}\n  - {name: s, type: select, proxies: [lb]}\n",
    ));
    let resolved = rig.resolve("s");
    let Resolved::Route {
        exit_group, udp, ..
    } = &resolved
    else {
        panic!("route");
    };
    assert_eq!(exit_group.as_deref(), Some("lb"));
    assert!(*udp);
    assert_eq!(
        rig.out.exit_identity(&resolved).as_deref(),
        Some("\"lb\" LoadBalance ")
    );
}

#[tokio::test]
async fn disable_udp_on_a_group_blocks_udp_below_it() {
    let rig = Rig::new(&config(
        "  - {name: g, type: select, disable-udp: true, proxies: [a]}\n  - {name: h, type: select, proxies: [a]}\n",
    ));
    let udp = |name: &str| matches!(rig.resolve(name), Resolved::Route { udp: true, .. });
    assert!(!udp("g"));
    assert!(udp("h"));
}

#[tokio::test]
async fn udp_support_stops_at_a_load_balancer_and_follows_the_pick_elsewhere() {
    let rig = Rig::new(&config(
        "  - {name: off, type: select, disable-udp: true, proxies: [a]}\n  - {name: lb, type: load-balance, proxies: [off]}\n  - {name: lbo, type: load-balance, disable-udp: true, proxies: [a]}\n  - {name: top, type: select, proxies: [lb]}\n  - {name: fb, type: fallback, proxies: [off], url: 'http://t.test/'}\n",
    ));
    let udp = |name: &str| matches!(rig.resolve(name), Resolved::Route { udp: true, .. });
    assert!(udp("lb"));
    assert!(udp("top"));
    assert!(!udp("lbo"));
    assert!(!udp("fb"));
}

#[tokio::test]
async fn provider_filters_choose_group_members() {
    let rig = Rig::new(&with_provider(
        "  - {name: hk, type: select, use: [p], filter: HK}\n  - {name: look, type: select, use: [p], filter: '(?i)^(?!.*02).*HK'}\n  - {name: nous, type: select, use: [p], exclude-filter: 'US|JP'}\n  - {name: notype, type: select, use: [p], exclude-type: direct}\n",
    ));
    assert_eq!(members(&rig, "hk"), ["HK-01", "HK-02"]);
    assert_eq!(members(&rig, "look"), ["HK-01"]);
    assert_eq!(members(&rig, "nous"), ["HK-01", "HK-02"]);
}

#[tokio::test]
async fn an_emptied_group_falls_back_to_compatible() {
    let rig = Rig::new(&with_provider(
        "  - {name: none, type: select, use: [p], filter: zzz}\n",
    ));
    assert_eq!(rig.leaf("none"), "COMPATIBLE");
}

#[tokio::test]
async fn use_position_orders_provider_nodes_among_the_group_proxies() {
    let rig = Rig::new(&format!(
        "{NODES}{PROVIDER}proxy-groups:\n  - {{name: g, type: select, proxies: [a, b], use: [p], filter: HK, use-position: {{p: 1}}}}\n"
    ));
    assert_eq!(members(&rig, "g"), ["a", "HK-01", "HK-02", "b"]);
}

#[tokio::test]
async fn a_quarantined_provider_node_is_rejected_when_selected() {
    let rig = Rig::new(
        "proxy-providers:
  p:
    type: inline
    payload:
      - {name: good, type: direct}
      - {name: ts, type: tailscale}
proxy-groups:
  - {name: g, type: select, use: [p]}
",
    );
    assert_eq!(members(&rig, "g"), ["good"]);
    assert_eq!(rig.leaf("ts"), "<rejected>");
    rig.store.set("g", "ts");
    assert_eq!(rig.leaf("g"), "<rejected>");
}

#[tokio::test]
async fn a_selector_pinned_on_a_node_the_config_dropped_is_rejected() {
    let rig = Rig::new(
        "proxies:
  - {name: a, type: direct}
  - {name: ts, type: tailscale}
proxy-groups:
  - {name: g, type: select, proxies: [a, ts]}
",
    );
    assert_eq!(rig.leaf("g"), "a");
    rig.store.set("g", "ts");
    assert_eq!(rig.leaf("g"), "<rejected>");
}

#[tokio::test]
async fn a_group_whose_only_members_are_quarantined_is_rejected_unless_it_says_otherwise() {
    let payload = "proxy-providers:
  p:
    type: inline
    payload:
      - {name: ts, type: tailscale}
";
    let rig = Rig::new(&format!(
        "{payload}proxy-groups:\n  - {{name: g, type: select, use: [p]}}\n  - {{name: kept, type: select, use: [p], empty-fallback: DIRECT}}\n"
    ));
    assert_eq!(rig.leaf("g"), "<rejected>");
    assert_eq!(rig.leaf("kept"), "DIRECT");
}

#[tokio::test]
async fn the_policy_names_match_the_wire_types() {
    let rig = Rig::new(&config(
        "  - {name: s, type: select, proxies: [a]}\n  - {name: u, type: url-test, proxies: [a]}\n  - {name: f, type: fallback, proxies: [a]}\n  - {name: l, type: load-balance, proxies: [a]}\n",
    ));
    let kinds: Vec<&str> = ["s", "u", "f", "l"]
        .iter()
        .map(|name| rig.out.group(name).unwrap().type_name())
        .collect();
    assert_eq!(kinds, ["Selector", "URLTest", "Fallback", "LoadBalance"]);
    assert!(matches!(
        rig.out.group("s").unwrap().policy(),
        Policy::Select { .. }
    ));
}

#[tokio::test]
async fn pass_and_pass_rule_resolve_to_their_own_variants_through_a_group() {
    let rig = Rig::new(&config(
        "  - {name: g, type: select, proxies: [PASS, PASS-RULE, a]}\n",
    ));
    assert!(matches!(rig.resolve("PASS"), Resolved::Pass));
    assert!(matches!(rig.resolve("PASS-RULE"), Resolved::PassRule));
    assert!(matches!(rig.resolve("g"), Resolved::Pass));
    rig.out.select("g", "PASS-RULE").await;
    assert!(matches!(rig.resolve("g"), Resolved::PassRule));
}
