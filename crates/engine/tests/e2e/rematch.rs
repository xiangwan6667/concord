use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rematch_through_a_group_restarts_rules_and_preserves_tcp_bytes() {
    let echo = tcp_echo().await;
    let (port, seen) = upstream_socks().await;
    let rig = Rig::new();
    rig.apply(&format!(
        "proxies:\n  - {{name: again, type: rematch, target-rematch-name: next}}\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {port}}}\nproxy-groups:\n  - {{name: pick, type: select, proxies: [again]}}\nrules:\n  - REMATCH-NAME,next,up\n  - MATCH,pick\n"
    )).await.unwrap();
    assert_eq!(rig.kind("again"), "Rematch");
    rig.engine.start_listeners().await;
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(*lock(&seen), vec![echo.to_string()]);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rematch_switches_sub_rules_and_preserves_udp_bytes() {
    let echo = udp_echo().await;
    let rig = Rig::new();
    rig.apply("proxies:\n  - {name: again, type: rematch, target-rematch-name: next, target-sub-rule: inner}\nproxy-groups:\n  - {name: pick, type: select, disable-udp: true, proxies: [again]}\nrules:\n  - MATCH,pick\nsub-rules:\n  inner:\n    - REMATCH-NAME,next,DIRECT\n    - MATCH,REJECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    let session = associate(rig.mixed).await;
    assert!(session.echoes(echo).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rematch_clears_a_sub_rule_and_falls_back_for_an_unknown_name() {
    let echo = tcp_echo().await;
    for destination in ["''", "unknown"] {
        let (port, seen) = upstream_socks().await;
        let rig = Rig::new();
        rig.apply(&format!(
            "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {port}}}\n  - {{name: enter, type: rematch, target-sub-rule: inner}}\n  - {{name: leave, type: rematch, target-rematch-name: done, target-sub-rule: {destination}}}\nrules:\n  - REMATCH-NAME,done,up\n  - MATCH,enter\nsub-rules:\n  inner:\n    - MATCH,leave\n"
        )).await.unwrap();
        rig.engine.start_listeners().await;
        let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
        round_trip(&mut stream).await;
        assert_eq!(*lock(&seen), vec![echo.to_string()]);
        assert!(eventually(|| rig.engine.connection_count() == 1).await);
        let records = rig.engine.connections();
        assert_eq!(records[0].rule.as_ref(), "RematchName");
        assert_eq!(records[0].meta.rematch_name, "done");
        rig.engine.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rematch_cycles_close_without_dialing_the_target() {
    let echo = tcp_echo().await;
    for rules in [
        "rules:\n  - MATCH,a\n",
        "rules:\n  - REMATCH-NAME,a,b\n  - MATCH,pick\n",
    ] {
        let rig = Rig::new();
        rig.apply(&format!(
            "proxies:\n  - {{name: a, type: rematch, target-rematch-name: a}}\n  - {{name: b, type: rematch, target-rematch-name: b}}\nproxy-groups:\n  - {{name: pick, type: select, proxies: [a]}}\n{rules}"
        )).await.unwrap();
        rig.engine.start_listeners().await;
        assert!(refused(rig.mixed, echo).await);
        rig.engine.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rematch_udp_cycle_in_a_udp_disabled_group_does_not_fall_through() {
    let echo = udp_echo().await;
    let rig = Rig::new();
    rig.apply("proxies:\n  - {name: again, type: rematch, target-rematch-name: same}\nproxy-groups:\n  - {name: pick, type: select, disable-udp: true, proxies: [again]}\nrules:\n  - MATCH,pick\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    let session = associate(rig.mixed).await;
    assert!(!session.echoes(echo).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rematch_empty_name_clears_the_name_and_preserves_the_sub_rule() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply("proxies:\n  - {name: enter, type: rematch, target-rematch-name: next, target-sub-rule: inner}\n  - {name: clear, type: rematch, target-rematch-name: ''}\nrules:\n  - MATCH,enter\nsub-rules:\n  inner:\n    - REMATCH-NAME,next,clear\n    - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert!(eventually(|| rig.engine.connection_count() == 1).await);
    let records = rig.engine.connections();
    assert_eq!(records[0].meta.special_rules, "inner");
    assert!(records[0].meta.rematch_name.is_empty());
    rig.engine.shutdown().await;
}
