mod alloc;
mod shared_dial;
pub(super) mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use concord_common::{Address, HostResolver, Initiator, IpVersion};
use concord_config::dns::{EnhancedMode, FakeIpFilterMode, PolicyEntry, PolicyKey};
use concord_config::hosts::{HostEntry, HostValue as ConfigHostValue, HostsConfig};
use concord_config::net::IpCidr;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::svcb::{
    Alpn, EchConfigList, IpHint, SVCB, SvcParamKey, SvcParamValue,
};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use support::*;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

async fn lookup_v4(resolver: &crate::Resolver, host: &str) -> std::io::Result<Vec<IpAddr>> {
    resolver
        .lookup(host, IpVersion::Ipv4, Initiator::App)
        .await
        .map(|found| found.v4)
}

#[tokio::test]
async fn a_udp_upstream_answers_and_the_record_names_it() {
    let server = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let (resolver, sink) = build(&config(&[server.udp_url()]));
    let got = resolver
        .lookup("one.test", IpVersion::Ipv4, Initiator::Direct)
        .await
        .unwrap();
    assert_eq!(got.v4, vec![ip("10.0.0.1")]);
    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].upstream, server.udp_url());
    assert_eq!(records[0].initiator, Initiator::Direct);
    assert_eq!(records[0].domain, "one.test");
    assert_eq!(records[0].qtype, "A");
    assert_eq!(records[0].rcode, "NOERROR");
    assert_eq!(records[0].answers, vec!["10.0.0.1".to_string()]);
    assert!(!records[0].cached);
}

#[tokio::test]
async fn a_tcp_upstream_answers() {
    let server = serve_tcp(answer_with(Ipv4Addr::new(10, 0, 0, 2))).await;
    let (resolver, _) = build(&config(&[server.tcp_url()]));
    assert_eq!(
        lookup_v4(&resolver, "two.test").await.unwrap(),
        vec![ip("10.0.0.2")]
    );
}

#[tokio::test]
async fn a_dot_upstream_answers_and_reuses_its_connection() {
    let server = serve_tls(answer_with(Ipv4Addr::new(10, 0, 0, 3))).await;
    let url = format!("tls://{}#skip-cert-verify=true", server.addr);
    let (resolver, _) = build(&config(&[url]));
    assert_eq!(
        lookup_v4(&resolver, "a.dot.test").await.unwrap(),
        vec![ip("10.0.0.3")]
    );
    assert_eq!(
        lookup_v4(&resolver, "b.dot.test").await.unwrap(),
        vec![ip("10.0.0.3")]
    );
    assert_eq!(server.hits(), 2);
}

#[tokio::test]
async fn a_doq_upstream_answers_over_one_connection() {
    let server = serve_quic(answer_with(Ipv4Addr::new(10, 0, 0, 7))).await;
    let (resolver, _) = build(&config(&[format!(
        "quic://127.0.0.1:{}#skip-cert-verify=true",
        server.addr.port()
    )]));
    assert_eq!(
        lookup_v4(&resolver, "a.doq.test").await.unwrap(),
        vec![ip("10.0.0.7")]
    );
    assert_eq!(
        lookup_v4(&resolver, "b.doq.test").await.unwrap(),
        vec![ip("10.0.0.7")]
    );
    assert_eq!(server.hits(), 2);
}

#[tokio::test]
async fn a_doh_upstream_with_h3_true_speaks_http3() {
    let server = serve_h3(answer_with(Ipv4Addr::new(10, 0, 0, 8))).await;
    let url = format!(
        "https://127.0.0.1:{}/dns-query#skip-cert-verify=true&h3=true",
        server.addr.port()
    );
    let (resolver, _) = build(&config(&[url]));
    assert_eq!(
        lookup_v4(&resolver, "a.doh3.test").await.unwrap(),
        vec![ip("10.0.0.8")]
    );
    assert_eq!(
        lookup_v4(&resolver, "b.doh3.test").await.unwrap(),
        vec![ip("10.0.0.8")]
    );
    assert_eq!(server.hits(), 2);
}

#[tokio::test]
async fn prefer_h3_uses_http3_when_it_answers_first_and_h2_otherwise() {
    let server = serve_h3(answer_with(Ipv4Addr::new(10, 0, 0, 9))).await;
    let url = format!(
        "https://127.0.0.1:{}/dns-query#skip-cert-verify=true",
        server.addr.port()
    );
    let mut cfg = config(&[url]);
    cfg.prefer_h3 = true;
    let (resolver, _) = build(&cfg);
    assert_eq!(
        lookup_v4(&resolver, "a.prefer.test").await.unwrap(),
        vec![ip("10.0.0.9")]
    );
    assert_eq!(server.hits(), 1);
}

async fn over_outbound(url: String, via: &str) -> (Vec<IpAddr>, Vec<(String, Address)>) {
    let dialer = UdpDialer::new(&["DIRECT", "node"]);
    let mut cfg = config(&[url]);
    cfg.prefer_h3 = true;
    let resolver = build_over(&cfg, &dialer);
    let mut answers = Vec::new();
    for host in ["a.over.test", "b.over.test"] {
        answers = lookup_v4(&resolver, host)
            .await
            .unwrap_or_else(|err| panic!("{via}: {err}"));
    }
    (answers, dialer.asked())
}

#[tokio::test]
async fn doh3_and_doq_go_through_the_outbound_they_name_direct_included() {
    for via in ["DIRECT", "node"] {
        let h3 = serve_h3(answer_with(Ipv4Addr::new(10, 0, 1, 1))).await;
        let quic = serve_quic(answer_with(Ipv4Addr::new(10, 0, 1, 2))).await;
        let cases = [
            (
                format!(
                    "https://127.0.0.1:{}/dns-query#{via}&skip-cert-verify=true&h3=true",
                    h3.addr.port()
                ),
                h3.addr,
                "10.0.1.1",
            ),
            (
                format!(
                    "https://127.0.0.1:{}/dns-query#skip-cert-verify=true&{via}",
                    h3.addr.port()
                ),
                h3.addr,
                "10.0.1.1",
            ),
            (
                format!(
                    "quic://127.0.0.1:{}#{via}&skip-cert-verify=true",
                    quic.addr.port()
                ),
                quic.addr,
                "10.0.1.2",
            ),
        ];
        for (url, server, answer) in cases {
            let (got, asked) = over_outbound(url.clone(), via).await;
            assert_eq!(got, vec![ip(answer)], "{url}");
            assert_eq!(
                asked,
                vec![(via.to_string(), Address::Socket(server))],
                "{url}"
            );
        }
        assert_eq!(h3.hits(), 4, "{via}");
        assert_eq!(quic.hits(), 2, "{via}");
    }
}

#[tokio::test]
async fn doq_through_an_outbound_without_udp_fails_with_its_error() {
    let quic = serve_quic(answer_with(Ipv4Addr::new(10, 0, 1, 3))).await;
    let dialer = Arc::new(NodeDialer {
        server: quic.addr,
        own_server: None,
        resolver: std::sync::OnceLock::new(),
    });
    let url = format!(
        "quic://127.0.0.1:{}#node&skip-cert-verify=true",
        quic.addr.port()
    );
    let resolver = build_through(&config(&[url]), &dialer);
    let err = lookup_v4(&resolver, "c.over.test").await.unwrap_err();
    assert!(err.to_string().contains("no udp through the node"), "{err}");
    assert_eq!(quic.hits(), 0);
}

/// `CONCORD_DOH3_PEER` is the UDP port of a quic-go HTTP/3 server answering every A query
/// with 10.9.8.7 on `/dns-query`.
#[tokio::test]
#[ignore = "needs a DoH3 server from quic-go"]
async fn a_quic_go_doh3_server_answers() {
    let port = std::env::var("CONCORD_DOH3_PEER").unwrap();
    for (setting, h3) in [("h3=true", true), ("", false)] {
        let url = format!("https://127.0.0.1:{port}/dns-query#skip-cert-verify=true&{setting}");
        let mut cfg = config(&[url]);
        cfg.prefer_h3 = !h3;
        let (resolver, _) = build(&cfg);
        assert_eq!(
            lookup_v4(&resolver, "a.peer.test").await.unwrap(),
            vec![ip("10.9.8.7")]
        );
        assert_eq!(
            lookup_v4(&resolver, "b.peer.test").await.unwrap(),
            vec![ip("10.9.8.7")]
        );
    }
}

#[tokio::test]
async fn a_doh_upstream_answers() {
    let server = serve_doh(answer_with(Ipv4Addr::new(10, 0, 0, 4))).await;
    let url = format!("http://{}/dns-query", server.addr);
    let (resolver, _) = build(&config(&[url]));
    assert_eq!(
        lookup_v4(&resolver, "doh.test").await.unwrap(),
        vec![ip("10.0.0.4")]
    );
    assert_eq!(server.hits(), 1);
}

#[tokio::test]
async fn a_silent_upstream_times_out() {
    let server = serve_udp(silent(), Duration::ZERO).await;
    let (resolver, sink) = build(&config(&[server.udp_url()]));
    let start = Instant::now();
    let err = lookup_v4(&resolver, "silent.test").await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(start.elapsed() >= Duration::from_secs(4));
    assert!(sink.records().iter().all(|r| !r.error.is_empty()));
}

#[tokio::test]
async fn running_out_of_descriptors_survives_the_batch_and_the_flight() {
    let sink = Arc::new(Sink::default());
    let mut deps = deps(&sink);
    let platform = Arc::new(Pressured);
    deps.sockets = Arc::new(concord_net::Sockets::new(platform.clone()));
    deps.platform = platform;
    let resolver = crate::Resolver::new(
        &config(&["udp://127.0.0.1:53".into()]),
        &HostsConfig::default(),
        deps,
    )
    .unwrap();
    let err = lookup_v4(&resolver, "pressure.test").await.unwrap_err();
    assert!(concord_platform::is_local_exhaustion(&err), "{err}");
    assert!(
        err.to_string()
            .starts_with("all DNS requests failed, first error: ")
    );
}

#[tokio::test]
async fn another_upstream_answers_when_the_first_is_silent() {
    let dead = serve_udp(silent(), Duration::ZERO).await;
    let live = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 5)), Duration::ZERO).await;
    let (resolver, sink) = build(&config(&[dead.udp_url(), live.udp_url()]));
    let start = Instant::now();
    assert_eq!(
        lookup_v4(&resolver, "fail.test").await.unwrap(),
        vec![ip("10.0.0.5")]
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(sink.records()[0].upstream, live.udp_url());
}

#[tokio::test]
async fn a_server_failure_loses_to_a_good_answer() {
    let failing = serve_udp(
        Arc::new(|req| Some(crate::msg::error_reply(req, ResponseCode::ServFail))),
        Duration::ZERO,
    )
    .await;
    let live = serve_udp(
        answer_with(Ipv4Addr::new(10, 0, 0, 6)),
        Duration::from_millis(100),
    )
    .await;
    let (resolver, _) = build(&config(&[failing.udp_url(), live.udp_url()]));
    assert_eq!(
        lookup_v4(&resolver, "sf.test").await.unwrap(),
        vec![ip("10.0.0.6")]
    );
}

#[tokio::test]
async fn nameserver_policy_is_matched_in_document_order() {
    let general = serve_udp(answer_with(Ipv4Addr::new(10, 1, 0, 1)), Duration::ZERO).await;
    let corp = serve_udp(answer_with(Ipv4Addr::new(10, 1, 0, 2)), Duration::ZERO).await;
    let special = serve_udp(answer_with(Ipv4Addr::new(10, 1, 0, 3)), Duration::ZERO).await;
    let mut cfg = config(&[general.udp_url()]);
    cfg.nameserver_policy = vec![
        PolicyEntry {
            key: PolicyKey::Domain("vip.corp.test".into()),
            servers: vec![up(&special.udp_url())],
        },
        PolicyEntry {
            key: PolicyKey::Domain("+.corp.test".into()),
            servers: vec![up(&corp.udp_url())],
        },
    ];
    let (resolver, _) = build(&cfg);
    assert_eq!(
        lookup_v4(&resolver, "vip.corp.test").await.unwrap(),
        vec![ip("10.1.0.3")]
    );
    assert_eq!(
        lookup_v4(&resolver, "www.corp.test").await.unwrap(),
        vec![ip("10.1.0.2")]
    );
    assert_eq!(
        lookup_v4(&resolver, "other.test").await.unwrap(),
        vec![ip("10.1.0.1")]
    );
}

#[tokio::test]
async fn proxy_server_names_use_the_proxy_server_nameserver() {
    let main = serve_udp(answer_with(Ipv4Addr::new(10, 2, 0, 1)), Duration::ZERO).await;
    let proxy = serve_udp(answer_with(Ipv4Addr::new(10, 2, 0, 2)), Duration::ZERO).await;
    let direct = serve_udp(answer_with(Ipv4Addr::new(10, 2, 0, 3)), Duration::ZERO).await;
    let mut cfg = config(&[main.udp_url()]);
    cfg.proxy_server_nameserver = vec![up(&proxy.udp_url())];
    cfg.direct_nameserver = vec![up(&direct.udp_url())];
    let (resolver, _) = build(&cfg);
    let ask = |initiator| resolver.lookup("g.test", IpVersion::Ipv4, initiator);
    assert_eq!(
        ask(Initiator::Proxy).await.unwrap().v4,
        vec![ip("10.2.0.2")]
    );
    assert_eq!(
        ask(Initiator::Direct).await.unwrap().v4,
        vec![ip("10.2.0.3")]
    );
    assert_eq!(ask(Initiator::Rule).await.unwrap().v4, vec![ip("10.2.0.1")]);
}

async fn through_node(
    asked: &str,
    own_server: Option<&'static str>,
) -> std::io::Result<Vec<IpAddr>> {
    let main = serve_udp(answer_with(Ipv4Addr::new(10, 2, 1, 1)), Duration::ZERO).await;
    let proxy = serve_tcp(answer_with(Ipv4Addr::new(10, 2, 1, 2))).await;
    let mut cfg = config(&[main.udp_url()]);
    cfg.proxy_server_nameserver = vec![up(&format!("{}#node", proxy.tcp_url()))];
    let dialer = Arc::new(NodeDialer {
        server: proxy.addr,
        own_server,
        resolver: std::sync::OnceLock::new(),
    });
    let resolver = build_through(&cfg, &dialer);
    resolver
        .lookup(asked, IpVersion::Ipv4, Initiator::Proxy)
        .await
        .map(|found| found.v4)
}

#[tokio::test]
async fn a_proxy_server_name_may_be_resolved_through_a_node() {
    assert_eq!(
        through_node("server.test", None).await.unwrap(),
        vec![ip("10.2.1.2")]
    );
}

#[tokio::test]
async fn a_node_that_resolves_its_own_server_through_itself_is_a_loop() {
    for asked in ["server.test", "node.test"] {
        let started = Instant::now();
        let err = through_node(asked, Some("node.test")).await.unwrap_err();
        assert!(
            err.to_string().contains("dialer proxy loop through node"),
            "{asked}: {err}"
        );
        assert!(started.elapsed() < Duration::from_secs(1), "{asked}");
    }
}

#[tokio::test]
async fn hosts_win_over_upstreams_and_literals_are_not_asked() {
    let server = serve_udp(answer_with(Ipv4Addr::new(10, 3, 0, 1)), Duration::ZERO).await;
    let hosts = HostsConfig {
        entries: vec![
            HostEntry {
                domain: "pinned.test".into(),
                value: ConfigHostValue::Ips(vec![ip("192.0.2.9"), ip("2001:db8::9")]),
            },
            HostEntry {
                domain: "alias.test".into(),
                value: ConfigHostValue::Domain("pinned.test".into()),
            },
        ],
    };
    let (resolver, _) = build_with_hosts(&config(&[server.udp_url()]), &hosts);
    let found = resolver
        .lookup("alias.test", IpVersion::Dual, Initiator::App)
        .await
        .unwrap();
    assert_eq!(
        (found.v4, found.v6),
        (vec![ip("192.0.2.9")], vec![ip("2001:db8::9")])
    );
    let literal = resolver
        .lookup("[::1]", IpVersion::Dual, Initiator::App)
        .await
        .unwrap();
    assert_eq!(literal.v6, vec![ip("::1")]);
    assert!(
        resolver
            .lookup("1.2.3.4", IpVersion::Ipv6, Initiator::App)
            .await
            .is_err()
    );
    assert_eq!(server.hits(), 0);
    let (value, ok) = resolver.hosts().search("alias.test", true);
    assert!(ok && value.unwrap().domain == "pinned.test");
}

#[tokio::test]
async fn identical_concurrent_questions_make_one_upstream_query() {
    let server = serve_udp(
        answer_with(Ipv4Addr::new(10, 4, 0, 1)),
        Duration::from_millis(300),
    )
    .await;
    let (resolver, sink) = build(&config(&[server.udp_url()]));
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let resolver = Arc::clone(&resolver);
        tasks.push(tokio::spawn(async move {
            resolver
                .lookup("flight.test", IpVersion::Ipv4, Initiator::App)
                .await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap().v4, vec![ip("10.4.0.1")]);
    }
    assert_eq!(server.hits(), 1);
    assert_eq!(sink.records().iter().filter(|r| !r.cached).count(), 1);
}

#[tokio::test]
async fn a_cache_hit_reports_the_upstream_that_answered_and_clear_cache_forgets() {
    let server = serve_udp(answer_with(Ipv4Addr::new(10, 5, 0, 1)), Duration::ZERO).await;
    let (resolver, sink) = build(&config(&[server.udp_url()]));
    lookup_v4(&resolver, "cache.test").await.unwrap();
    lookup_v4(&resolver, "cache.test").await.unwrap();
    assert_eq!(server.hits(), 1);
    let records = sink.records();
    assert_eq!(records.len(), 2);
    assert!(!records[0].cached && records[1].cached);
    assert_eq!(records[1].upstream, server.udp_url());
    assert_eq!(records[1].answers, vec!["10.5.0.1".to_string()]);
    resolver.clear_cache();
    lookup_v4(&resolver, "cache.test").await.unwrap();
    assert_eq!(server.hits(), 2);
}

#[tokio::test]
async fn a_failed_exchange_is_retried_once_in_the_background() {
    let server = serve_udp(
        Arc::new(|req| Some(crate::msg::error_reply(req, ResponseCode::ServFail))),
        Duration::ZERO,
    )
    .await;
    let (resolver, sink) = build(&config(&[server.udp_url()]));
    assert!(lookup_v4(&resolver, "retry.test").await.is_err());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(server.hits(), 2);
    assert_eq!(sink.records().len(), 2);
}

#[tokio::test]
async fn the_last_system_servers_win_and_an_empty_list_means_none() {
    let first = serve_udp(answer_with(Ipv4Addr::new(10, 6, 0, 1)), Duration::ZERO).await;
    let second = serve_udp(answer_with(Ipv4Addr::new(10, 6, 0, 2)), Duration::ZERO).await;
    let (resolver, _) = build(&config(&["system://".to_string()]));
    resolver.set_system_servers(vec![first.addr]);
    resolver.set_system_servers(vec![second.addr]);
    assert_eq!(
        lookup_v4(&resolver, "sys.test").await.unwrap(),
        vec![ip("10.6.0.2")]
    );
    assert_eq!(first.hits(), 0);
    resolver.set_system_servers(vec![first.addr]);
    assert_eq!(
        lookup_v4(&resolver, "sys.test").await.unwrap(),
        vec![ip("10.6.0.1")]
    );
    resolver.set_system_servers(Vec::new());
    assert!(lookup_v4(&resolver, "none.test").await.is_err());
}

#[tokio::test]
async fn disable_ipv6_answers_empty_without_asking() {
    let server = serve_udp(answer_with(Ipv4Addr::new(10, 7, 0, 1)), Duration::ZERO).await;
    let url = format!("{}#disable-ipv6=true", server.udp_url());
    let (resolver, _) = build(&config(&[url]));
    let reply = resolver
        .handle_query(&query_bytes("v6.test", RecordType::AAAA), Initiator::App)
        .await
        .unwrap();
    assert!(parse(&reply).answers.is_empty());
    assert_eq!(server.hits(), 0);
}

#[tokio::test]
async fn an_rcode_upstream_answers_with_its_code() {
    let (resolver, _) = build(&config(&["rcode://refused".to_string()]));
    let reply = resolver
        .handle_query(&query_bytes("no.test", RecordType::A), Initiator::App)
        .await
        .unwrap();
    assert_eq!(parse(&reply).metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn the_fallback_answers_when_the_main_answer_is_filtered() {
    let main = serve_udp(answer_with(Ipv4Addr::new(240, 0, 0, 1)), Duration::ZERO).await;
    let fallback = serve_udp(
        answer_with(Ipv4Addr::new(10, 8, 0, 1)),
        Duration::from_millis(50),
    )
    .await;
    let mut cfg = config(&[main.udp_url()]);
    cfg.fallback = vec![up(&fallback.udp_url())];
    cfg.fallback_filter.ipcidr = vec![IpCidr::parse("240.0.0.0/4").unwrap()];
    let (resolver, _) = build(&cfg);
    assert_eq!(
        lookup_v4(&resolver, "fb.test").await.unwrap(),
        vec![ip("10.8.0.1")]
    );
    let (resolver, _) = build(&{
        let mut cfg = cfg.clone();
        cfg.fallback_filter.ipcidr = vec![IpCidr::parse("203.0.113.0/24").unwrap()];
        cfg
    });
    assert_eq!(
        lookup_v4(&resolver, "fb.test").await.unwrap(),
        vec![ip("240.0.0.1")]
    );
}

#[tokio::test]
async fn a_geoip_fallback_filter_without_a_code_is_skipped() {
    let main = serve_udp(answer_with(Ipv4Addr::new(240, 0, 0, 1)), Duration::ZERO).await;
    let fallback = serve_udp(answer_with(Ipv4Addr::new(10, 8, 0, 1)), Duration::ZERO).await;
    let mut cfg = config(&[main.udp_url()]);
    cfg.fallback = vec![up(&fallback.udp_url())];
    cfg.fallback_filter.geoip = true;
    let (resolver, _) = build(&cfg);
    assert_eq!(
        lookup_v4(&resolver, "fb.test").await.unwrap(),
        vec![ip("240.0.0.1")]
    );
}

fn fake_ip_config(upstream: String) -> concord_config::dns::DnsConfig {
    let mut cfg = config(&[upstream]);
    cfg.enhanced_mode = EnhancedMode::FakeIp;
    cfg.fake_ip_range = IpCidr::parse("198.18.0.1/16");
    cfg.fake_ip_ttl = 1;
    cfg
}

async fn ask_a(resolver: &crate::Resolver, host: &str) -> Message {
    let reply = resolver
        .handle_query(&query_bytes(host, RecordType::A), Initiator::App)
        .await
        .unwrap();
    parse(&reply)
}

fn first_a(message: &Message) -> Option<IpAddr> {
    crate::msg::answer_ips(message).first().copied()
}

#[test]
fn a_disabled_dns_hands_out_no_fake_ips() {
    let mut cfg = fake_ip_config("udp://127.0.0.1:53".to_string());
    cfg.enable = false;
    let (resolver, _) = build(&cfg);
    assert!(!resolver.fake_ip_enabled());
    assert!(!resolver.mapping_enabled());
    assert!(!resolver.is_fake_ip(ip("198.18.0.5")));
}

#[tokio::test]
async fn fake_ip_allocates_in_order_and_reverses() {
    let server = serve_udp(answer_with(Ipv4Addr::new(10, 9, 0, 1)), Duration::ZERO).await;
    let mut cfg = fake_ip_config(server.udp_url());
    cfg.ipv6 = false;
    let (resolver, sink) = build(&cfg);
    assert_eq!(resolver.mode(), concord_common::DnsMode::FakeIp);
    let first = ask_a(&resolver, "a.fake.test").await;
    assert_eq!(first_a(&first), Some(ip("198.18.0.4")));
    assert_eq!(first.answers[0].ttl, 1);
    assert_eq!(
        first_a(&ask_a(&resolver, "A.fake.test").await),
        Some(ip("198.18.0.4"))
    );
    assert_eq!(
        first_a(&ask_a(&resolver, "b.fake.test").await),
        Some(ip("198.18.0.5"))
    );
    assert_eq!(
        resolver.fake_ip_reverse(ip("198.18.0.5")).as_deref(),
        Some("b.fake.test")
    );
    assert_eq!(
        resolver.find_host_by_ip(ip("198.18.0.4")).as_deref(),
        Some("a.fake.test")
    );
    assert!(resolver.is_fake_ip(ip("198.18.0.4")) && !resolver.is_fake_ip(ip("198.18.0.1")));
    assert!(resolver.is_exist_fake_ip(ip("198.18.0.4")));
    assert!(resolver.is_fake_broadcast_ip(ip("198.18.255.255")));
    assert!(resolver.mapping_enabled());
    assert_eq!(server.hits(), 0);
    assert!(sink.records().is_empty());
    let aaaa = resolver
        .handle_query(
            &query_bytes("a.fake.test", RecordType::AAAA),
            Initiator::App,
        )
        .await
        .unwrap();
    assert!(parse(&aaaa).answers.is_empty());
    resolver.flush_fake_ip();
    assert!(resolver.fake_ip_reverse(ip("198.18.0.4")).is_none());
}

#[tokio::test]
async fn a_burst_of_fake_ips_is_one_snapshot_that_keeps_every_mapping() {
    let mut cfg = fake_ip_config("udp://127.0.0.1:53".to_string());
    cfg.ipv6 = false;
    let (resolver, _) = build(&cfg);
    let ready = || tokio::time::timeout(Duration::ZERO, resolver.fake_ip_changed());
    assert!(ready().await.is_err());
    let mut mapped = Vec::new();
    for n in 0..50 {
        let host = format!("h{n}.fake.test");
        let addr = first_a(&ask_a(&resolver, &host).await).unwrap();
        mapped.push((host, addr));
    }
    assert!(ready().await.is_ok());
    let pending: Vec<_> = resolver
        .fake_ip_pools()
        .filter_map(|(name, pool)| Some((name, pool, pool.pending()?)))
        .collect();
    assert_eq!(pending.len(), 1);
    let (file, pool, (version, bytes)) = &pending[0];
    assert!(ready().await.is_err());
    assert!(pool.pending().is_some());
    pool.mark_saved(*version);
    assert!(pool.pending().is_none());

    let (restored, _) = build(&cfg);
    restored.restore_fake_ip(|name| (name == *file).then(|| bytes.clone()));
    for (host, addr) in &mapped {
        assert_eq!(
            restored.fake_ip_reverse(*addr).as_deref(),
            Some(host.as_str())
        );
    }
}

#[tokio::test]
async fn fake_ip_filter_modes() {
    let server = serve_udp(answer_with(Ipv4Addr::new(10, 9, 1, 1)), Duration::ZERO).await;
    let real = Some(ip("10.9.1.1"));

    let mut blacklist = fake_ip_config(server.udp_url());
    blacklist.fake_ip_filter = vec!["+.lan".into()];
    let (resolver, _) = build(&blacklist);
    assert_eq!(first_a(&ask_a(&resolver, "nas.lan").await), real);
    assert!(resolver.is_fake_ip(first_a(&ask_a(&resolver, "web.test").await).unwrap()));

    let mut whitelist = fake_ip_config(server.udp_url());
    whitelist.fake_ip_filter = vec!["+.only.test".into()];
    whitelist.fake_ip_filter_mode = FakeIpFilterMode::Whitelist;
    let (resolver, _) = build(&whitelist);
    assert!(resolver.is_fake_ip(first_a(&ask_a(&resolver, "x.only.test").await).unwrap()));
    assert_eq!(first_a(&ask_a(&resolver, "else.test").await), real);

    let mut rules = fake_ip_config(server.udp_url());
    rules.fake_ip_filter_mode = FakeIpFilterMode::Rule;
    rules.fake_ip_filter_rules = [
        "DOMAIN-SUFFIX,lan,real-ip",
        "DOMAIN-KEYWORD,stun,real-ip",
        "MATCH,fake-ip",
    ]
    .iter()
    .map(|line| concord_config::parse_rule(line).unwrap())
    .collect();
    let (resolver, _) = build(&rules);
    assert_eq!(first_a(&ask_a(&resolver, "a.lan").await), real);
    assert_eq!(first_a(&ask_a(&resolver, "stun.example").await), real);
    assert!(resolver.is_fake_ip(first_a(&ask_a(&resolver, "other.example").await).unwrap()));
}

fn https_with_hints(req: &Message) -> Option<Message> {
    let query = req.queries.first()?;
    let mut resp = crate::msg::empty_answer(req);
    let params = vec![
        (
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["h3".into()])),
        ),
        (
            SvcParamKey::Ipv4Hint,
            SvcParamValue::Ipv4Hint(IpHint(vec![A::new(192, 0, 2, 1)])),
        ),
    ];
    let svcb = SVCB::new(1, Name::root(), params);
    resp.answers.push(Record::from_rdata(
        query.name.clone(),
        60,
        RData::HTTPS(hickory_proto::rr::rdata::HTTPS(svcb)),
    ));
    Some(resp)
}

fn has_hint(message: &Message) -> bool {
    message.answers.iter().any(|record| match &record.data {
        RData::HTTPS(https) => https
            .0
            .svc_params
            .iter()
            .any(|(key, _)| matches!(key, SvcParamKey::Ipv4Hint | SvcParamKey::Ipv6Hint)),
        _ => false,
    })
}

#[tokio::test]
async fn fake_ip_strips_address_hints_and_answers_empty_for_faked_names() {
    let server = serve_udp(Arc::new(https_with_hints), Duration::ZERO).await;
    let mut cfg = fake_ip_config(server.udp_url());
    cfg.fake_ip_filter = vec!["+.real.test".into()];
    let (resolver, _) = build(&cfg);
    let ask = |host: &'static str| {
        let resolver = Arc::clone(&resolver);
        async move {
            let reply = resolver
                .handle_query(&query_bytes(host, RecordType::HTTPS), Initiator::App)
                .await
                .unwrap();
            parse(&reply)
        }
    };
    let faked = ask("faked.test").await;
    assert!(faked.answers.is_empty());
    assert_eq!(server.hits(), 0);
    let real = ask("www.real.test").await;
    assert_eq!(real.answers.len(), 1);
    assert!(!has_hint(&real));
    match &real.answers[0].data {
        RData::HTTPS(https) => assert!(
            https
                .0
                .svc_params
                .iter()
                .any(|(key, _)| matches!(key, SvcParamKey::Alpn)),
            "alpn is kept"
        ),
        other => panic!("{other:?}"),
    }
}

fn https_with_both_hints(req: &Message) -> Option<Message> {
    let mut resp = https_with_hints(req)?;
    if let RData::HTTPS(https) = &mut resp.answers.first_mut()?.data {
        https.0.svc_params.push((
            SvcParamKey::Ipv6Hint,
            SvcParamValue::Ipv6Hint(IpHint(vec![AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)])),
        ));
    }
    Some(resp)
}

fn hint_keys(message: &Message) -> Vec<SvcParamKey> {
    match &message.answers[0].data {
        RData::HTTPS(https) => https
            .0
            .svc_params
            .iter()
            .map(|(key, _)| *key)
            .filter(|key| matches!(key, SvcParamKey::Ipv4Hint | SvcParamKey::Ipv6Hint))
            .collect(),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn disabled_ipv6_strips_only_the_ipv6_hint_from_https_answers() {
    let server = serve_udp(Arc::new(https_with_both_hints), Duration::ZERO).await;
    for (ipv6, expected) in [
        (false, vec![SvcParamKey::Ipv4Hint]),
        (true, vec![SvcParamKey::Ipv4Hint, SvcParamKey::Ipv6Hint]),
    ] {
        let mut cfg = config(&[server.udp_url()]);
        cfg.ipv6 = ipv6;
        let (resolver, _) = build(&cfg);
        let reply = resolver
            .handle_query(
                &query_bytes("www.hint.test", RecordType::HTTPS),
                Initiator::App,
            )
            .await
            .unwrap();
        assert_eq!(hint_keys(&parse(&reply)), expected, "ipv6 {ipv6}");
    }
}

#[tokio::test]
async fn a_server_failure_answer_echoes_edns() {
    let (resolver, _) = build(&config(&["tcp://127.0.0.1:1".to_string()]));
    let mut query = crate::msg::build_query("down.test", RecordType::A).unwrap();
    query.edns = Some(hickory_proto::op::Edns::new());
    let reply = resolver
        .handle_query(&query.to_vec().unwrap(), Initiator::App)
        .await
        .unwrap();
    let reply = parse(&reply);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(reply.edns.is_some());
}

#[tokio::test]
async fn a_datagram_that_does_not_answer_the_question_is_ignored() {
    let right = answer_with(Ipv4Addr::new(10, 0, 0, 9));
    let server = serve_udp_sequence(Arc::new(move |req| {
        let mut elsewhere = right(req).unwrap();
        elsewhere.queries[0].name = Name::from_ascii("other.test.").unwrap();
        let mut not_a_response = right(req).unwrap();
        not_a_response.metadata.message_type = MessageType::Query;
        vec![elsewhere, not_a_response, right(req).unwrap()]
    }))
    .await;
    let (resolver, _) = build(&config(&[server.udp_url()]));
    assert_eq!(
        lookup_v4(&resolver, "Real.Test").await.unwrap(),
        vec![ip("10.0.0.9")]
    );
}

#[tokio::test]
async fn redir_host_remembers_answers_and_hosts_answer_the_server_path() {
    let server = serve_udp(answer_with(Ipv4Addr::new(93, 184, 216, 34)), Duration::ZERO).await;
    let mut cfg = config(&[server.udp_url()]);
    cfg.enhanced_mode = EnhancedMode::RedirHost;
    cfg.use_hosts = true;
    let hosts = HostsConfig {
        entries: vec![HostEntry {
            domain: "pinned.test".into(),
            value: ConfigHostValue::Ips(vec![ip("192.0.2.9")]),
        }],
    };
    let (resolver, _) = build_with_hosts(&cfg, &hosts);
    let reply = ask_a(&resolver, "site.test").await;
    assert_eq!(first_a(&reply), Some(ip("93.184.216.34")));
    assert_eq!(
        resolver.find_host_by_ip(ip("93.184.216.34")).as_deref(),
        Some("site.test")
    );
    assert!(resolver.fake_ip_reverse(ip("93.184.216.34")).is_none());
    assert!(!resolver.is_fake_ip(ip("93.184.216.34")));
    let pinned = ask_a(&resolver, "pinned.test").await;
    assert_eq!(first_a(&pinned), Some(ip("192.0.2.9")));
    assert_eq!(server.hits(), 1);
}

#[tokio::test]
async fn a_hijacked_udp_answer_fits_what_the_client_advertised() {
    let big: Handler = Arc::new(|req: &Message| {
        let query = req.queries.first()?;
        let mut resp = crate::msg::empty_answer(req);
        for i in 0..60u8 {
            resp.answers.push(crate::msg::a_record(
                &query.name,
                60,
                Ipv4Addr::new(10, 0, 0, i),
            ));
        }
        Some(resp)
    });
    let server = serve_tcp(big).await;
    let (resolver, _) = build(&config(&[server.tcp_url()]));
    let query = query_bytes("big.test", RecordType::A);
    let full = parse(&resolver.handle_query(&query, Initiator::App).await.unwrap());
    assert_eq!(full.answers.len(), 60);
    let cut = parse(
        &resolver
            .handle_query_udp(&query, Initiator::App)
            .await
            .unwrap(),
    );
    assert!(cut.metadata.truncation && cut.answers.len() < 60);
}

#[tokio::test]
async fn garbage_is_not_answered_and_an_empty_question_is_a_server_failure() {
    let (resolver, _) = build(&config(&["rcode://success".to_string()]));
    assert!(
        resolver
            .handle_query(&[1, 2, 3], Initiator::App)
            .await
            .is_none()
    );
    let empty = Message::query().to_vec().unwrap();
    let reply = resolver.handle_query(&empty, Initiator::App).await.unwrap();
    assert_eq!(parse(&reply).metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn a_dhcp_interface_upstream_asks_the_system_servers() {
    let server = serve_udp(answer_with(Ipv4Addr::new(10, 6, 0, 3)), Duration::ZERO).await;
    let (resolver, _) = build(&config(&["dhcp://en0".to_string()]));
    resolver.set_system_servers(vec![server.addr]);
    assert_eq!(
        lookup_v4(&resolver, "dhcp.test").await.unwrap(),
        vec![ip("10.6.0.3")]
    );
}

#[test]
fn a_name_policy_that_cannot_be_resolved_is_a_build_error() {
    let sink = Arc::new(Sink::default());
    let mut cfg = config(&["1.1.1.1".to_string()]);
    cfg.nameserver_policy = vec![PolicyEntry {
        key: PolicyKey::GeoSite("cn".into()),
        servers: vec![up("8.8.8.8")],
    }];
    assert!(crate::Resolver::new(&cfg, &HostsConfig::default(), deps(&sink)).is_err());
}

fn https_ech(ech: Option<Vec<u8>>) -> Handler {
    Arc::new(move |req| {
        let query = req.queries.first()?;
        let mut resp = crate::msg::empty_answer(req);
        if query.query_type != RecordType::HTTPS {
            return Some(resp);
        }
        let mut params = vec![(
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["h2".into()])),
        )];
        if let Some(list) = &ech {
            params.push((
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(list.clone())),
            ));
        }
        resp.answers.push(Record::from_rdata(
            query.name.clone(),
            60,
            RData::HTTPS(hickory_proto::rr::rdata::HTTPS(SVCB::new(
                1,
                Name::root(),
                params,
            ))),
        ));
        Some(resp)
    })
}

#[tokio::test]
async fn an_ech_config_comes_from_the_https_record_and_is_cached() {
    let list = vec![0, 6, 0xfe, 0x0d, 0, 2, 7, 8];
    let server = serve_udp(https_ech(Some(list.clone())), Duration::ZERO).await;
    let (resolver, sink) = build(&config(&[server.udp_url()]));
    for _ in 0..2 {
        let got = resolver
            .resolve_ech("ech.test", Initiator::Proxy)
            .await
            .unwrap();
        assert_eq!(got, list);
    }
    assert_eq!(server.hits(), 1);
    let records = sink.records();
    assert_eq!(records[0].qtype, "HTTPS");
    assert_eq!(records[0].domain, "ech.test");
}

#[tokio::test]
async fn ech_lookups_use_the_proxy_server_nameserver_for_proxies() {
    let main = serve_udp(https_ech(Some(vec![1])), Duration::ZERO).await;
    let proxy = serve_udp(https_ech(Some(vec![2])), Duration::ZERO).await;
    let mut cfg = config(&[main.udp_url()]);
    cfg.proxy_server_nameserver = vec![up(&proxy.udp_url())];
    let (resolver, _) = build(&cfg);
    assert_eq!(
        resolver
            .resolve_ech("e.test", Initiator::Proxy)
            .await
            .unwrap(),
        vec![2]
    );
    assert_eq!(
        resolver
            .resolve_ech("e.test", Initiator::Rule)
            .await
            .unwrap(),
        vec![1]
    );
}

#[tokio::test]
async fn a_record_without_ech_or_an_empty_answer_is_an_error() {
    let plain = serve_udp(https_ech(None), Duration::ZERO).await;
    let (resolver, _) = build(&config(&[plain.udp_url()]));
    let err = resolver
        .resolve_ech("plain.test", Initiator::Proxy)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "no ECH config found in DNS records");

    let empty = serve_udp(answer_with(Ipv4Addr::new(10, 9, 0, 1)), Duration::ZERO).await;
    let (resolver, _) = build(&config(&[empty.udp_url()]));
    let err = resolver
        .resolve_ech("empty.test", Initiator::Proxy)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "no ECH config found in DNS records");
}

#[tokio::test]
async fn a_failing_upstream_fails_the_ech_lookup() {
    let failing = serve_udp(
        Arc::new(|req| Some(crate::msg::error_reply(req, ResponseCode::ServFail))),
        Duration::ZERO,
    )
    .await;
    let (resolver, _) = build(&config(&[failing.udp_url()]));
    let err = resolver
        .resolve_ech("fail.test", Initiator::Proxy)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("all DNS requests failed"), "{err}");
}

#[tokio::test]
async fn boundary_names_reach_hosts_policy_and_the_fake_ip_filter() {
    let general = serve_udp(answer_with(Ipv4Addr::new(10, 7, 0, 1)), Duration::ZERO).await;
    let corp = serve_udp(answer_with(Ipv4Addr::new(10, 7, 0, 2)), Duration::ZERO).await;
    let mut cfg = config(&[general.udp_url()]);
    cfg.nameserver_policy = vec![PolicyEntry {
        key: PolicyKey::Domain("+.corp.test".into()),
        servers: vec![up(&corp.udp_url())],
    }];
    let hosts = HostsConfig {
        entries: vec![
            HostEntry {
                domain: "pinned.test".into(),
                value: ConfigHostValue::Ips(vec![ip("192.0.2.9")]),
            },
            HostEntry {
                domain: "xn--fiqs8s.test".into(),
                value: ConfigHostValue::Ips(vec![ip("192.0.2.10")]),
            },
        ],
    };
    let (resolver, _) = build_with_hosts(&cfg, &hosts);
    for (host, want) in [
        ("PINNED.TEST", "192.0.2.9"),
        ("XN--FIQS8S.TEST", "192.0.2.10"),
        ("WWW.CORP.TEST", "10.7.0.2"),
        ("xn--fiqs8s.corp.test", "10.7.0.2"),
        ("a.b.c.d.e.f.g.h.Corp.Test", "10.7.0.2"),
        ("corp.test.example", "10.7.0.1"),
    ] {
        assert_eq!(
            lookup_v4(&resolver, host).await.unwrap(),
            vec![ip(want)],
            "{host}"
        );
    }

    let server = serve_udp(answer_with(Ipv4Addr::new(10, 7, 1, 1)), Duration::ZERO).await;
    let mut faking = fake_ip_config(server.udp_url());
    faking.fake_ip_filter = vec!["+.lan".into(), "+.xn--fiqs8s".into()];
    let (resolver, _) = build(&faking);
    let real = Some(ip("10.7.1.1"));
    for host in ["NAS.LAN", "lan", "www.XN--FIQS8S"] {
        assert_eq!(first_a(&ask_a(&resolver, host).await), real, "{host}");
    }
    for host in ["lan.example", "xn--fiqs8s.example"] {
        let answer = first_a(&ask_a(&resolver, host).await).unwrap();
        assert!(resolver.is_fake_ip(answer), "{host}");
    }
}

#[tokio::test]
async fn a_cache_hit_is_a_copy_the_caller_may_change() {
    let server = serve_udp(answer_with(Ipv4Addr::new(10, 8, 0, 1)), Duration::ZERO).await;
    let (resolver, _) = build(&config(&[server.udp_url()]));
    let ask = |host: &str, id: u16| {
        let mut req = crate::msg::build_query(host, RecordType::A).unwrap();
        req.metadata.id = id;
        req
    };
    resolver
        .exchange(&ask("copy.test", 1), Initiator::App)
        .await
        .unwrap();
    let mut first = resolver
        .exchange(&ask("COPY.TEST", 2), Initiator::App)
        .await
        .unwrap();
    assert_eq!(first.metadata.id, 2);
    assert_eq!(crate::msg::answer_ips(&first), vec![ip("10.8.0.1")]);
    first.metadata.id = 99;
    first.answers.clear();
    first.queries.clear();

    let second = resolver
        .exchange(&ask("copy.test", 3), Initiator::App)
        .await
        .unwrap();
    assert_eq!(second.metadata.id, 3);
    assert_eq!(crate::msg::answer_ips(&second), vec![ip("10.8.0.1")]);
    assert_eq!(second.queries.len(), 1);
    assert!(
        second
            .answers
            .iter()
            .all(|record| (1..=60).contains(&record.ttl))
    );
    assert_eq!(server.hits(), 1);

    resolver
        .exchange(
            &crate::msg::build_query("copy.test", RecordType::AAAA).unwrap(),
            Initiator::App,
        )
        .await
        .unwrap();
    assert_eq!(
        server.hits(),
        2,
        "an AAAA question is not answered from the A entry"
    );
}
