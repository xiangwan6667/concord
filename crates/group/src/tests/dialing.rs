use std::sync::atomic::Ordering;
use std::time::Duration;

use concord_common::NodeDialer;

use super::*;
use crate::GroupError;

fn connects(rig: &Rig, name: &str) -> usize {
    rig.book.get(name).connects.load(Ordering::SeqCst)
}

async fn dial(rig: &Rig, name: &str) -> io::Result<BoxStream> {
    let env = rig.out.env();
    let cx = DialCx::new(&env, Initiator::Other, None);
    let Resolved::Route { leaf, .. } = rig.resolve(name) else {
        panic!("{name} does not resolve to a route");
    };
    leaf.connect(&cx, &Address::new("example.com", 80)).await
}

#[tokio::test(start_paused = true)]
async fn a_dialer_proxy_reaches_its_target_through_the_named_node() {
    let rig = Rig::new(
        "proxies:
  - {name: x, type: direct, dialer-proxy: y}
  - {name: y, type: direct}
",
    );
    assert!(dial(&rig, "x").await.is_ok());
    assert_eq!((connects(&rig, "x"), connects(&rig, "y")), (1, 1));
}

#[tokio::test(start_paused = true)]
async fn a_dialer_proxy_may_name_a_group_and_follows_its_pick() {
    let rig = Rig::new(
        "proxies:
  - {name: y, type: direct}
  - {name: z, type: direct}
proxy-providers:
  p:
    type: inline
    payload:
      - {name: x, type: direct, dialer-proxy: g}
proxy-groups:
  - {name: g, type: select, proxies: [y, z]}
",
    );
    rig.out.select("g", "z").await;
    assert!(dial(&rig, "x").await.is_ok());
    assert_eq!((connects(&rig, "y"), connects(&rig, "z")), (0, 1));
}

#[tokio::test]
async fn pass_outbounds_return_a_typed_dial_error() {
    let rig = Rig::new("proxies: []\n");
    let env = rig.out.env();
    let cx = DialCx::new(&env, Initiator::Other, None);
    let dst = Address::new("example.com", 80);
    for name in ["PASS", "PASS-RULE"] {
        let dial = rig.out.dial_via(name, &cx, &dst).await.err().unwrap();
        let associate = rig.out.associate_via(name, &cx, &dst).await.err().unwrap();
        for err in [dial, associate] {
            assert_eq!(err.kind(), io::ErrorKind::Other);
            assert_eq!(err.to_string(), format!("{name} cannot be dialed"));
            let typed = err
                .get_ref()
                .and_then(|err| err.downcast_ref::<GroupError>());
            assert!(matches!(typed, Some(GroupError::CannotDial(node)) if node == name));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_loop_through_a_group_is_refused_and_reported_at_most_every_three_seconds() {
    let rig = Rig::new(
        "proxies:
  - {name: y, type: direct}
proxy-providers:
  p:
    type: inline
    payload:
      - {name: x, type: direct, dialer-proxy: g}
proxy-groups:
  - {name: g, type: select, proxies: [y], use: [p]}
",
    );
    rig.out.select("g", "x").await;
    let err = dial(&rig, "x").await.err().expect("a loop");
    assert!(err.to_string().contains("loop"), "{err}");
    assert_eq!(rig.events.loops(), ["x"]);
    assert!(dial(&rig, "x").await.is_err());
    assert_eq!(rig.events.loops().len(), 1);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(dial(&rig, "x").await.is_err());
    assert_eq!(rig.events.loops().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn repeated_dial_failures_make_the_group_test_its_members() {
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
proxy-groups:
  - {{name: f, type: fallback, proxies: [a, b], url: '{TEST_URL}', max-failed-times: 2}}
"
    ));
    let chain: Vec<Arc<str>> = vec![Arc::from("a"), Arc::from("f")];
    let err = io::Error::new(io::ErrorKind::TimedOut, "i/o timeout");
    rig.out
        .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &err);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 0);
    rig.out
        .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &err);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!((connects(&rig, "a"), connects(&rig, "b")), (1, 1));
}

#[tokio::test(start_paused = true)]
async fn a_refused_connection_and_a_success_are_counted_differently() {
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: a, type: direct}}
proxy-groups:
  - {{name: f, type: fallback, proxies: [a], url: '{TEST_URL}', max-failed-times: 3}}
"
    ));
    let chain: Vec<Arc<str>> = vec![Arc::from("a"), Arc::from("f")];
    let timeout = io::Error::new(io::ErrorKind::TimedOut, "i/o timeout");
    rig.out
        .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &timeout);
    rig.out.note_dial_succeeded(&chain);
    rig.out
        .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &timeout);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 0);
    let refused = io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "dial tcp: connection refused",
    );
    rig.out
        .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &refused);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 1);
    rig.out
        .note_dial_failed(&chain, OutboundKind::Direct, Network::Tcp, &refused);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 1);
}

#[tokio::test(start_paused = true)]
async fn running_out_of_descriptors_says_nothing_about_the_members() {
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
proxy-groups:
  - {{name: f, type: fallback, proxies: [a, b], url: '{TEST_URL}', max-failed-times: 2}}
"
    ));
    let chain: Vec<Arc<str>> = vec![Arc::from("a"), Arc::from("f")];
    let pressure = || io::Error::from(concord_common::CoreError::FdPressure);
    for err in [
        pressure(),
        io::Error::other(pressure()),
        io::Error::from(io::ErrorKind::OutOfMemory),
    ] {
        rig.out
            .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &err);
        rig.out
            .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &err);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 0);
    let timeout = io::Error::other(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"));
    rig.out
        .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &timeout);
    rig.out
        .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &timeout);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!((connects(&rig, "a"), connects(&rig, "b")), (1, 1));
}

struct Pending(tokio::io::DuplexStream);

impl tokio::io::AsyncRead for Pending {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Pending {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl concord_common::Stream for Pending {
    fn needs_handshake(&self) -> bool {
        true
    }
}

fn counting_rig(kind: &str) -> Rig {
    Rig::new(&format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
proxy-groups:
  - {{name: inner, type: select, proxies: [a]}}
  - {{name: f, type: {kind}, proxies: [a, b], url: '{TEST_URL}', max-failed-times: 2}}
  - {{name: outer, type: fallback, proxies: [inner], url: '{TEST_URL}', max-failed-times: 1}}
"
    ))
}

fn chain(names: &[&str]) -> Vec<Arc<str>> {
    names.iter().map(|name| Arc::from(*name)).collect()
}

#[tokio::test(start_paused = true)]
async fn udp_failures_count_for_url_test_but_not_for_fallback_or_load_balance() {
    let err = io::Error::new(io::ErrorKind::TimedOut, "i/o timeout");
    for (kind, tests) in [("url-test", 1), ("fallback", 0), ("load-balance", 0)] {
        let rig = counting_rig(kind);
        let chain = chain(&["a", "f"]);
        for _ in 0..2 {
            rig.out
                .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Udp, &err);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(connects(&rig, "a"), tests, "{kind}");
    }
}

#[tokio::test(start_paused = true)]
async fn only_the_direct_child_decides_the_exemption() {
    let rig = counting_rig("fallback");
    let err = io::Error::new(io::ErrorKind::TimedOut, "i/o timeout");
    for _ in 0..3 {
        rig.out.note_dial_failed(
            &chain(&["a", "f"]),
            OutboundKind::Direct,
            Network::Tcp,
            &err,
        );
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 0);
    for _ in 0..2 {
        rig.out.note_dial_failed(
            &chain(&["a", "inner", "outer"]),
            OutboundKind::Direct,
            Network::Tcp,
            &err,
        );
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 1);
}

#[tokio::test(start_paused = true)]
async fn a_plain_connect_does_not_reset_the_count_but_a_first_write_does() {
    let rig = counting_rig("fallback");
    let chain = chain(&["a", "f"]);
    let err = io::Error::new(io::ErrorKind::TimedOut, "i/o timeout");
    let kind = OutboundKind::Shadowsocks;

    rig.out.note_dial_failed(&chain, kind, Network::Tcp, &err);
    let (plain, _far) = tokio::io::duplex(64);
    let mut plain = rig.out.watch_first_write(&chain, kind, Box::new(plain));
    plain.write_all(b"x").await.unwrap();
    rig.out.note_dial_failed(&chain, kind, Network::Tcp, &err);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 1);

    let rig = counting_rig("fallback");
    rig.out.note_dial_failed(&chain, kind, Network::Tcp, &err);
    let (near, _far) = tokio::io::duplex(64);
    let mut lazy = rig
        .out
        .watch_first_write(&chain, kind, Box::new(Pending(near)));
    tokio::time::sleep(Duration::from_secs(1)).await;
    lazy.write_all(b"x").await.unwrap();
    rig.out.note_dial_failed(&chain, kind, Network::Tcp, &err);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 0);
}

#[tokio::test(start_paused = true)]
async fn a_failed_first_write_counts_as_a_failed_dial() {
    let rig = counting_rig("fallback");
    let chain = chain(&["a", "f"]);
    let kind = OutboundKind::Shadowsocks;
    for _ in 0..2 {
        let (near, far) = tokio::io::duplex(64);
        drop(far);
        let mut lazy = rig
            .out
            .watch_first_write(&chain, kind, Box::new(Pending(near)));
        assert!(lazy.write_all(b"x").await.is_err());
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 1);
}

#[tokio::test(start_paused = true)]
async fn the_providers_of_a_group_are_tested_together() {
    let rig = Rig::new(&format!(
        "proxy-providers:
  p:
    type: inline
    payload:
      - {{name: n1, type: direct}}
proxies:
  - {{name: a, type: direct}}
proxy-groups:
  - {{name: f, type: fallback, proxies: [a], use: [p], url: '{TEST_URL}', max-failed-times: 1}}
"
    ));
    rig.book.get("a").set_delay(5000);
    rig.book.get("n1").set_delay(5000);
    let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
    rig.out.note_dial_failed(
        &chain(&["a", "f"]),
        OutboundKind::Shadowsocks,
        Network::Tcp,
        &refused,
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!((connects(&rig, "a"), connects(&rig, "n1")), (1, 1));
}
