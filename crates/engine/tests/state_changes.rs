#![allow(
    clippy::disallowed_methods,
    reason = "the peer here stands for an unresponsive proxy server, not the core's own sockets"
)]

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{
    Change, CoreEvent, CoreOptions, EventSink, GeneralChange, Origin, StateChange, TunnelMode,
};
use concord_engine::{Engine, EngineConfig, SetupRequest, TunPatch, UpdateRequest};
use concord_platform::NativePlatform;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Changes(Mutex<Vec<StateChange>>);

impl EventSink for Changes {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        if let CoreEvent::State(change) = event {
            lock(&self.0).push(change);
        }
    }
}

struct Rig {
    engine: Arc<Engine>,
    changes: Arc<Changes>,
    _home: tempfile::TempDir,
}

impl Rig {
    async fn new(config: &str) -> Rig {
        let changes = Arc::new(Changes::default());
        let engine = Engine::new(EngineConfig {
            sink: changes.clone(),
            android: false,
            platform: Arc::new(NativePlatform::new()),
        });
        let home = tempfile::tempdir().unwrap();
        engine.init(home.path().to_str().unwrap(), 0).unwrap();
        std::fs::write(home.path().join("config.yaml"), config).unwrap();
        engine
            .setup(SetupRequest {
                base: None,
                selected: BTreeMap::new(),
                options: CoreOptions::default(),
            })
            .await
            .unwrap();
        Rig {
            engine,
            changes,
            _home: home,
        }
    }

    fn taken(&self) -> Vec<StateChange> {
        std::mem::take(&mut *lock(&self.changes.0))
    }
}

fn mode(mode: &str) -> UpdateRequest {
    UpdateRequest {
        mode: Some(mode.to_string()),
        ..UpdateRequest::default()
    }
}

const SELECT: &str = "mixed-port: 0
proxy-groups:
  - {name: G, type: select, proxies: [DIRECT, REJECT]}
rules:
  - MATCH,G
";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changes_carry_their_origin_and_are_numbered_in_the_order_they_took_effect() {
    let rig = Rig::new(SELECT).await;
    let applied = rig.taken();
    assert!(matches!(
        applied.as_slice(),
        [StateChange {
            change: Change::Applied,
            origin: Origin::Host,
            ..
        }]
    ));
    let start = applied[0].seq;

    let picked = rig
        .engine
        .select_as(Origin::Controller, "G", "REJECT")
        .await;
    assert!(picked.message.is_empty());
    assert_eq!(picked.seq, start + 1);
    let moved = rig
        .engine
        .update_as(Origin::Host, mode("global"))
        .await
        .unwrap();
    assert_eq!(moved, start + 2);
    assert_eq!(
        rig.taken(),
        [
            StateChange {
                seq: start + 1,
                origin: Origin::Controller,
                change: Change::Selected {
                    group: "G".into(),
                    proxy: "REJECT".into(),
                },
            },
            StateChange {
                seq: start + 2,
                origin: Origin::Host,
                change: Change::General(GeneralChange {
                    mode: Some(TunnelMode::Global),
                    ..GeneralChange::default()
                }),
            },
        ]
    );

    let unchanged = rig
        .engine
        .update_as(Origin::Controller, mode("global"))
        .await
        .unwrap();
    assert_eq!(unchanged, start + 2);
    assert_eq!(
        rig.engine.select_as(Origin::Host, "G", "REJECT").await.seq,
        start + 2
    );
    assert!(rig.taken().is_empty());

    let general = rig.engine.general().await.unwrap();
    assert_eq!(general.seq, start + 2);
    assert_eq!(general.mode, TunnelMode::Global);
    assert_eq!(
        general.selections,
        [("G".to_string(), "REJECT".to_string())]
    );
    rig.engine.shutdown().await;
}

/// An HTTP proxy that drops its first client, so a test through it fails and
/// marks the node dead, then answers each later one after `pause`, so a probe
/// through it takes that long and brings the node back.
async fn slow_proxy(pause: Duration) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut first = true;
        while let Ok((mut stream, _)) = listener.accept().await {
            if std::mem::take(&mut first) {
                drop(stream);
                continue;
            }
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                for reply in [
                    "HTTP/1.1 200 Connection established\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                ] {
                    head.clear();
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    tokio::time::sleep(pause).await;
                    if stream.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_select_publishes_its_pick_before_it_probes_and_holds_back_no_other_change() {
    let port = slow_proxy(Duration::from_millis(400)).await;
    let rig = Rig::new(&format!(
        "mixed-port: 0
proxies:
  - {{name: slow, type: http, server: 127.0.0.1, port: {port}}}
proxy-groups:
  - {{name: F, type: fallback, proxies: [DIRECT, slow], url: 'http://127.0.0.1:1/', timeout: 200, lazy: true}}
rules:
  - MATCH,F
"
    ))
    .await;
    let dead = rig
        .engine
        .test_delay("slow", "http://127.0.0.1:1/", 200)
        .await;
    assert!(dead.value < 0);
    rig.taken();

    let engine = rig.engine.clone();
    let select =
        tokio::spawn(async move { engine.select_as(Origin::Controller, "F", "slow").await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!select.is_finished(), "the probe should still be running");
    assert_eq!(
        rig.taken(),
        [StateChange {
            seq: picked_seq(&rig).await,
            origin: Origin::Controller,
            change: Change::Selected {
                group: "F".into(),
                proxy: "slow".into(),
            },
        }],
        "the pick is published before the probe, as mihomo stores it before it tests"
    );

    let moved = tokio::time::timeout(
        Duration::from_secs(1),
        rig.engine.update_as(Origin::Host, mode("direct")),
    )
    .await
    .expect("an update must not wait for another origin's probe")
    .unwrap();

    let picked = select.await.unwrap();
    assert!(picked.message.is_empty());
    assert!(picked.seq < moved);
    let changes = rig.taken();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].origin, Origin::Host);
    assert_eq!(
        rig.engine.general().await.unwrap().selections,
        [("F".to_string(), "slow".to_string())],
        "a pick whose probe succeeds survives the probe"
    );
    rig.engine.shutdown().await;
}

async fn picked_seq(rig: &Rig) -> u64 {
    rig.engine.general().await.unwrap().seq
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pick_the_core_drops_for_a_dead_node_is_reported_as_its_own_change() {
    let rig = Rig::new(
        "mixed-port: 0
proxies:
  - {name: gone, type: http, server: 127.0.0.1, port: 1}
proxy-groups:
  - {name: F, type: fallback, proxies: [DIRECT, gone], url: 'http://127.0.0.1:1/', timeout: 200, lazy: true}
rules:
  - MATCH,F
",
    )
    .await;
    let dead = rig
        .engine
        .test_delay("gone", "http://127.0.0.1:1/", 200)
        .await;
    assert!(dead.value < 0);
    rig.taken();

    let picked = rig.engine.select_as(Origin::Host, "F", "gone").await;
    assert!(picked.message.is_empty());
    let mut changes = Vec::new();
    for _ in 0..100 {
        changes.extend(rig.taken());
        if changes.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        changes,
        [
            StateChange {
                seq: picked.seq,
                origin: Origin::Host,
                change: Change::Selected {
                    group: "F".into(),
                    proxy: "gone".into(),
                },
            },
            StateChange {
                seq: picked.seq + 1,
                origin: Origin::Core,
                change: Change::Selected {
                    group: "F".into(),
                    proxy: String::new(),
                },
            },
        ]
    );
    assert!(
        rig.engine.general().await.unwrap().selections.is_empty(),
        "a host that mirrors the picks must not put the dead one back"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_setting_the_general_view_reports_is_part_of_a_change() {
    let rig = Rig::new(SELECT).await;
    rig.taken();
    let mut request = mode("rule");
    request.tun = Some(TunPatch {
        enable: false,
        device: Some("utun-k".into()),
        stack: None,
        auto_route: Some(false),
    });
    request.authentication = Some(vec!["user:pass".into()]);
    request.geo_auto_update = Some(true);
    request.geo_update_interval = Some(12);
    request.geox_url =
        BTreeMap::from([("mmdb".to_string(), "http://127.0.0.1:1/mmdb".to_string())]);
    rig.engine
        .update_as(Origin::Controller, request)
        .await
        .unwrap();

    let changes = rig.taken();
    let [
        StateChange {
            origin: Origin::Controller,
            change: Change::General(general),
            ..
        },
    ] = changes.as_slice()
    else {
        panic!("one general change expected, got {changes:?}");
    };
    assert_eq!(general.tun_device.as_deref(), Some("utun-k"));
    assert_eq!(general.tun_auto_route, Some(false));
    assert_eq!(general.authentication, Some(vec!["user".to_string()]));
    assert_eq!(general.geo_auto_update, Some(true));
    assert_eq!(general.geo_update_interval, Some(12));
    assert_eq!(
        general
            .geox_url
            .as_ref()
            .and_then(|urls| urls.get("mmdb"))
            .map(String::as_str),
        Some("http://127.0.0.1:1/mmdb")
    );
    assert_eq!(general.mode, None);
    rig.engine.shutdown().await;
}
