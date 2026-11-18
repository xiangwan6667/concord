#![allow(
    clippy::disallowed_methods,
    reason = "the peers here stand for the outside world, not the core's own sockets"
)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{CoreEvent, CoreOptions, EventSink, RouteStamp};
use concord_engine::{Engine, EngineConfig, SetupRequest, UpdateRequest};
use concord_platform::NativePlatform;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Stamps(std::sync::Mutex<Vec<RouteStamp>>);

impl EventSink for Stamps {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        if let CoreEvent::RouteChanged(view) = event {
            lock(&self.0).push(view.stamp);
        }
    }
}

struct Rig {
    engine: Arc<Engine>,
    stamps: Arc<Stamps>,
    home: tempfile::TempDir,
}

impl Rig {
    fn new() -> Rig {
        let stamps = Arc::new(Stamps::default());
        let engine = Engine::new(EngineConfig {
            sink: stamps.clone(),
            android: false,
            platform: Arc::new(NativePlatform::new()),
        });
        let home = tempfile::tempdir().unwrap();
        engine.init(home.path().to_str().unwrap(), 0).unwrap();
        Rig {
            engine,
            stamps,
            home,
        }
    }

    async fn apply(&self, config: &str) {
        std::fs::write(self.home.path().join("config.yaml"), config).unwrap();
        self.engine
            .setup(SetupRequest {
                base: None,
                selected: BTreeMap::new(),
                options: CoreOptions::default(),
            })
            .await
            .unwrap();
    }

    fn stamp(&self) -> RouteStamp {
        self.engine.watch_route(true).stamp
    }

    async fn settled(&self) -> RouteStamp {
        let mut last = self.stamp();
        loop {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let now = self.stamp();
            if now == last {
                return now;
            }
            last = now;
        }
    }

    fn published(&self) -> usize {
        lock(&self.stamps.0).len()
    }
}

async fn http_body(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    check()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_apply_and_a_listener_start_advance_the_epoch() {
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await;
    let applied = rig.stamp();

    rig.apply("rules:\n  - MATCH,DIRECT\n").await;
    let reapplied = rig.stamp();
    assert_eq!(reapplied.epoch, applied.epoch + 1);
    assert_eq!(reapplied.version, applied.version + 1);

    rig.engine.start_listeners().await;
    let started = rig.stamp();
    assert_eq!(started.epoch, reapplied.epoch + 1);
    assert_eq!(started.version, reapplied.version + 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_and_a_stop_report_the_listeners_with_the_epoch_they_move() {
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await;
    let applied = rig.engine.watch_route(true);
    assert!(!applied.running);

    rig.engine.start_listeners().await;
    let started = rig.engine.route_view();
    assert!(started.running);
    assert_eq!(started.stamp.epoch, applied.stamp.epoch + 1);

    rig.engine.stop_listeners().await;
    let stopped = rig.engine.route_view();
    assert!(!stopped.running);
    assert_eq!(stopped.stamp.epoch, started.stamp.epoch + 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_network_advances_the_epoch() {
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await;
    let before = rig.stamp();

    rig.engine.reset_network();

    assert_eq!(rig.stamp().epoch, before.epoch + 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeating_a_mode_moves_the_route_once_and_a_pick_never_moves_the_epoch() {
    let rig = Rig::new();
    rig.apply(
        "proxy-groups:\n  - {name: G, type: select, proxies: [DIRECT, REJECT]}\nrules:\n  - MATCH,G\n",
    )
    .await;
    let before = rig.stamp();

    for _ in 0..2 {
        let request = UpdateRequest {
            mode: Some("global".to_string()),
            ..UpdateRequest::default()
        };
        rig.engine.update(request).await.unwrap();
    }
    let after_mode = rig.stamp();
    assert_eq!(after_mode.epoch, before.epoch);
    assert_eq!(after_mode.version, before.version + 1);

    assert!(rig.engine.select("G", "REJECT").await.changed);
    assert!(!rig.engine.select("G", "REJECT").await.changed);
    let after_pick = rig.stamp();
    assert_eq!(after_pick.epoch, before.epoch);
    assert_eq!(after_pick.version, after_mode.version + 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_that_swaps_its_nodes_moves_the_route_and_the_same_content_does_not() {
    let server =
        http_body("proxies:\n  - {name: one, type: socks5, server: 127.0.0.1, port: 1}\n").await;
    let rig = Rig::new();
    rig.apply(&format!(
        "proxy-providers:\n  sub:\n    type: http\n    url: http://{server}/p\n    path: providers/p.yaml\n\
         proxy-groups:\n  - {{name: G, type: select, use: [sub]}}\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await;
    assert!(
        eventually(|| rig
            .engine
            .providers()
            .get("sub")
            .is_some_and(|view| view.count == 1))
        .await
    );
    let before = rig.settled().await;
    let published = rig.published();

    rig.engine
        .providers()
        .side_load(
            "sub",
            "proxies:\n  - {name: one, type: socks5, server: 127.0.0.1, port: 1}\n".to_string(),
        )
        .await
        .unwrap();
    assert_eq!(rig.stamp(), before, "the same nodes moved the route");
    assert_eq!(rig.published(), published);

    rig.engine
        .providers()
        .side_load(
            "sub",
            "proxies:\n  - {name: two, type: socks5, server: 127.0.0.1, port: 1}\n".to_string(),
        )
        .await
        .unwrap();
    let after = rig.stamp();
    assert_eq!(after.epoch, before.epoch);
    assert!(after.version > before.version);
    rig.engine.shutdown().await;
}
