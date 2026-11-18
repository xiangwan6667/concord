use std::collections::BTreeMap;
use std::time::Duration;

use concord_common::{CoreEvent, CoreOptions, ResourcePhase};
use concord_platform::NativePlatform;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::*;

struct NoEvents;

impl EventSink for NoEvents {
    fn enabled(&self) -> bool {
        false
    }

    fn publish(&self, _event: CoreEvent) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_applies_release_the_runtimes_they_replace() {
    let home = tempfile::tempdir().unwrap();
    let engine = Engine::new(EngineConfig {
        sink: Arc::new(NoEvents),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    engine.init(home.path().to_str().unwrap(), 0).unwrap();
    let mut replaced = Vec::new();
    for round in 0..3 {
        let config = format!(
            "proxies:\n  - {{name: n{round}, type: socks5, server: 127.0.0.1, port: 1}}\n\
             rules:\n  - MATCH,n{round}\n"
        );
        std::fs::write(home.path().join("config.yaml"), config).unwrap();
        engine
            .setup(SetupRequest {
                base: None,
                selected: BTreeMap::new(),
                options: CoreOptions::default(),
            })
            .await
            .unwrap();
        replaced.push(Arc::downgrade(&engine.runtime().unwrap()));
    }
    let current = replaced.pop().unwrap();
    let released = tokio::time::timeout(Duration::from_secs(10), async {
        while replaced.iter().any(|old| old.upgrade().is_some()) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "a runtime an apply replaced is still held after ten seconds"
    );
    assert!(current.upgrade().is_some());
    engine.shutdown().await;
}

#[tokio::test]
async fn a_panicked_holder_of_the_answer_token_still_lets_first_loads_wait() {
    let engine = Engine::new(EngineConfig {
        sink: Arc::new(NoEvents),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    concord_test_support::poison(&engine.answered);
    let answering = engine.hold_first_loads();
    let held = lock(&engine.answered).clone();
    assert!(!held.is_cancelled(), "the next apply's first loads wait");
    drop(answering);
    assert!(held.is_cancelled());
}

#[tokio::test]
async fn a_system_dns_update_sent_before_shutdown_has_landed_when_it_returns() {
    let engine = Engine::new(EngineConfig {
        sink: Arc::new(NoEvents),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    engine.update_system_dns("192.0.2.1:53".to_string());
    engine.shutdown().await;
    assert_eq!(
        *lock(&engine.system_dns),
        Some(vec!["192.0.2.1:53".parse().unwrap()])
    );
}

#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "external DNS clients and a silent upstream for the lifecycle test"
)]
async fn shutdown_releases_dns_sockets_and_streams_before_reinit() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserved.local_addr().unwrap();
    let home = tempfile::tempdir().unwrap();
    let engine = Engine::new(EngineConfig {
        sink: Arc::new(NoEvents),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    let config = format!(
        "dns:\n  enable: true\n  listen: {address}\n  nameserver:\n    - {}\nrules:\n  - MATCH,DIRECT\n",
        upstream.local_addr().unwrap()
    );
    std::fs::write(home.path().join("config.yaml"), config).unwrap();
    drop(reserved);
    let home_dir = home.path().to_str().unwrap();
    let request = || SetupRequest {
        base: None,
        selected: BTreeMap::new(),
        options: CoreOptions::default(),
    };
    engine.init(home_dir, 0).unwrap();
    engine.setup(request()).await.unwrap();
    assert!(engine.faults.list().is_empty());

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_query =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07udpwait\x04test\x00\x00\x01\x00\x01";
    udp.send_to(udp_query, address).await.unwrap();
    let mut received = [0; 512];
    tokio::time::timeout(Duration::from_secs(10), upstream.recv_from(&mut received))
        .await
        .unwrap()
        .unwrap();
    let mut tcp = TcpStream::connect(address).await.unwrap();
    let tcp_query =
        b"\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07tcpwait\x04test\x00\x00\x01\x00\x01";
    tcp.write_u16(u16::try_from(tcp_query.len()).unwrap())
        .await
        .unwrap();
    tcp.write_all(tcp_query).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), upstream.recv_from(&mut received))
        .await
        .unwrap()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(10), engine.shutdown())
        .await
        .expect("shutdown waited for an unanswered DNS query");
    let rebound_udp = UdpSocket::bind(address).await.unwrap();
    let rebound_tcp = TcpListener::bind(address).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut received))
            .await
            .unwrap()
            .unwrap(),
        0,
        "a DNS stream outlived shutdown"
    );
    drop((rebound_udp, rebound_tcp));
    engine.init(home_dir, 0).unwrap();
    engine.setup(request()).await.unwrap();
    assert!(engine.faults.list().is_empty());
    assert_eq!(
        UdpSocket::bind(address).await.unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse
    );
    engine.shutdown().await;
}

#[derive(Default)]
struct GeoPhases(StdMutex<Vec<ResourcePhase>>);

impl EventSink for GeoPhases {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        if let CoreEvent::Resource(update) = event {
            lock(&self.0).push(update.phase);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_ends_a_geo_update_in_flight_and_frees_its_claim() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    let home = tempfile::tempdir().unwrap();
    let phases = Arc::new(GeoPhases::default());
    let engine = Engine::new(EngineConfig {
        sink: phases.clone(),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    let home_dir = home.path().to_str().unwrap();
    engine.init(home_dir, 0).unwrap();
    let config =
        format!("geox-url:\n  asn: http://127.0.0.1:{port}/asn\nrules:\n  - MATCH,DIRECT\n");
    std::fs::write(home.path().join("config.yaml"), config).unwrap();
    engine
        .setup(SetupRequest {
            base: None,
            selected: BTreeMap::new(),
            options: CoreOptions::default(),
        })
        .await
        .unwrap();
    engine.geo_update("ASN").unwrap();
    let (mut download, _) = tokio::time::timeout(Duration::from_secs(10), server.accept())
        .await
        .unwrap()
        .unwrap();
    let mut request = [0; 1024];
    let _ = download.read(&mut request).await.unwrap();

    tokio::time::timeout(Duration::from_secs(10), engine.shutdown())
        .await
        .expect("shutdown waited out the download");
    assert!(
        matches!(lock(&phases.0).last(), Some(ResourcePhase::Failed(_))),
        "the update was still running when shutdown returned"
    );
    engine.init(home_dir, 0).unwrap();
    assert!(engine.geo_update("ASN").is_ok());
    engine.shutdown().await;
}

fn bare_engine() -> Arc<Engine> {
    Engine::new(EngineConfig {
        sink: Arc::new(NoEvents),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    })
}

#[tokio::test]
async fn shutdown_stops_the_proxy_tasks_and_waits_for_their_teardown() {
    let engine = bare_engine();
    let tasks = engine.shared.proxy_tasks.tasks();
    let torn_down = Arc::new(AtomicBool::new(false));
    tasks.spawn(std::future::pending());
    tasks.spawn_detached(std::future::pending());
    tasks.spawn_to_end({
        let (tasks, torn_down) = (tasks.clone(), torn_down.clone());
        async move {
            tasks.stopped().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            torn_down.store(true, Ordering::SeqCst);
        }
    });
    engine.shutdown().await;
    assert!(torn_down.load(Ordering::SeqCst));
    assert!(engine.tasks.is_empty());
    let next = engine.shared.proxy_tasks.tasks();
    let (ran, done) = tokio::sync::oneshot::channel();
    next.spawn(async move {
        let _ = ran.send(());
    });
    assert!(
        done.await.is_ok(),
        "a config built after shutdown starts stopped"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_returns_at_its_bound_when_a_task_never_ends() {
    let engine = bare_engine();
    engine
        .shared
        .proxy_tasks
        .tasks()
        .spawn_to_end(std::future::pending());
    let started = tokio::time::Instant::now();
    engine.shutdown().await;
    let took = started.elapsed();
    assert!(
        (SHUTDOWN_GRACE..SHUTDOWN_GRACE + Duration::from_secs(1)).contains(&took),
        "{took:?}"
    );
    assert_eq!(engine.tasks.len(), 1);
}
