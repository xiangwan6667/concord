#![allow(
    clippy::disallowed_methods,
    reason = "the clients and origins here are the outside world, not the core's own sockets"
)]

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{CoreEvent, CoreOptions, EventSink, ResourcePhase, ResourceUpdate};
use concord_engine::{Engine, EngineConfig, ProxyView, RouteHit, SetupRequest, UpdateRequest};
use concord_platform::{NativePlatform, Platform};
use concord_test_support::{tcp_echo, udp_echo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

#[cfg(feature = "mitm")]
#[path = "e2e/mitm.rs"]
mod mitm;

#[path = "e2e/rematch.rs"]
mod rematch;

#[path = "e2e/find_process.rs"]
mod find_process;

const PATIENCE: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Events {
    seen: Mutex<Vec<CoreEvent>>,
}

impl EventSink for Events {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        lock(&self.seen).push(event);
    }
}

impl Events {
    fn phases(&self, wanted: &str) -> Vec<ResourcePhase> {
        lock(&self.seen)
            .iter()
            .filter_map(|event| match event {
                CoreEvent::Resource(ResourceUpdate { name, phase, .. }) if &**name == wanted => {
                    Some(phase.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn loaded(&self) -> Vec<String> {
        lock(&self.seen)
            .iter()
            .filter_map(|event| match event {
                CoreEvent::Resource(ResourceUpdate {
                    name,
                    phase: ResourcePhase::Updated | ResourcePhase::Unchanged,
                    ..
                }) => Some(name.to_string()),
                _ => None,
            })
            .collect()
    }
}

/// The core binds its ports later than this picks them. They come from below
/// the ephemeral range, so another test's `bind(0)` or outgoing connection
/// cannot take one in between, and never repeat within the process.
fn free_port() -> u16 {
    static NEXT: OnceLock<AtomicU16> = OnceLock::new();
    let next = NEXT.get_or_init(|| AtomicU16::new(10_000 + (std::process::id() % 20_000) as u16));
    loop {
        let port = next.fetch_add(1, Ordering::Relaxed);
        let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port));
        let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port));
        if tcp.is_ok() && udp.is_ok() {
            return port;
        }
    }
}

/// Answers each path with its body; anything else is a 404.
async fn http_server(routes: HashMap<&'static str, String>) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let routes = routes.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let head = String::from_utf8_lossy(&head);
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let response = match routes.get(path.as_str()) {
                    Some(body) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None => {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    }
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, hits)
}

/// A SOCKS5 server that counts what passes through it, to show a flow took a node.
async fn upstream_socks() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.ok()?;
                let mut methods = vec![0u8; usize::from(greeting[1])];
                client.read_exact(&mut methods).await.ok()?;
                client.write_all(&[5, 0]).await.ok()?;
                let target = read_socks_target(&mut client).await?;
                lock(&log).push(target.clone());
                let mut remote = TcpStream::connect(&target).await.ok()?;
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok()?;
                tokio::io::copy_bidirectional(&mut client, &mut remote)
                    .await
                    .ok()
            });
        }
    });
    (port, seen)
}

async fn read_socks_target(stream: &mut TcpStream) -> Option<String> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.ok()?;
    let host = match head[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.ok()?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut name).await.ok()?;
            String::from_utf8(name).ok()?
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await.ok()?;
    Some(format!("{host}:{}", u16::from_be_bytes(port)))
}

async fn socks_connect(port: u16, target: SocketAddr) -> std::io::Result<TcpStream> {
    let SocketAddr::V4(target) = target else {
        panic!("tests use IPv4 targets");
    };
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("socks reply {}", reply[1])));
    }
    Ok(stream)
}

/// The SOCKS reply goes out before routing, as in mihomo, so a refusal is the
/// stream closing without an answer.
async fn refused(port: u16, target: SocketAddr) -> bool {
    let Ok(mut stream) = socks_connect(port, target).await else {
        return true;
    };
    let _ = stream.write_all(b"ping").await;
    let mut buf = [0u8; 4];
    matches!(
        timeout(PATIENCE, stream.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

async fn round_trip(stream: &mut TcpStream) {
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    timeout(PATIENCE, stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"ping");
}

/// Plain VLESS whose first read must hold the whole request header; it keeps each first read.
async fn vless_server() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let firsts = Arc::new(Mutex::new(Vec::new()));
    let record = firsts.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let record = record.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = client.read(&mut buf).await.unwrap_or(0);
                let first = buf[..n].to_vec();
                lock(&record).push(first.clone());
                let at = 18 + usize::from(first[17]);
                assert_eq!(first[at + 3], 1, "tests use IPv4 targets");
                let port = u16::from_be_bytes([first[at + 1], first[at + 2]]);
                let ip = Ipv4Addr::new(first[at + 4], first[at + 5], first[at + 6], first[at + 7]);
                let Ok(mut target) = TcpStream::connect((ip, port)).await else {
                    return;
                };
                let _ = target.write_all(&first[at + 8..]).await;
                let _ = client.write_all(&[0, 0]).await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
            });
        }
    });
    (port, firsts)
}

async fn greeter_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(b"hi").await;
                let _ = stream.read(&mut [0u8; 1]).await;
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

struct Rig {
    engine: Arc<Engine>,
    events: Arc<Events>,
    mixed: u16,
    home: tempfile::TempDir,
}

impl Rig {
    fn proxy(&self, name: &str) -> ProxyView {
        self.engine
            .proxy_views()
            .proxies
            .into_iter()
            .find_map(|(key, view)| (key.as_ref() == name).then_some(view))
            .unwrap_or_else(|| panic!("no proxy named {name}"))
    }

    fn selected(&self, group: &str) -> Option<String> {
        match self.proxy(group) {
            ProxyView::Group(group) => group.now,
            ProxyView::Node(_) => None,
        }
    }

    fn kind(&self, name: &str) -> &'static str {
        match self.proxy(name) {
            ProxyView::Group(group) => group.kind,
            ProxyView::Node(node) => node.kind,
        }
    }

    fn new() -> Rig {
        Rig::at(tempfile::tempdir().unwrap())
    }

    fn at(home: tempfile::TempDir) -> Rig {
        Rig::on(home, Arc::new(NativePlatform::new()))
    }

    fn on(home: tempfile::TempDir, platform: Arc<dyn Platform>) -> Rig {
        let events = Arc::new(Events::default());
        let engine = Engine::new(EngineConfig {
            sink: events.clone(),
            android: false,
            platform,
        });
        engine.init(home.path().to_str().unwrap(), 0).unwrap();
        Rig {
            engine,
            events,
            mixed: free_port(),
            home,
        }
    }

    async fn apply(&self, config: &str) -> Result<(), concord_engine::Failure> {
        self.apply_with(config, BTreeMap::new()).await
    }

    async fn apply_with(
        &self,
        config: &str,
        selected: BTreeMap<String, String>,
    ) -> Result<(), concord_engine::Failure> {
        self.setup(config, selected, CoreOptions::default()).await
    }

    async fn setup(
        &self,
        config: &str,
        selected: BTreeMap<String, String>,
        options: CoreOptions,
    ) -> Result<(), concord_engine::Failure> {
        let text = format!("mixed-port: {}\n{config}", self.mixed);
        std::fs::write(self.home.path().join("config.yaml"), text).unwrap();
        self.engine
            .setup(SetupRequest {
                base: None,
                selected,
                options,
            })
            .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flow_goes_direct_and_shows_in_the_connection_table() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    assert!(eventually(|| rig.engine.connection_count() == 1).await);
    let records = rig.engine.connections();
    let record = records.first().unwrap();
    assert_eq!(record.chains.first().map(AsRef::as_ref), Some("DIRECT"));
    assert_eq!(rig.engine.traffic_total(false).0, 4);

    rig.engine.close_all_connections();
    assert!(eventually(|| rig.engine.connection_count() == 0).await);
    let mut rest = [0u8; 1];
    assert_eq!(
        timeout(PATIENCE, stream.read(&mut rest))
            .await
            .expect("the stream stays open")
            .unwrap_or(0),
        0
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flow_still_dialing_when_every_connection_closes_is_closed_as_well() {
    let echo = tcp_echo().await;
    let (upstream, _) = upstream_socks().await;
    let gate = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gated = gate.local_addr().unwrap().port();
    let (entered, dialing) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut client, _) = gate.accept().await.unwrap();
        let _ = entered.send(());
        let _ = released.await;
        let mut server = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream))
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    });
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {gated}}}\n\
         rules:\n  - MATCH,up\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    timeout(PATIENCE, dialing)
        .await
        .expect("the flow never dialed")
        .unwrap();
    rig.engine.close_all_connections();
    release.send(()).unwrap();
    let mut rest = [0u8; 1];
    let read = timeout(PATIENCE, stream.read(&mut rest)).await;
    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "the flow that was dialing stayed open"
    );
    assert_eq!(rig.engine.connection_count(), 0);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lazy_header_waits_for_a_slow_client_and_still_lets_a_server_speak_first() {
    let echo = tcp_echo().await;
    let greeter = greeter_server().await;
    let (vless, firsts) = vless_server().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: v, type: vless, server: 127.0.0.1, port: {vless}, uuid: b831381d-6324-4d53-ad4f-8cda48b30811}}\n\
         rules:\n  - MATCH,v\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    let mut slow = socks_connect(rig.mixed, echo).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    round_trip(&mut slow).await;
    assert!(
        lock(&firsts)[0].ends_with(b"ping"),
        "the header left without the client's first bytes: {:?}",
        lock(&firsts)
    );

    let mut quiet = socks_connect(rig.mixed, greeter).await.unwrap();
    let mut hello = [0u8; 2];
    timeout(PATIENCE, quiet.read_exact(&mut hello))
        .await
        .expect("the server's greeting never came")
        .unwrap();
    assert_eq!(&hello, b"hi");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rules_pick_a_group_and_a_selection_moves_it() {
    let echo = tcp_echo().await;
    let (upstream, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [up, DIRECT]}}\n\
         rules:\n  - DST-PORT,{},G\n  - MATCH,REJECT\n",
        echo.port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    assert!(
        rig.engine
            .proxy_views()
            .all
            .iter()
            .any(|name| name.as_ref() == "G")
    );
    assert_eq!(rig.selected("G").as_deref(), Some("up"));
    assert_eq!(rig.kind("G"), "Selector");

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(lock(&seen).len(), 1);
    assert_eq!(lock(&seen)[0], echo.to_string());

    let outcome = rig.engine.select("G", "DIRECT").await;
    assert!(outcome.changed);
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(
        lock(&seen).len(),
        1,
        "the second flow must not pass the node"
    );
    assert_eq!(rig.selected("G").as_deref(), Some("DIRECT"));

    let other = tcp_echo().await;
    assert!(
        refused(rig.mixed, other).await,
        "MATCH,REJECT refuses what no other rule takes"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_selected_map_is_honoured_when_a_config_applies() {
    let (upstream, _) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [up, DIRECT]}}\n\
         rules:\n  - MATCH,G\n"
    );
    let selected = BTreeMap::from([("G".to_string(), "DIRECT".to_string())]);
    rig.apply_with(&config, selected).await.unwrap();
    assert_eq!(rig.selected("G").as_deref(), Some("DIRECT"));
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_config_falls_back_to_direct_and_says_so() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    let failure = rig
        .apply("rules:\n  - NOT-A-RULE,x,DIRECT\n")
        .await
        .unwrap_err();
    assert_eq!(failure.code, "config_rejected");
    assert!(
        failure.message.contains("NOT-A-RULE"),
        "{}",
        failure.message
    );
    rig.engine.start_listeners().await;
    assert!(
        socks_connect(rig.mixed, echo).await.is_err(),
        "the default config opens no port"
    );
    assert_eq!(rig.kind("DIRECT"), "Direct");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_that_cannot_be_built_is_set_aside_and_the_config_runs() {
    let rig = Rig::new();
    let uuid = "6a4f3bc1-2c44-4a43-a5a3-3f1a2b0e6a11";
    let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let config = format!(
        "proxies:\n  \
         - {{name: pin, type: vless, server: 127.0.0.1, port: 1, uuid: {uuid}, tls: true, fingerprint: chrome}}\n  \
         - {{name: ws-reality, type: vless, server: 127.0.0.1, port: 1, uuid: {uuid}, tls: true, network: ws, \
         client-fingerprint: chrome, reality-opts: {{public-key: {key}}}}}\n\
         proxy-providers:\n  \
         inline:\n    type: inline\n    payload:\n      \
         - {{name: in-pin, type: trojan, server: 127.0.0.1, port: 1, password: p, fingerprint: zz}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [pin, ws-reality, DIRECT], use: [inline]}}\n\
         rules:\n  - MATCH,G\n"
    );
    rig.apply(&config).await.unwrap();
    let warned: Vec<_> = rig
        .engine
        .warnings()
        .into_iter()
        .map(|w| (w.code, w.path))
        .collect();
    assert_eq!(
        warned,
        [
            ("proxy_quarantined", "proxies.pin".to_string()),
            ("proxy_quarantined", "proxies.ws-reality".to_string()),
        ]
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_emptied_for_override_expr_leaves_the_config_running() {
    let rig = Rig::new();
    rig.apply(
        "proxy-providers:\n  sub:\n    type: inline\n    override:\n      override-expr: ['.udp = true']\n    \
         payload:\n      - {name: a, type: socks5, server: 127.0.0.1, port: 1}\n\
         proxy-groups:\n  - {name: G, type: select, use: [sub], proxies: [DIRECT]}\n\
         rules:\n  - MATCH,G\n",
    )
    .await
    .unwrap();
    let warned: Vec<_> = rig.engine.warnings().into_iter().map(|w| w.code).collect();
    assert_eq!(warned, ["provider_emptied"]);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_geo_file_that_cannot_be_fetched_rejects_the_config() {
    let (server, hits) = http_server(HashMap::new()).await;
    let rig = Rig::new();
    let config = format!(
        "geox-url:\n  mmdb: http://{server}/Country.mmdb\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,DIRECT\n"
    );
    let failure = rig.apply(&config).await.unwrap_err();
    assert_eq!(failure.code, "config_rejected");
    assert!(
        failure.message.contains("can't download MMDB"),
        "{}",
        failure.message
    );
    assert!(failure.message.contains("404"), "{}", failure.message);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn providers_load_over_the_tunnel_and_update_on_request() {
    let echo = tcp_echo().await;
    let (upstream, seen) = upstream_socks().await;
    let nodes = format!(
        "proxies:\n  - {{name: fetched, type: socks5, server: 127.0.0.1, port: {upstream}}}\n"
    );
    let (server, hits) = http_server(HashMap::from([
        ("/p.yaml", nodes),
        ("/r.txt", format!("{}/32\n", echo.ip())),
    ]))
    .await;
    let rig = Rig::new();
    let config = format!(
        "proxy-providers:\n  sub:\n    type: http\n    url: http://{server}/p.yaml\n    path: providers/p.yaml\n\
         rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/r.txt\n    path: rules/r.txt\n\
         proxy-groups:\n  - {{name: G, type: select, use: [sub]}}\n\
         rules:\n  - RULE-SET,local,G\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    assert!(
        eventually(|| {
            let loaded = rig.events.loaded();
            loaded.iter().any(|name| name == "sub") && loaded.iter().any(|name| name == "local")
        })
        .await,
        "providers did not report loading: {:?}",
        rig.events.loaded()
    );
    let names: Vec<String> = rig
        .engine
        .providers()
        .list()
        .into_iter()
        .map(|view| view.name)
        .collect();
    assert_eq!(names, ["local", "sub"]);
    let rule = rig.engine.providers().get("local").unwrap();
    assert_eq!(rule.kind, "Rule");
    assert_eq!(rule.vehicle_type, "HTTP");
    assert_eq!(rule.count, 1);
    assert!(rig.home.path().join("rules/r.txt").is_file());
    assert_eq!(rig.selected("G").as_deref(), Some("fetched"));

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(lock(&seen).len(), 1);

    let before = hits.load(Ordering::SeqCst);
    rig.engine.providers().update("local").await.unwrap();
    rig.engine.providers().update("sub").await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), before + 2);

    let missing = rig.engine.providers().update("nope").await.unwrap_err();
    assert_eq!(missing.code, "provider_not_found");
    rig.engine.shutdown().await;
}

/// Answers the first request with 503 and every later one with `body`.
async fn flaky_server(body: String) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let body: Arc<str> = body.into();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let first = counter.fetch_add(1, Ordering::SeqCst) == 0;
            let body = body.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let response = if first {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (server, hits)
}

async fn wait_loaded(rig: &Rig, name: &str) -> bool {
    for _ in 0..60 {
        if rig.events.loaded().iter().any(|loaded| loaded == name) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_provider_that_failed_its_first_fetch_is_retried_before_the_interval() {
    let (server, hits) = flaky_server("10.0.0.0/8\n".to_string()).await;
    let rig = Rig::new();
    let config = format!(
        "rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/r.txt\n    path: rules/r.txt\n    interval: 3600\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    assert!(
        wait_loaded(&rig, "local").await,
        "the provider was not retried"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert_eq!(rig.engine.providers().get("local").unwrap().count, 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_provider_without_an_interval_is_not_retried() {
    let (server, hits) = flaky_server(
        "proxies:\n  - {name: fetched, type: socks5, server: 127.0.0.1, port: 1}\n".to_string(),
    )
    .await;
    let rig = Rig::new();
    let config = format!(
        "proxy-providers:\n  sub:\n    type: http\n    url: http://{server}/p.yaml\n    path: providers/p.yaml\n    interval: 0\n\
         proxy-groups:\n  - {{name: G, type: select, use: [sub]}}\n\
         rules:\n  - MATCH,G\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    assert!(!wait_loaded(&rig, "sub").await, "the provider was retried");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_side_load_replaces_a_rule_set_without_a_reapply() {
    let echo = tcp_echo().await;
    let (server, _) = http_server(HashMap::from([("/r.txt", "10.0.0.0/8\n".to_string())])).await;
    let rig = Rig::new();
    let config = format!(
        "rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/r.txt\n    path: rules/r.txt\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    assert!(eventually(|| rig.events.loaded().iter().any(|name| name == "local")).await);

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    rig.engine
        .providers()
        .side_load("local", format!("{}/32\n", echo.ip()))
        .await
        .unwrap();
    assert!(refused(rig.mixed, echo).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_rule_provider_reloads_when_the_file_is_rewritten() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    std::fs::write(rig.home.path().join("r.txt"), "10.0.0.0/8\n").unwrap();
    let config = "rule-providers:\n  local:\n    type: file\n    behavior: ipcidr\n    format: text\n    path: r.txt\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n";
    rig.apply(config).await.unwrap();
    rig.engine.start_listeners().await;
    assert!(eventually(|| rig.events.loaded().iter().any(|name| name == "local")).await);

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    std::fs::write(
        rig.home.path().join("r.txt"),
        format!("{}/32\n10.0.0.0/8\n", echo.ip()),
    )
    .unwrap();
    let mut rejected = false;
    for _ in 0..100 {
        if refused(rig.mixed, echo).await {
            rejected = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(rejected, "the rewritten file was never reloaded");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_rule_provider_serves_its_payload_until_the_file_loads() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    let config = format!(
        "rule-providers:\n  local:\n    type: file\n    behavior: ipcidr\n    format: text\n    path: r.txt\n    payload:\n      - {}/32\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n",
        echo.ip()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    assert!(refused(rig.mixed, echo).await);

    std::fs::write(rig.home.path().join("r.txt"), "10.0.0.0/8\n").unwrap();
    let mut open = false;
    for _ in 0..100 {
        if !refused(rig.mixed, echo).await {
            open = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(open, "the loaded file never replaced the payload");
    rig.engine.shutdown().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_path_through_a_symlink_names_the_provider_and_the_path() {
    let rig = Rig::new();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), rig.home.path().join("linked")).unwrap();
    let config = "rule-providers:\n  local:\n    type: file\n    behavior: domain\n    path: linked/r.txt\n\
                  rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n";
    let failure = rig.apply(config).await.unwrap_err();
    assert!(
        failure
            .message
            .contains("rule provider local: path crosses a symlink: linked/r.txt"),
        "{}",
        failure.message
    );
    rig.engine.shutdown().await;
}

/// Answers the first request with `body` and never answers another.
async fn answers_once(body: String) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut first = true;
        while let Ok((mut stream, _)) = listener.accept().await {
            let answer = std::mem::take(&mut first).then(|| body.clone());
            tokio::spawn(async move {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let Some(body) = answer else {
                    return std::future::pending().await;
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    server
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reapplied_rule_set_keeps_matching_while_it_loads_again() {
    let echo = tcp_echo().await;
    let server = answers_once(format!("{}/32\n", echo.ip())).await;
    let rig = Rig::new();
    let config = |path: &str| {
        format!(
            "rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/{path}\n    path: rules/{path}\n\
             rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n"
        )
    };
    rig.apply(&config("r.txt")).await.unwrap();
    rig.engine.start_listeners().await;
    assert!(eventually(|| rig.events.loaded().iter().any(|name| name == "local")).await);
    assert!(refused(rig.mixed, echo).await);

    std::fs::remove_file(rig.home.path().join("rules/r.txt")).unwrap();
    rig.apply(&config("r.txt")).await.unwrap();
    assert!(
        refused(rig.mixed, echo).await,
        "the rule set was empty while it was fetched again"
    );

    rig.apply(&config("s.txt")).await.unwrap();
    assert!(
        !refused(rig.mixed, echo).await,
        "a provider with another source kept the old set"
    );
    rig.engine.shutdown().await;
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

fn last_a_record(answer: &[u8]) -> [u8; 4] {
    assert_eq!(&answer[..2], &[0x12, 0x34]);
    assert!(answer[6] != 0 || answer[7] != 0, "no answers: {answer:?}");
    answer[answer.len() - 4..].try_into().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dns_listener_answers_from_hosts_over_udp_and_tcp() {
    let port = free_port();
    let rig = Rig::new();
    let config = format!(
        "hosts:\n  a.test: 1.2.3.4\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: redir-host\n  nameserver:\n    - 127.0.0.1:1\n\
         rules:\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(&dns_query("a.test"), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no UDP answer")
        .unwrap();
    assert_eq!(last_a_record(&buf[..len]), [1, 2, 3, 4]);

    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let query = dns_query("a.test");
    let mut framed = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    stream.write_all(&framed).await.unwrap();
    let mut prefix = [0u8; 2];
    timeout(PATIENCE, stream.read_exact(&mut prefix))
        .await
        .expect("no TCP answer")
        .unwrap();
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(last_a_record(&answer), [1, 2, 3, 4]);

    let again = format!(
        "hosts:\n  a.test: 5.6.7.8\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: redir-host\n  nameserver:\n    - 127.0.0.1:1\n\
         rules:\n  - MATCH,DIRECT\n"
    );
    rig.apply(&again).await.unwrap();
    socket
        .send_to(&dns_query("a.test"), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no answer after a reapply")
        .unwrap();
    assert_eq!(last_a_record(&buf[..len]), [5, 6, 7, 8]);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_through_socks_reaches_its_target_and_back() {
    let echo = udp_echo().await;
    let SocketAddr::V4(echo_v4) = echo else {
        panic!("IPv4 expected")
    };
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;

    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
        .await
        .unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&echo_v4.ip().octets());
    packet.extend_from_slice(&echo_v4.port().to_be_bytes());
    packet.extend_from_slice(b"datagram");
    socket.send_to(&packet, relay).await.unwrap();

    let mut buf = [0u8; 256];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no UDP reply")
        .unwrap();
    assert_eq!(&buf[len - 8..len], b"datagram");
    assert_eq!(&buf[4..8], &echo_v4.ip().octets());
    assert!(eventually(|| rig.engine.connection_count() >= 1).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dns_node_answers_from_the_core_over_tcp_and_udp() {
    let rig = Rig::new();
    rig.apply(
        "hosts:\n  a.test: 1.2.3.4\n\
         dns:\n  enable: true\n  enhanced-mode: redir-host\n  nameserver:\n    - 127.0.0.1:1\n\
         proxies:\n  - {name: dns-out, type: dns}\n\
         rules:\n  - DST-PORT,53,dns-out\n  - MATCH,REJECT\n",
    )
    .await
    .unwrap();
    rig.engine.start_listeners().await;
    assert_eq!(rig.kind("dns-out"), "Dns");
    let resolver = SocketAddr::from(([192, 0, 2, 1], 53));

    let mut stream = socks_connect(rig.mixed, resolver).await.unwrap();
    for _ in 0..2 {
        let query = dns_query("a.test");
        let mut framed = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        stream.write_all(&framed).await.unwrap();
        let mut prefix = [0u8; 2];
        timeout(PATIENCE, stream.read_exact(&mut prefix))
            .await
            .expect("no TCP answer")
            .unwrap();
        let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(last_a_record(&answer), [1, 2, 3, 4]);
    }

    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
        .await
        .unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 192, 0, 2, 1, 0, 53];
    packet.extend_from_slice(&dns_query("a.test"));
    socket.send_to(&packet, relay).await.unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no UDP answer")
        .unwrap();
    assert_eq!(&buf[..10], &[0, 0, 0, 1, 192, 0, 2, 1, 0, 53]);
    assert_eq!(last_a_record(&buf[10..len]), [1, 2, 3, 4]);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_update_changes_the_mode_and_the_route_stamp() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,REJECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    assert!(refused(rig.mixed, echo).await);

    let before = rig.engine.watch_route(true).stamp;
    let request = UpdateRequest {
        mode: Some("direct".to_string()),
        ..UpdateRequest::default()
    };
    rig.engine.update(request).await.unwrap();
    let after = rig.engine.watch_route(true).stamp;
    assert_eq!(after.epoch, before.epoch);
    assert!(after.version > before.version);

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    let request = UpdateRequest {
        ipv6: Some(false),
        ..UpdateRequest::default()
    };
    rig.engine.update(request).await.unwrap();
    let moved = rig.engine.watch_route(false).stamp;
    assert_eq!(
        moved.epoch,
        after.epoch + 1,
        "IPv6 moves a direct dial's exit"
    );
    rig.engine.shutdown().await;
}

/// mihomo's default listeners filter every peer by the LAN lists, LAN or not
/// (`listener/mixed/mixed.go`), and bind `bind-address` only with `allow-lan`
/// (`listener/listener.go` `genAddr`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lan_keys_bind_and_filter_the_listeners() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply(
        "allow-lan: true\nbind-address: 127.0.0.1\nlan-allowed-ips: [127.0.0.0/8]\nrules:\n  - MATCH,DIRECT\n",
    )
    .await
    .unwrap();
    rig.engine.start_listeners().await;
    assert!(
        TcpStream::connect((Ipv6Addr::LOCALHOST, rig.mixed))
            .await
            .is_err(),
        "bound to the one address only"
    );
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    let request = UpdateRequest {
        lan_disallowed_ips: Some(vec!["127.0.0.1/32".to_string()]),
        ..UpdateRequest::default()
    };
    rig.engine.update(request).await.unwrap();
    assert!(refused(rig.mixed, echo).await, "the deny list wins");

    let request = UpdateRequest {
        allow_lan: Some(false),
        bind_address: Some("192.0.2.1".to_string()),
        ..UpdateRequest::default()
    };
    rig.engine.update(request).await.unwrap();
    assert!(
        refused(rig.mixed, echo).await,
        "the lists hold without the LAN"
    );
    let request = UpdateRequest {
        lan_disallowed_ips: Some(Vec::new()),
        ..UpdateRequest::default()
    };
    rig.engine.update(request).await.unwrap();
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    let request = UpdateRequest {
        lan_allowed_ips: Some(vec!["10.0.0.0/8".to_string(), "127.0.0.1".to_string()]),
        ..UpdateRequest::default()
    };
    let failure = rig.engine.update(request).await.unwrap_err();
    assert_eq!(failure.code, "invalid_arguments");
    let general = rig.engine.general().await.unwrap();
    assert_eq!(general.lan_allowed_ips, ["127.0.0.0/8"]);
    assert_eq!(general.bind_address, "192.0.2.1");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_update_before_any_config_is_refused() {
    let rig = Rig::new();
    let failure = rig
        .engine
        .update(UpdateRequest::default())
        .await
        .unwrap_err();
    assert_eq!(failure.message, "config is not applied");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listeners_follow_the_start_and_stop_calls() {
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
            .await
            .is_err(),
        "a config alone opens no port"
    );
    rig.engine.start_listeners().await;
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
            .await
            .is_ok()
    );
    rig.engine.stop_listeners().await;
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
            .await
            .is_err()
    );
    rig.engine.start_listeners().await;
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
            .await
            .is_ok()
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delay_tests_read_the_node_and_name_what_failed() {
    let (server, _) = http_server(HashMap::from([("/ok", "ok".to_string())])).await;
    let (upstream, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         rules:\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();

    let url = format!("http://{server}/ok");
    let good = rig.engine.test_delay("up", &url, 3000).await;
    assert!(good.value > 0, "{good:?}");
    assert_eq!(lock(&seen).len(), 1);

    let unknown = rig.engine.test_delay("nope", &url, 3000).await;
    assert_eq!(unknown.value, -2);

    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_probe_reports_where_it_left_and_the_route_can_be_rechecked() {
    let (server, _) = http_server(HashMap::from([("/ip", "203.0.113.7".to_string())])).await;
    let (upstream, _) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [up, DIRECT]}}\n\
         rules:\n  - MATCH,G\n"
    );
    rig.apply(&config).await.unwrap();

    let url = format!("http://{server}/ip");
    let answer = rig
        .engine
        .probe_outbound_ip("G".to_string(), vec![url], 5000)
        .await;
    assert_eq!(answer["body"], "203.0.113.7", "{answer}");
    assert_eq!(answer["chains"], serde_json::json!(["up", "G"]), "{answer}");
    let hits = answer["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "{answer}");
    let hit = RouteHit {
        host: hits[0]["host"].as_str().unwrap().to_string(),
        proxy: hits[0]["proxy"].as_str().unwrap_or("").to_string(),
        exit: hits[0]["exit"].as_str().unwrap().to_string(),
    };
    assert!(hit.exit.starts_with("\"up\" Socks5 "), "{}", hit.exit);

    let (_, held) = rig.engine.check_routes(vec![vec![hit.clone()]]).await;
    assert_eq!(held, [true]);

    rig.engine.select("G", "DIRECT").await;
    let (_, held) = rig.engine.check_routes(vec![vec![hit]]).await;
    assert_eq!(held, [false], "the selection moved the exit");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_core_that_shut_down_can_start_over() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    rig.engine.shutdown().await;
    assert!(!rig.engine.is_initialized());
    assert!(
        rig.apply("rules:\n  - MATCH,DIRECT\n").await.is_err(),
        "setup before init"
    );

    rig.engine
        .init(rig.home.path().to_str().unwrap(), 0)
        .unwrap();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_in_a_group_moves_on_to_the_next_rule() {
    let echo = tcp_echo().await;
    let (upstream, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [PASS, up]}}\n\
         rules:\n  - DST-PORT,{},G\n  - DST-PORT,{},up\n  - MATCH,REJECT\n",
        echo.port(),
        echo.port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(lock(&seen).len(), 1);
    let records = rig.engine.connections();
    assert_eq!(
        records[0].chains.first().map(AsRef::as_ref),
        Some("up"),
        "the group passed, so the second rule's node carries it"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_skips_a_rule_whose_outbound_has_no_udp() {
    let echo = udp_echo().await;
    let SocketAddr::V4(echo_v4) = echo else {
        panic!("IPv4 expected")
    };
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: web, type: http, server: 127.0.0.1, port: {}}}\n\
         rules:\n  - NETWORK,UDP,web\n  - MATCH,DIRECT\n",
        free_port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
        .await
        .unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    let relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&echo_v4.ip().octets());
    packet.extend_from_slice(&echo_v4.port().to_be_bytes());
    packet.extend_from_slice(b"datagram");
    socket.send_to(&packet, relay).await.unwrap();
    let mut buf = [0u8; 256];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no UDP reply")
        .unwrap();
    assert_eq!(&buf[len - 8..len], b"datagram");
    assert!(eventually(|| rig.engine.connection_count() >= 1).await);
    let chains = rig.engine.connections()[0].chains.clone();
    assert_eq!(chains.first().map(AsRef::as_ref), Some("DIRECT"));
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_refuses_a_loop_back_into_the_core() {
    let echo = tcp_echo().await;
    let SocketAddr::V4(echo_v4) = echo else {
        panic!("IPv4 expected")
    };
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    let own = SocketAddr::from((Ipv4Addr::LOCALHOST, rig.mixed));
    let mut stream = socks_connect(rig.mixed, own).await.unwrap();

    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    timeout(PATIENCE, stream.read_exact(&mut method))
        .await
        .expect("the nested greeting was not answered")
        .unwrap();
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&echo_v4.ip().octets());
    request.extend_from_slice(&echo_v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let _ = stream.write_all(b"ping").await;

    let mut seen = Vec::new();
    let _ = timeout(PATIENCE, stream.read_to_end(&mut seen))
        .await
        .expect("the nested flow was left open");
    assert!(
        !seen.windows(4).any(|window| window == b"ping"),
        "the nested flow came out of DIRECT: {seen:?}"
    );
    drop(stream);
    assert!(eventually(|| rig.engine.connection_count() == 0).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fake_ip_flow_is_routed_by_the_name_behind_it() {
    let echo = tcp_echo().await;
    let (upstream, seen) = upstream_socks().await;
    let port = free_port();
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - 127.0.0.1:1\n\
         rules:\n  - DOMAIN,faked.test,up\n  - MATCH,REJECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(&dns_query("faked.test"), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no fake-ip answer")
        .unwrap();
    let fake = Ipv4Addr::from(last_a_record(&buf[..len]));
    assert_eq!(fake.octets()[..2], [198, 18], "{fake}");

    let target = SocketAddr::from((fake, echo.port()));
    let mut stream = socks_connect(rig.mixed, target).await.unwrap();
    let _ = stream.write_all(b"x").await;
    assert!(
        eventually(|| !lock(&seen).is_empty()).await,
        "the flow never reached the node"
    );
    assert_eq!(lock(&seen)[0], format!("faked.test:{}", echo.port()));
    rig.engine.shutdown().await;
}

async fn fake_ip_of(port: u16, host: &str) -> Ipv4Addr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(&dns_query(host), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no fake-ip answer")
        .unwrap();
    Ipv4Addr::from(last_a_record(&buf[..len]))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stored_fake_ips_outlive_a_restart() {
    let port = free_port();
    let config = format!(
        "profile:\n  store-fake-ip: true\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - 127.0.0.1:1\n"
    );
    let rig = Rig::new();
    rig.apply(&config).await.unwrap();
    let kept = fake_ip_of(port, "kept.test").await;
    rig.engine.shutdown().await;
    let Rig { engine, home, .. } = rig;
    drop(engine);

    let rig = Rig::at(home);
    rig.apply(&config).await.unwrap();
    assert_ne!(fake_ip_of(port, "new.test").await, kept);
    assert_eq!(fake_ip_of(port, "kept.test").await, kept);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sniffed_name_is_what_rules_see() {
    let (server, _) = http_server(HashMap::from([("/", "hello".to_string())])).await;
    let (upstream, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         sniffer:\n  enable: true\n  parse-pure-ip: true\n  sniff:\n    HTTP:\n      ports: [{}]\n      override-destination: false\n\
         rules:\n  - DOMAIN,sniffed.test,up\n  - MATCH,REJECT\n",
        server.port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    let mut stream = socks_connect(rig.mixed, server).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: sniffed.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = Vec::new();
    timeout(PATIENCE, stream.read_to_end(&mut body))
        .await
        .expect("no HTTP answer")
        .unwrap();
    assert!(String::from_utf8_lossy(&body).ends_with("hello"));
    assert_eq!(
        lock(&seen)[0],
        server.to_string(),
        "without override-destination the node dials the original address"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_flows_leave_nothing_behind() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..200 {
            let (mut stream, _) = listener.accept().await.unwrap();
            tasks.spawn(async move {
                let (mut read, mut write) = stream.split();
                tokio::io::copy(&mut read, &mut write)
                    .await
                    .expect("echo copy");
                write.shutdown().await.expect("origin half-close");
            });
        }
        while let Some(task) = tasks.join_next().await {
            task.unwrap();
        }
    });
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;

    // macOS caps a listen backlog at kern.ipc.somaxconn, 128 by default; 200 simultaneous
    // connects can overflow the mixed listener's accept queue before it drains it.
    let handshakes = Arc::new(tokio::sync::Semaphore::new(128));
    let mut tasks = Vec::new();
    for _ in 0..200 {
        let mixed = rig.mixed;
        let handshakes = handshakes.clone();
        tasks.push(tokio::spawn(async move {
            timeout(PATIENCE, async {
                let permit = handshakes.acquire().await.expect("semaphore open");
                let mut stream = socks_connect(mixed, echo).await.expect("SOCKS connect");
                drop(permit);
                let payload = vec![7u8; 64 * 1024];
                let (mut read, mut write) = stream.split();
                let send = async {
                    write.write_all(&payload).await.expect("payload send");
                    write.shutdown().await.expect("client half-close");
                };
                let mut echoed = vec![0u8; payload.len()];
                let receive = async {
                    read.read_exact(&mut echoed).await.expect("echo payload");
                    let mut trailing = [0u8; 1];
                    assert_eq!(read.read(&mut trailing).await.expect("echo EOF"), 0);
                };
                tokio::join!(send, receive);
                assert_eq!(echoed, payload);
            })
            .await
            .expect("full flow (connect, payload, half-close, EOF) stalled");
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    timeout(PATIENCE, origin)
        .await
        .expect("echo tasks did not finish")
        .unwrap();
    assert!(
        eventually(|| rig.engine.connection_count() == 0).await,
        "{} connections left",
        rig.engine.connection_count()
    );
    assert_eq!(rig.engine.traffic_total(false).0, 200 * 64 * 1024);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capabilities_report_ss_plugins_and_congestion_controllers() {
    let rig = Rig::new();
    let value = serde_json::to_value(rig.engine.capabilities()).unwrap();
    assert_eq!(
        value["ss-plugins"],
        serde_json::json!(["obfs", "v2ray-plugin", "shadow-tls", "jls", "gost-plugin"])
    );
    assert_eq!(
        value["congestion-controllers"],
        serde_json::json!(["cubic", "reno"])
    );
    rig.engine.shutdown().await;
}

fn ntp_reply(request: &[u8], skew_secs: u64) -> Vec<u8> {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + skew_secs
        + 2_208_988_800;
    let mut reply = vec![0u8; 48];
    reply[0] = 0x24;
    reply[1] = 2;
    reply[24..32].copy_from_slice(&request[40..48]);
    reply[32..40].copy_from_slice(&(unix << 32).to_be_bytes());
    reply[40..48].copy_from_slice(&(unix << 32).to_be_bytes());
    reply
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ntp_section_runs_a_service_that_a_config_without_it_stops() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 128];
        while let Ok((len, peer)) = server.recv_from(&mut buf).await {
            if len >= 48 {
                let _ = server.send_to(&ntp_reply(&buf[..len], 7200), peer).await;
            }
        }
    });
    let rig = Rig::new();
    rig.apply(&format!(
        "ntp:\n  enable: true\n  server: 127.0.0.1\n  port: {port}\n  interval: 30\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await
    .unwrap();
    let mut offset = 0;
    for _ in 0..100 {
        offset = rig.engine.clock_offset_nanos();
        if offset != 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        (offset - 7_200_000_000_000).abs() < 3_000_000_000,
        "offset {offset}"
    );

    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    for _ in 0..100 {
        if rig.engine.clock_offset_nanos() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(rig.engine.clock_offset_nanos(), 0);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_off_leaves_flows_alone_and_capabilities_say_whether_it_is_built() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(
        rig.engine.capabilities().features.mitm,
        cfg!(feature = "mitm")
    );
    let certificate = rig.engine.mitm().certificate();
    if cfg!(feature = "mitm") {
        assert!(certificate.unwrap().is_none());
    } else {
        assert!(certificate.is_err());
    }
    rig.engine.shutdown().await;
}

/// A SOCKS5 server with UDP ASSOCIATE that counts the datagrams it relays.
async fn upstream_socks_udp() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let relayed = Arc::new(AtomicUsize::new(0));
    let count = relayed.clone();
    tokio::spawn(async move {
        while let Ok((mut control, _)) = listener.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                control.read_exact(&mut greeting).await.ok()?;
                control.write_all(&[5, 0]).await.ok()?;
                let mut head = [0u8; 10];
                control.read_exact(&mut head).await.ok()?;
                let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.ok()?;
                let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
                reply.extend_from_slice(&relay.local_addr().ok()?.port().to_be_bytes());
                control.write_all(&reply).await.ok()?;
                let (mut client, mut buf, mut idle) = (None, [0u8; 2048], [0u8; 1]);
                loop {
                    tokio::select! {
                        read = control.read(&mut idle) => {
                            if read.ok()? == 0 {
                                return Some(());
                            }
                        }
                        received = relay.recv_from(&mut buf) => {
                            let (len, from) = received.ok()?;
                            if client.is_none_or(|known| known == from) {
                                client = Some(from);
                                let dst = SocketAddr::from((
                                    Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
                                    u16::from_be_bytes([buf[8], buf[9]]),
                                ));
                                count.fetch_add(1, Ordering::SeqCst);
                                relay.send_to(&buf[10..len], dst).await.ok()?;
                            } else if let Some(client) = client {
                                let mut back = vec![0, 0, 0, 1];
                                if let SocketAddr::V4(from) = from {
                                    back.extend_from_slice(&from.ip().octets());
                                    back.extend_from_slice(&from.port().to_be_bytes());
                                }
                                back.extend_from_slice(&buf[..len]);
                                relay.send_to(&back, client).await.ok()?;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, relayed)
}

struct Association {
    _control: TcpStream,
    relay: SocketAddr,
    socket: UdpSocket,
}

async fn associate(port: u16) -> Association {
    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    Association {
        _control: control,
        relay: SocketAddr::from((
            Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
            u16::from_be_bytes([reply[8], reply[9]]),
        )),
        socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
    }
}

impl Association {
    async fn echoes(&self, echo: SocketAddr) -> bool {
        let SocketAddr::V4(echo) = echo else {
            panic!("tests use IPv4 targets");
        };
        let mut packet = vec![0, 0, 0, 1];
        packet.extend_from_slice(&echo.ip().octets());
        packet.extend_from_slice(&echo.port().to_be_bytes());
        packet.extend_from_slice(b"datagram");
        let mut buf = [0u8; 256];
        for _ in 0..3 {
            self.socket.send_to(&packet, self.relay).await.unwrap();
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_secs(1), self.socket.recv_from(&mut buf)).await
            {
                return &buf[len - 8..len] == b"datagram";
            }
        }
        false
    }
}

fn via_udp_proxy(proxy: u16) -> String {
    format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {proxy}, udp: true}}\n\
         rules:\n  - MATCH,up\n"
    )
}

/// Applying a second profile must not leave UDP behind, whether the listener keeps
/// its port or moves, and whether the listeners were stopped around the apply.
#[derive(Clone, Copy, Default)]
struct Switch {
    move_port: bool,
    stop_around: bool,
    open_to_lan: bool,
}

async fn udp_after_a_switch(switch: Switch) {
    let (echo, other) = (udp_echo().await, udp_echo().await);
    let (proxy, relayed) = upstream_socks_udp().await;
    let mut rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    let before = associate(rig.mixed).await;
    assert!(before.echoes(echo).await);
    assert_eq!(relayed.load(Ordering::SeqCst), 0);

    if switch.stop_around {
        rig.engine.stop_listeners().await;
    }
    if switch.move_port {
        rig.mixed = free_port();
    }
    let lan = if switch.open_to_lan {
        "allow-lan: true\n"
    } else {
        ""
    };
    rig.apply(&format!("{lan}{}", via_udp_proxy(proxy)))
        .await
        .unwrap();
    if switch.stop_around {
        rig.engine.start_listeners().await;
    }

    let fresh = associate(rig.mixed).await;
    assert!(
        fresh.echoes(echo).await,
        "a fresh association gets no reply"
    );
    assert!(
        relayed.load(Ordering::SeqCst) > 0,
        "it did not take the new profile's proxy"
    );

    if !switch.move_port && !switch.stop_around && !switch.open_to_lan {
        assert!(
            before.echoes(other).await,
            "an association from before the switch lost UDP"
        );
    }
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_follows_a_profile_switch_on_the_same_port() {
    udp_after_a_switch(Switch::default()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_follows_a_profile_switch_that_moves_the_port() {
    udp_after_a_switch(Switch {
        move_port: true,
        ..Switch::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_follows_a_profile_switch_between_a_stop_and_a_start() {
    udp_after_a_switch(Switch {
        stop_around: true,
        ..Switch::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_follows_a_profile_switch_that_opens_the_listener_to_the_lan() {
    udp_after_a_switch(Switch {
        open_to_lan: true,
        ..Switch::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_loads_report_their_outcome_only_once_the_apply_lets_them() {
    let rig = Rig::new();
    std::fs::write(
        rig.home.path().join("p.yaml"),
        "proxies:\n  - {name: pn, type: socks5, server: 127.0.0.1, port: 1}\n",
    )
    .unwrap();
    std::fs::write(rig.home.path().join("r.txt"), "10.0.0.0/8\n").unwrap();
    let hold = rig.engine.hold_first_loads();
    rig.apply(
        "proxy-providers:\n  sub: {type: file, path: p.yaml}\n\
         rule-providers:\n  local: {type: file, behavior: ipcidr, format: text, path: r.txt}\n\
         proxy-groups:\n  - {name: G, type: select, use: [sub]}\n\
         rules:\n  - RULE-SET,local,G\n  - MATCH,DIRECT\n",
    )
    .await
    .unwrap();
    assert!(
        eventually(|| rig
            .engine
            .providers()
            .list()
            .iter()
            .filter(|view| view.count == 1)
            .count()
            == 2)
        .await,
        "both providers load while every step is held"
    );
    assert!(
        rig.events.phases("sub").is_empty(),
        "{:?}",
        rig.events.phases("sub")
    );
    assert!(
        rig.events.phases("local").is_empty(),
        "{:?}",
        rig.events.phases("local")
    );

    drop(hold);
    let loaded = [ResourcePhase::Updating, ResourcePhase::Updated];
    assert!(
        eventually(|| rig.events.phases("sub") == loaded && rig.events.phases("local") == loaded)
            .await,
        "{:?} {:?}",
        rig.events.phases("sub"),
        rig.events.phases("local")
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_load_a_newer_apply_cuts_short_ends_superseded() {
    let silent = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            held.push(stream);
        }
    });
    let rig = Rig::new();
    rig.apply(&format!(
        "proxy-providers:\n  slow: {{type: http, url: 'http://{server}/p.yaml', path: p.yaml}}\n\
         proxy-groups:\n  - {{name: G, type: select, use: [slow]}}\n\
         rules:\n  - MATCH,DIRECT\n"
    ))
    .await
    .unwrap();
    assert!(
        eventually(|| rig.events.phases("slow") == [ResourcePhase::Updating]).await,
        "{:?}",
        rig.events.phases("slow")
    );

    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    let ended = [
        ResourcePhase::Updating,
        ResourcePhase::Failed(concord_common::SUPERSEDED.to_string()),
    ];
    assert!(
        eventually(|| rig.events.phases("slow") == ended).await,
        "{:?}",
        rig.events.phases("slow")
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_provider_reports_every_fetch_whatever_started_it() {
    let (server, _) = flaky_server("10.0.0.0/8\n".to_string()).await;
    let rig = Rig::new();
    let config = format!(
        "rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/r.txt\n    path: rules/r.txt\n    interval: 1\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    assert!(
        eventually(|| rig.events.phases("local").len() >= 6).await,
        "{:?}",
        rig.events.phases("local")
    );
    let seen = rig.events.phases("local");
    assert!(
        matches!(
            seen[..6],
            [
                ResourcePhase::Updating,
                ResourcePhase::Failed(_),
                ResourcePhase::Updating,
                ResourcePhase::Updated,
                ResourcePhase::Updating,
                ResourcePhase::Unchanged,
            ]
        ),
        "first load, retry, interval: {seen:?}"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_provider_update_and_side_load_from_a_caller_are_reported() {
    let rig = Rig::new();
    std::fs::write(rig.home.path().join("r.txt"), "10.0.0.0/8\n").unwrap();
    rig.apply(
        "rule-providers:\n  local: {type: file, behavior: ipcidr, format: text, path: r.txt}\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n",
    )
    .await
    .unwrap();
    assert!(eventually(|| rig.events.phases("local").len() == 2).await);

    rig.engine.providers().update("local").await.unwrap();
    rig.engine
        .providers()
        .side_load("local", "192.168.0.0/16\n".to_string())
        .await
        .unwrap();
    assert_eq!(
        rig.events.phases("local")[..6],
        [
            ResourcePhase::Updating,
            ResourcePhase::Updated,
            ResourcePhase::Updating,
            ResourcePhase::Unchanged,
            ResourcePhase::Updating,
            ResourcePhase::Updated,
        ]
    );
    rig.engine.shutdown().await;
}
