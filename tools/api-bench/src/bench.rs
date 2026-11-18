#![allow(
    clippy::disallowed_methods,
    reason = "the peers here stand for the outside world, not the core's own sockets"
)]

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use concord_api::{Control, ControlOptions, EventBus};
use concord_common::CoreOptions;
use concord_engine::{Engine, EngineConfig, SetupRequest};
use concord_ipc::{FramedChannel, Token, dial, initiate, respond};
use concord_platform::NativePlatform;
use concord_rpc::{Incoming, MessageChannel, MessageReader, MessageWriter, Server};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::mpsc;

const CONNECTIONS: usize = 1000;
const ACTIVE: usize = 100;
const CHURN_PER_TICK: usize = 5;
const WINDOW: Duration = Duration::from_secs(10);

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn echo_target() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                while let Ok(count) = stream.read(&mut buffer).await {
                    if count == 0 || stream.write_all(&buffer[..count]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

async fn through(proxy: u16, target: u16) -> TcpStream {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy))
        .await
        .unwrap();
    stream
        .write_all(format!("CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    stream
}

struct Rig {
    engine: Arc<Engine>,
    proxy: u16,
    target: u16,
    _home: tempfile::TempDir,
}

async fn boot(sink: Arc<dyn concord_common::EventSink>) -> Rig {
    let home = tempfile::tempdir().unwrap();
    let proxy = free_port();
    std::fs::write(
        home.path().join("config.yaml"),
        format!("mixed-port: {proxy}\nlog-level: silent\nrules:\n  - MATCH,DIRECT\n"),
    )
    .unwrap();
    let engine = Engine::new(EngineConfig {
        sink,
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    engine.init(home.path().to_str().unwrap(), 0).unwrap();
    engine
        .setup(SetupRequest {
            base: None,
            selected: Default::default(),
            options: CoreOptions::default(),
        })
        .await
        .unwrap();
    engine.start_listeners().await;
    Rig {
        engine,
        proxy,
        target: echo_target().await,
        _home: home,
    }
}

struct Load {
    held: Vec<TcpStream>,
    proxy: u16,
    target: u16,
}

impl Load {
    async fn open(rig: &Rig, count: usize) -> Load {
        let mut load = Load {
            held: Vec::new(),
            proxy: rig.proxy,
            target: rig.target,
        };
        for _ in 0..count {
            load.held.push(through(rig.proxy, rig.target).await);
        }
        load
    }

    async fn churn_and_traffic(&mut self, window: Duration) {
        let started = Instant::now();
        while started.elapsed() < window {
            for stream in self.held.iter_mut().take(ACTIVE) {
                let _ = stream.write_all(&[7u8; 100]).await;
            }
            for _ in 0..CHURN_PER_TICK {
                self.held.pop();
                self.held.push(through(self.proxy, self.target).await);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

fn bench_token() -> Token {
    Token::parse("00000000000000000000000000000000").unwrap()
}

struct Peer {
    writer: concord_ipc::FramedWriter<concord_ipc::Socket>,
    responses: mpsc::UnboundedReceiver<Value>,
    bytes: Arc<AtomicU64>,
    next: u64,
}

impl Peer {
    async fn connect(control: Arc<Control>, dir: &Path) -> Peer {
        let socket = dir.join(format!("{}.sock", rand_suffix()));
        let listener = UnixListener::bind(&socket).unwrap();
        let address = socket.to_str().unwrap().to_string();
        tokio::spawn(async move {
            let mut connection = dial(&address).await.unwrap();
            initiate(&mut connection, &bench_token()).await.unwrap();
            let server = Server::new(control);
            server.serve(FramedChannel::new(connection)).await;
        });
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = concord_ipc::Socket::Unix(stream);
        respond(&mut stream, &bench_token()).await.unwrap();
        let (mut reader, writer) = FramedChannel::new(stream).split();
        let bytes = Arc::new(AtomicU64::new(0));
        let (feed, responses) = mpsc::unbounded_channel();
        let counted = bytes.clone();
        tokio::spawn(async move {
            while let Ok(Some(Incoming::Message(message))) = reader.recv().await {
                counted.fetch_add(message.len() as u64 + 4, Ordering::Relaxed);
                if message.windows(5).any(|w| w == b"\"id\":") {
                    let _ = feed.send(serde_json::from_slice(&message).unwrap());
                }
            }
        });
        let mut peer = Peer {
            writer,
            responses,
            bytes,
            next: 0,
        };
        peer.call(
            "core.hello",
            json!({"protocol": {"min": 1, "max": 1}, "client": {"name": "bench", "version": "0"}}),
        )
        .await;
        peer
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.writer
            .send(serde_json::to_vec(&message).unwrap())
            .await
            .ok()
            .unwrap();
        loop {
            let response = self.responses.recv().await.unwrap();
            if response["id"] == json!(id) {
                return response;
            }
        }
    }
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn per_second(bytes: u64, window: Duration) -> f64 {
    bytes as f64 / window.as_secs_f64()
}

async fn wire() {
    let bus = EventBus::new();
    let rig = boot(bus.clone()).await;
    let control = Control::new(rig.engine.clone(), bus, ControlOptions::default());
    let dir = tempfile::tempdir().unwrap();
    let mut peer = Peer::connect(control, dir.path()).await;
    let mut load = Load::open(&rig, CONNECTIONS).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = peer.bytes.load(Ordering::Relaxed);
    let opened = peer
        .call(
            "connection.watch",
            json!({"credit": 1000, "maxBatchMs": 100}),
        )
        .await;
    let snapshot = peer.bytes.load(Ordering::Relaxed) - before;
    assert_eq!(
        opened["result"]["snapshot"]["connections"]
            .as_array()
            .unwrap()
            .len(),
        CONNECTIONS
    );
    println!(
        "connection.watch: snapshot of {CONNECTIONS} connections is {snapshot} bytes, sent once"
    );
    let before = peer.bytes.load(Ordering::Relaxed);
    tokio::time::sleep(WINDOW).await;
    println!(
        "idle:  {:.0} bytes/s",
        per_second(peer.bytes.load(Ordering::Relaxed) - before, WINDOW)
    );
    let before = peer.bytes.load(Ordering::Relaxed);
    load.churn_and_traffic(WINDOW).await;
    println!(
        "churn: {:.0} bytes/s ({} opens and closes per second, {ACTIVE} connections moving data)",
        per_second(peer.bytes.load(Ordering::Relaxed) - before, WINDOW),
        CHURN_PER_TICK * 10
    );
    drop(load);
    rig.engine.shutdown().await;
}

fn percentile(sorted: &[Duration], share: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * share) as usize]
}

async fn rtt() {
    let bus = EventBus::new();
    let rig = boot(bus.clone()).await;
    let control = Control::new(rig.engine.clone(), bus, ControlOptions::default());
    let dir = tempfile::tempdir().unwrap();
    let mut peer = Peer::connect(control, dir.path()).await;
    for method in ["core.lastWarnings", "core.stats", "proxy.groups"] {
        for _ in 0..1000 {
            peer.call(method, Value::Null).await;
        }
        let mut samples = Vec::new();
        for _ in 0..20_000 {
            let started = Instant::now();
            peer.call(method, Value::Null).await;
            samples.push(started.elapsed());
        }
        samples.sort();
        println!(
            "{method}: p50 {:?}  p90 {:?}  p99 {:?}  max {:?}",
            percentile(&samples, 0.5),
            percentile(&samples, 0.9),
            percentile(&samples, 0.99),
            samples[samples.len() - 1]
        );
    }
    rig.engine.shutdown().await;
}

async fn subs() {
    let bus = EventBus::new();
    let rig = boot(bus.clone()).await;
    let control = Control::new(rig.engine.clone(), bus, ControlOptions::default());
    let dir = tempfile::tempdir().unwrap();
    let mut peer = Peer::connect(control, dir.path()).await;
    for (method, params, count) in [
        ("route.watch", json!({}), 5000usize),
        ("log.watch", json!({}), 5000),
        ("connection.watch", json!({}), 2000),
    ] {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let before = concord_platform::resident_memory();
        let mut ids = Vec::new();
        for _ in 0..count {
            let answer = peer.call(method, params.clone()).await;
            ids.push(answer["id"].clone());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let grown = concord_platform::resident_memory().saturating_sub(before);
        println!(
            "{method}: {count} idle subscriptions grew RSS by {} KiB, {:.0} bytes each",
            grown / 1024,
            grown as f64 / count as f64
        );
        for id in ids {
            peer.writer
                .send(
                    serde_json::to_vec(
                        &json!({"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": id}}),
                    )
                    .unwrap(),
                )
                .await
                .ok()
                .unwrap();
        }
    }
    rig.engine.shutdown().await;
}

#[tokio::main]
pub async fn main() {
    concord_platform::raise_fd_limit();
    match std::env::args().nth(1).as_deref() {
        Some("wire") => wire().await,
        Some("rtt") => rtt().await,
        Some("subs") => subs().await,
        _ => eprintln!("usage: api-bench wire | rtt | subs"),
    }
}
