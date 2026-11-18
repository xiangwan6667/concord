#![allow(dead_code, reason = "each test file uses a different part")]
#![allow(
    clippy::disallowed_methods,
    reason = "test clients bind loopback sockets directly"
)]

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{BoxStream, FlowHandler, FlowMeta, UdpFlow, UdpPayload, UdpReply};
use concord_inbound::{ListenError, ListenSpec, ListenerKind, Listeners};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type TcpFn = dyn Fn(FlowMeta, BoxStream) + Send + Sync;

pub struct Fake {
    on_tcp: Box<TcpFn>,
    pub flows: Mutex<Vec<FlowMeta>>,
    pub datagrams: Mutex<Vec<(FlowMeta, Vec<u8>)>>,
    pub replies: Mutex<Vec<Arc<dyn UdpReply>>>,
}

impl Fake {
    pub fn new(on_tcp: impl Fn(FlowMeta, BoxStream) + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Fake {
            on_tcp: Box::new(on_tcp),
            flows: Mutex::new(Vec::new()),
            datagrams: Mutex::new(Vec::new()),
            replies: Mutex::new(Vec::new()),
        })
    }

    pub fn echo() -> Arc<Self> {
        Fake::new(|_, stream| {
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        })
    }

    pub fn flow_count(&self) -> usize {
        lock(&self.flows).len()
    }

    pub fn flow(&self, index: usize) -> FlowMeta {
        lock(&self.flows)[index].clone()
    }

    pub fn datagram_count(&self) -> usize {
        lock(&self.datagrams).len()
    }
}

impl FlowHandler for Fake {
    fn handle_tcp(&self, meta: FlowMeta, stream: BoxStream) {
        lock(&self.flows).push(meta.clone());
        (self.on_tcp)(meta, stream);
    }

    fn handle_udp(&self, flow: UdpFlow<'_>, payload: UdpPayload<'_>, reply: &Arc<dyn UdpReply>) {
        let meta = flow.meta();
        let payload = payload.as_slice().to_vec();
        lock(&self.datagrams).push((meta.clone(), payload.clone()));
        lock(&self.replies).push(reply.clone());
        let reply = reply.clone();
        let from = meta.dst;
        tokio::spawn(async move {
            let _ = poll_fn(|cx| reply.poll_write_back(cx, &payload, &from)).await;
        });
    }
}

pub struct Running {
    pub listeners: Listeners,
    pub fake: Arc<Fake>,
    pub spec: ListenSpec,
}

/// Port 0 gives a TCP listener a port from the system, and the UDP socket of a mixed or SOCKS
/// listener then binds the same number, which another socket on the host may already hold.
const FRESH_PORT_ATTEMPTS: usize = 8;

/// `reconcile`, binding again on a fresh port while a port 0 listener's UDP side collides.
pub async fn open(
    listeners: &Listeners,
    spec: &ListenSpec,
    handler: Arc<dyn FlowHandler>,
) -> Vec<ListenError> {
    let collided = |error: &ListenError| {
        spec.port(error.kind) == Some(0) && error.source.kind() == io::ErrorKind::AddrInUse
    };
    let mut errors = listeners.reconcile(spec, handler.clone()).await;
    for _ in 1..FRESH_PORT_ATTEMPTS {
        if !errors.iter().any(collided) {
            break;
        }
        errors = listeners.reconcile(spec, handler.clone()).await;
    }
    errors
}

pub async fn start(spec: ListenSpec, fake: Arc<Fake>) -> Running {
    let listeners = Listeners::new();
    let errors = open(&listeners, &spec, fake.clone()).await;
    assert!(errors.is_empty(), "{errors:?}");
    Running {
        listeners,
        fake,
        spec,
    }
}

pub async fn reconcile(running: &Running, spec: &ListenSpec) -> Vec<ListenError> {
    open(&running.listeners, spec, running.fake.clone()).await
}

impl Running {
    pub async fn addr(&self, kind: ListenerKind) -> SocketAddr {
        self.listeners
            .bound()
            .await
            .into_iter()
            .find(|bound| bound.kind == kind)
            .unwrap_or_else(|| panic!("{kind:?} is not bound"))
            .addr
    }
}

pub fn mixed() -> ListenSpec {
    ListenSpec {
        mixed_port: Some(0),
        ..Default::default()
    }
}

pub async fn connect(addr: SocketAddr) -> TcpStream {
    TcpStream::connect(addr).await.unwrap()
}

pub async fn read_exact(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut out))
        .await
        .expect("timed out")
        .unwrap();
    out
}

pub async fn read_until(stream: &mut TcpStream, marker: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while !out.ends_with(marker) {
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut byte))
            .await
            .expect("timed out")
            .unwrap();
        out.push(byte[0]);
    }
    out
}

pub async fn read_to_close(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
        .await
        .expect("timed out")
        .ok();
    out
}

pub async fn wait_for(mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached");
}

pub fn socks5_connect_domain(host: &str, port: u16) -> Vec<u8> {
    let mut out = vec![5, 1, 0, 3, host.len() as u8];
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

pub async fn socks5_session(addr: SocketAddr, host: &str, port: u16) -> TcpStream {
    let mut stream = connect(addr).await;
    stream.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(read_exact(&mut stream, 2).await, [5, 0]);
    stream
        .write_all(&socks5_connect_domain(host, port))
        .await
        .unwrap();
    let reply = read_exact(&mut stream, 10).await;
    assert_eq!(reply.get(..4), Some(&[5, 0, 0, 1][..]));
    stream
}

pub type Seen = Arc<Mutex<Vec<String>>>;

async fn fill_more(rd: &mut (impl AsyncReadExt + Unpin), buf: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 4096];
    match rd.read(&mut chunk).await {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
            true
        }
    }
}

/// An HTTP/1.1 origin behind the handler: it records each request head and
/// answers with whatever `respond(head, body)` returns, until the client closes.
pub fn origin(
    respond: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
) -> (Arc<Fake>, Seen) {
    let seen: Seen = Arc::default();
    let respond = Arc::new(respond);
    let record = seen.clone();
    let fake = Fake::new(move |_, stream| {
        let respond = respond.clone();
        let record = record.clone();
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(stream);
            let mut buf: Vec<u8> = Vec::new();
            loop {
                let end = loop {
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                    if !fill_more(&mut rd, &mut buf).await {
                        return;
                    }
                };
                let head = String::from_utf8_lossy(buf.get(..end).unwrap_or_default()).into_owned();
                buf.drain(..end);
                let lower = head.to_ascii_lowercase();
                let mut body = Vec::new();
                if lower.contains("transfer-encoding: chunked") {
                    loop {
                        body.append(&mut buf);
                        if body.ends_with(b"0\r\n\r\n") || !fill_more(&mut rd, &mut buf).await {
                            break;
                        }
                    }
                } else if let Some(length) = lower
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                {
                    while buf.len() < length {
                        if !fill_more(&mut rd, &mut buf).await {
                            return;
                        }
                    }
                    body = buf.drain(..length).collect();
                }
                lock(&record).push(head);
                let answer = respond(&lower, &body);
                if answer.is_empty() || wr.write_all(&answer).await.is_err() {
                    return;
                }
            }
        });
    });
    (fake, seen)
}

pub fn ok(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
