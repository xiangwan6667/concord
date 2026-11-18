//! Servers written from what mihomo's own servers parse (`vmess/websocket.go`
//! upgrade handling, `gun/server.go`, `xhttp/server.go`), sharing no code with
//! the client, so a client byte they would reject fails here.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use concord_common::BoxStream;
use concord_common::sync::lock;
use concord_transport::{
    DialFn, GrpcOptions, GunClient, Layer, TransportStack, WsOptions, XhttpClient, XhttpOptions,
};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::sync::mpsc;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + i / 251) % 256) as u8).collect()
}

async fn read_head(io: &mut DuplexStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 512];
        let n = io.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed before the request head ended");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return (String::from_utf8(buf).unwrap(), rest);
        }
    }
}

mod ws_server {
    use super::*;

    pub struct Upgraded {
        pub io: DuplexStream,
        pub early_data: Vec<u8>,
        pub head: String,
        pub leftover: Vec<u8>,
    }

    fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        head.lines().skip(1).find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.eq_ignore_ascii_case(name).then_some(v.trim())
        })
    }

    /// What `StreamUpgradedWebsocketConn` and gobwas' upgrader need to see.
    pub async fn accept(mut io: DuplexStream) -> Upgraded {
        let (head, leftover) = read_head(&mut io).await;
        assert!(head.starts_with("GET "), "{head}");
        assert!(head.lines().next().unwrap().ends_with(" HTTP/1.1"));
        assert_eq!(header(&head, "Upgrade"), Some("websocket"));
        assert_eq!(header(&head, "Connection"), Some("Upgrade"));
        assert_eq!(header(&head, "Sec-WebSocket-Version"), Some("13"));
        let key = header(&head, "Sec-WebSocket-Key").expect("key");
        assert_eq!(STANDARD.decode(key).unwrap().len(), 16);
        let mut sha = Sha1::new();
        sha.update(key.as_bytes());
        sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept = STANDARD.encode(sha.finalize());
        io.write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-Websocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let early_data = header(&head, "Sec-WebSocket-Protocol")
            .and_then(|v| URL_SAFE_NO_PAD.decode(v.replace(['+', '/', '='], "")).ok())
            .unwrap_or_default();
        Upgraded {
            io,
            early_data,
            head,
            leftover,
        }
    }

    /// Reads one frame the way a server must: client frames are masked.
    pub async fn read_frame(
        io: &mut DuplexStream,
        leftover: &mut Vec<u8>,
    ) -> Option<(u8, Vec<u8>)> {
        async fn take(io: &mut DuplexStream, leftover: &mut Vec<u8>, n: usize) -> Option<Vec<u8>> {
            while leftover.len() < n {
                let mut chunk = [0u8; 4096];
                let got = io.read(&mut chunk).await.unwrap();
                if got == 0 {
                    return None;
                }
                leftover.extend_from_slice(&chunk[..got]);
            }
            Some(leftover.drain(..n).collect())
        }
        let head = take(io, leftover, 2).await?;
        assert_eq!(head[1] & 0x80, 0x80, "client frames must be masked");
        let len = match head[1] & 0x7F {
            126 => u16::from_be_bytes(take(io, leftover, 2).await?.try_into().unwrap()) as usize,
            127 => u64::from_be_bytes(take(io, leftover, 8).await?.try_into().unwrap()) as usize,
            n => n as usize,
        };
        let key = take(io, leftover, 4).await?;
        let mut payload = take(io, leftover, len).await?;
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
        Some((head[0] & 0x0F, payload))
    }

    pub fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80 | opcode];
        match payload.len() {
            n if n < 126 => out.push(n as u8),
            n if n < 65536 => {
                out.push(126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        out
    }
}

fn ws_stack(opts: WsOptions) -> TransportStack {
    TransportStack::new(vec![Layer::Ws(opts)], Default::default())
}

type SeenHeaders = (String, String, String, String);

#[tokio::test]
async fn websocket_echoes_large_payloads_through_a_strict_server() {
    let (client, server) = duplex(1 << 16);
    let echo = tokio::spawn(async move {
        let mut up = ws_server::accept(server).await;
        let mut received = Vec::new();
        while let Some((op, data)) = ws_server::read_frame(&mut up.io, &mut up.leftover).await {
            if op == 8 {
                up.io.write_all(&ws_server::frame(8, &data)).await.unwrap();
                break;
            }
            assert_eq!(op, 2);
            received.extend_from_slice(&data);
            up.io.write_all(&ws_server::frame(2, &data)).await.unwrap();
        }
        received
    });
    let stack = ws_stack(WsOptions {
        path: "/ray".into(),
        headers: vec![("Host".into(), "front.example.net".into())],
        ..WsOptions::default()
    });
    let conn = stack.apply(Box::new(client), "198.51.100.9").await.unwrap();
    let payload = pattern(200_000);
    let (mut rd, mut wr) = tokio::io::split(conn);
    let send = payload.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&send).await.unwrap();
        wr.flush().await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut back = Vec::new();
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut chunk = [0u8; 8192];
        loop {
            let n = rd.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            back.extend_from_slice(&chunk[..n]);
        }
    })
    .await;
    assert!(read.is_ok(), "stalled after {} bytes", back.len());
    writer.await.unwrap();
    assert_eq!(back, payload);
    assert_eq!(echo.await.unwrap(), payload);
}

#[tokio::test]
async fn websocket_early_data_is_what_the_server_prepends() {
    let (client, server) = duplex(1 << 16);
    let accept = tokio::spawn(async move { ws_server::accept(server).await });
    let stack = ws_stack(WsOptions {
        path: "/ray".into(),
        max_early_data: 2048,
        early_data_header_name: "Sec-WebSocket-Protocol".into(),
        ..WsOptions::default()
    });
    let mut conn = stack.apply(Box::new(client), "example.com").await.unwrap();
    let request = pattern(1500);
    conn.write_all(&request).await.unwrap();
    conn.flush().await.unwrap();
    let mut up = accept.await.unwrap();
    assert_eq!(up.early_data, request);
    assert!(up.head.contains("Host: example.com\r\n"));
    up.io
        .write_all(&ws_server::frame(2, b"pong"))
        .await
        .unwrap();
    let mut got = [0u8; 4];
    conn.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");
}

#[tokio::test]
async fn websocket_early_data_overflow_follows_as_frames() {
    let (client, server) = duplex(1 << 16);
    let accept = tokio::spawn(async move { ws_server::accept(server).await });
    let stack = ws_stack(WsOptions {
        path: "/ray?ed=100".into(),
        ..WsOptions::default()
    });
    let mut conn = stack.apply(Box::new(client), "example.com").await.unwrap();
    let data = pattern(400);
    conn.write_all(&data).await.unwrap();
    conn.flush().await.unwrap();
    let mut up = accept.await.unwrap();
    assert_eq!(up.early_data, &data[..100]);
    assert!(up.head.starts_with("GET /ray HTTP/1.1\r\n"));
    let mut rest = Vec::new();
    while rest.len() < 300 {
        let (op, payload) = ws_server::read_frame(&mut up.io, &mut up.leftover)
            .await
            .unwrap();
        assert_eq!(op, 2);
        rest.extend_from_slice(&payload);
    }
    assert_eq!(rest, &data[100..]);
}

#[tokio::test]
async fn websocket_rejects_a_server_that_does_not_upgrade() {
    let (client, mut server) = duplex(1 << 16);
    tokio::spawn(async move {
        let _ = read_head(&mut server).await;
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let stack = ws_stack(WsOptions::default());
    assert!(stack.apply(Box::new(client), "h").await.is_err());
}

mod h2_servers {

    /// Reads gun messages the way an xray/mihomo server does: five bytes of gRPC
    /// header, tag 0x0A, a varint length, the payload.
    pub struct GunReader<R> {
        pub inner: R,
        buf: Vec<u8>,
    }

    pub fn encode_gun(data: &[u8]) -> Vec<u8> {
        let mut varint = Vec::new();
        let mut n = data.len();
        loop {
            if n < 0x80 {
                varint.push(n as u8);
                break;
            }
            varint.push((n as u8 & 0x7F) | 0x80);
            n >>= 7;
        }
        let mut out = vec![0];
        out.extend_from_slice(&((1 + varint.len() + data.len()) as u32).to_be_bytes());
        out.push(0x0A);
        out.extend_from_slice(&varint);
        out.extend_from_slice(data);
        out
    }

    impl<R> GunReader<R> {
        pub fn new(inner: R) -> Self {
            GunReader {
                inner,
                buf: Vec::new(),
            }
        }
    }

    impl GunReader<h2::RecvStream> {
        async fn fill(&mut self, n: usize) -> bool {
            while self.buf.len() < n {
                match self.inner.data().await {
                    Some(Ok(chunk)) => {
                        self.inner
                            .flow_control()
                            .release_capacity(chunk.len())
                            .unwrap();
                        self.buf.extend_from_slice(&chunk);
                    }
                    _ => return false,
                }
            }
            true
        }

        pub async fn message(&mut self) -> Option<Vec<u8>> {
            if !self.fill(6).await {
                return None;
            }
            assert_eq!(self.buf[0], 0, "compressed message");
            let total = u32::from_be_bytes(self.buf[1..5].try_into().unwrap()) as usize;
            assert_eq!(self.buf[5], 0x0A);
            let mut idx = 6;
            let mut len = 0usize;
            let mut shift = 0;
            loop {
                if !self.fill(idx + 1).await {
                    return None;
                }
                let b = self.buf[idx];
                idx += 1;
                len |= ((b & 0x7F) as usize) << shift;
                shift += 7;
                if b & 0x80 == 0 {
                    break;
                }
            }
            assert_eq!(
                total,
                idx - 5 + len,
                "grpc length must cover the protobuf message"
            );
            if !self.fill(idx + len).await {
                return None;
            }
            let data = self.buf[idx..idx + len].to_vec();
            self.buf.drain(..idx + len);
            Some(data)
        }
    }
}

#[tokio::test]
async fn grpc_follows_the_gun_server_contract_and_shares_a_connection() {
    let connections = Arc::new(Mutex::new(0usize));
    let seen_headers: Arc<Mutex<Vec<SeenHeaders>>> = Arc::default();
    let counter = connections.clone();
    let headers = seen_headers.clone();
    let dial: DialFn = Arc::new(move || {
        let counter = counter.clone();
        let headers = headers.clone();
        Box::pin(async move {
            *lock(&counter) += 1;
            let (client, server) = duplex(1 << 20);
            tokio::spawn(async move {
                let mut conn = h2::server::handshake(server).await.unwrap();
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    let headers = headers.clone();
                    tokio::spawn(async move {
                        let (parts, body) = request.into_parts();
                        let get = |n: &str| {
                            parts
                                .headers
                                .get(n)
                                .map(|v| v.to_str().unwrap().to_string())
                                .unwrap_or_default()
                        };
                        lock(&headers).push((
                            parts.method.to_string(),
                            parts.uri.path().to_string(),
                            get("content-type"),
                            get("user-agent"),
                        ));
                        assert!(get("content-type").starts_with("application/grpc"));
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .header("te", "trailers")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        let mut reader = h2_servers::GunReader::new(body);
                        while let Some(msg) = reader.message().await {
                            send.reserve_capacity(msg.len() + 16);
                            let wire = h2_servers::encode_gun(&msg);
                            send.send_data(Bytes::from(wire), false).unwrap();
                        }
                        send.send_data(Bytes::new(), true).unwrap();
                    });
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    });
    let client = GunClient::new(
        GrpcOptions {
            service_name: "ray".into(),
            authority: "node.example.com:443".into(),
            ..GrpcOptions::default()
        },
        dial,
        Default::default(),
    );
    let stack = TransportStack::new(vec![Layer::Grpc(client)], Default::default());
    assert!(stack.owns_dial());
    let mut first = stack.apply_owned("node.example.com").await.unwrap();
    let mut second = stack.apply_owned("node.example.com").await.unwrap();
    let big = pattern(70_000);
    first.write_all(&big).await.unwrap();
    second.write_all(b"small").await.unwrap();
    let mut got = vec![0u8; big.len()];
    first.read_exact(&mut got).await.unwrap();
    assert_eq!(got, big);
    let mut small = [0u8; 5];
    second.read_exact(&mut small).await.unwrap();
    assert_eq!(&small, b"small");
    first.shutdown().await.unwrap();
    let mut rest = Vec::new();
    first.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    assert_eq!(*lock(&connections), 1);
    let seen = lock(&seen_headers);
    assert_eq!(seen[0].0, "POST");
    assert_eq!(seen[0].1, "/ray/Tun");
    assert_eq!(seen[0].2, "application/grpc");
    assert_eq!(seen[0].3, "grpc-go/1.36.0");
}

#[tokio::test]
async fn grpc_survives_a_malformed_server_message() {
    let dial: DialFn = Arc::new(|| {
        Box::pin(async {
            let (client, server) = duplex(1 << 16);
            tokio::spawn(async move {
                let mut conn = h2::server::handshake(server).await.unwrap();
                if let Some(Ok((_request, mut respond))) = conn.accept().await {
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(
                        Bytes::from_static(&[0, 0, 0, 0, 4, 0x0A, 0xFF, 0xFF, 0xFF]),
                        true,
                    )
                    .unwrap();
                    while conn.accept().await.is_some() {}
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    });
    let client = GunClient::new(
        GrpcOptions {
            authority: "a:1".into(),
            ..GrpcOptions::default()
        },
        dial,
        Default::default(),
    );
    let mut conn = client.dial().await.unwrap();
    let mut buf = [0u8; 8];
    assert!(conn.read(&mut buf).await.is_err());
}

struct XhttpSession {
    next: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    echo: mpsc::UnboundedSender<Vec<u8>>,
    download: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
}

#[derive(Default)]
struct XhttpServer {
    sessions: Mutex<HashMap<String, XhttpSession>>,
    bad_requests: Mutex<Vec<String>>,
    packets: Mutex<usize>,
}

impl XhttpServer {
    fn session<T>(&self, id: &str, f: impl FnOnce(&mut XhttpSession) -> T) -> T {
        let mut sessions = lock(&self.sessions);
        let session = sessions.entry(id.to_string()).or_insert_with(|| {
            let (tx, rx) = mpsc::unbounded_channel();
            XhttpSession {
                next: 0,
                pending: BTreeMap::new(),
                echo: tx,
                download: Some(rx),
            }
        });
        f(session)
    }

    fn reject(&self, why: &str) {
        lock(&self.bad_requests).push(why.to_string());
    }
}

/// `requestHandler.ServeHTTP` in miniature, for path placement and the default padding.
async fn serve_xhttp(io: DuplexStream, server: Arc<XhttpServer>) {
    let mut conn = h2::server::handshake(io).await.unwrap();
    while let Some(Ok((request, mut respond))) = conn.accept().await {
        let server = server.clone();
        tokio::spawn(async move {
            let (parts, mut body) = request.into_parts();
            let path = parts.uri.path().to_string();
            let Some(rest) = path.strip_prefix("/xh/") else {
                server.reject(&format!("path {path}"));
                let _ = respond.send_response(
                    http::Response::builder().status(404).body(()).unwrap(),
                    true,
                );
                return;
            };
            let referer = parts
                .headers
                .get("referer")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            let padding = referer.split("x_padding=").nth(1).unwrap_or_default();
            if !(100..=1000).contains(&padding.len()) || !padding.bytes().all(|b| b == b'X') {
                server.reject("invalid xpadding");
                let _ = respond.send_response(
                    http::Response::builder().status(400).body(()).unwrap(),
                    true,
                );
                return;
            }
            assert_eq!(parts.uri.authority().unwrap().as_str(), "cdn.example.com");
            let mut pieces = rest.split('/').filter(|p| !p.is_empty());
            let session = pieces.next().map(str::to_string);
            let seq = pieces.next().map(str::to_string);
            let ok = || http::Response::builder().status(200).body(()).unwrap();
            match (parts.method.as_str(), session, seq) {
                ("GET", Some(id), None) => {
                    let mut rx = server
                        .session(&id, |s| s.download.take())
                        .expect("one download per session");
                    let response = http::Response::builder()
                        .status(200)
                        .header("x-accel-buffering", "no")
                        .header("cache-control", "no-store")
                        .header("content-type", "text/event-stream")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    while let Some(chunk) = rx.recv().await {
                        send.send_data(Bytes::from(chunk), false).unwrap();
                    }
                }
                ("POST", Some(id), Some(seq)) => {
                    assert_eq!(parts.headers.get("content-type"), None);
                    let seq: u64 = seq.parse().unwrap();
                    let mut payload = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        payload.extend_from_slice(&chunk);
                    }
                    *lock(&server.packets) += 1;
                    server.session(&id, |s| {
                        s.pending.insert(seq, payload);
                        while let Some(next) = s.pending.remove(&s.next) {
                            s.next += 1;
                            let _ = s.echo.send(next);
                        }
                    });
                    let _ = respond.send_response(ok(), true);
                }
                ("POST", Some(id), None) => {
                    assert_eq!(
                        parts
                            .headers
                            .get("content-type")
                            .map(|v| v.to_str().unwrap()),
                        Some("application/grpc")
                    );
                    let echo = server.session(&id, |s| s.echo.clone());
                    let mut send = respond.send_response(ok(), false).unwrap();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        let _ = echo.send(chunk.to_vec());
                    }
                    let _ = send.send_data(Bytes::new(), true);
                }
                ("POST", None, None) => {
                    let mut send = respond.send_response(ok(), false).unwrap();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        send.send_data(chunk, false).unwrap();
                    }
                    send.send_data(Bytes::new(), true).unwrap();
                }
                other => {
                    server.reject(&format!("unrouted {other:?}"));
                    let _ = respond.send_response(
                        http::Response::builder().status(404).body(()).unwrap(),
                        true,
                    );
                }
            }
        });
    }
}

fn xhttp_dial(server: Arc<XhttpServer>) -> DialFn {
    Arc::new(move || {
        let server = server.clone();
        Box::pin(async move {
            let (client, io) = duplex(1 << 20);
            tokio::spawn(serve_xhttp(io, server));
            Ok::<BoxStream, io::Error>(Box::new(client))
        })
    })
}

fn xhttp_opts(mode: &str) -> XhttpOptions {
    XhttpOptions {
        host: "cdn.example.com".into(),
        path: "/xh".into(),
        mode: mode.into(),
        sc_min_posts_interval_ms: "5".into(),
        ..XhttpOptions::default()
    }
}

async fn xhttp_roundtrip(mode: &str) -> Arc<XhttpServer> {
    let server = Arc::new(XhttpServer::default());
    let client = XhttpClient::new(
        xhttp_opts(mode),
        xhttp_dial(server.clone()),
        None,
        Default::default(),
    )
    .unwrap();
    let stack = TransportStack::new(vec![Layer::Xhttp(client)], Default::default());
    let conn = stack.apply_owned("cdn.example.com").await.unwrap();
    let payload = pattern(120_000);
    let (mut rd, mut wr) = tokio::io::split(conn);
    let send = payload.clone();
    let writer = tokio::spawn(async move {
        for chunk in send.chunks(7000) {
            wr.write_all(chunk).await.unwrap();
        }
        wr
    });
    let mut got = vec![0u8; payload.len()];
    rd.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);
    drop(writer.await.unwrap());
    server
}

#[tokio::test]
async fn xhttp_packet_up_orders_posts_by_sequence() {
    let server = xhttp_roundtrip("packet-up").await;
    assert!(
        lock(&server.bad_requests).is_empty(),
        "{:?}",
        lock(&server.bad_requests)
    );
    assert!(*lock(&server.packets) >= 1);
}

#[tokio::test]
async fn xhttp_stream_up_streams_the_upload() {
    let server = xhttp_roundtrip("stream-up").await;
    assert!(
        lock(&server.bad_requests).is_empty(),
        "{:?}",
        lock(&server.bad_requests)
    );
    assert_eq!(*lock(&server.packets), 0);
}

#[tokio::test]
async fn xhttp_stream_one_uses_a_single_request() {
    let server = Arc::new(XhttpServer::default());
    let mut opts = xhttp_opts("stream-one");
    opts.path = "/xh/".into();
    let client =
        XhttpClient::new(opts, xhttp_dial(server.clone()), None, Default::default()).unwrap();
    let mut conn = client.dial().await.unwrap();
    conn.write_all(b"hello stream-one").await.unwrap();
    let mut got = [0u8; 16];
    conn.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello stream-one");
    conn.shutdown().await.unwrap();
    let mut rest = Vec::new();
    conn.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    assert!(
        lock(&server.bad_requests).is_empty(),
        "{:?}",
        lock(&server.bad_requests)
    );
}

#[tokio::test]
async fn xhttp_rejects_unknown_modes_and_bad_ranges() {
    let server = Arc::new(XhttpServer::default());
    assert!(
        XhttpClient::new(
            xhttp_opts("mekya"),
            xhttp_dial(server.clone()),
            None,
            Default::default()
        )
        .is_err()
    );
    let mut opts = xhttp_opts("packet-up");
    opts.sc_max_each_post_bytes = "0".into();
    assert!(XhttpClient::new(opts, xhttp_dial(server), None, Default::default()).is_err());
}

#[tokio::test]
async fn xhttp_server_errors_reach_the_reader() {
    let server = Arc::new(XhttpServer::default());
    let mut opts = xhttp_opts("packet-up");
    opts.path = "/other".into();
    let client = XhttpClient::new(opts, xhttp_dial(server), None, Default::default()).unwrap();
    let mut conn = client.dial().await.unwrap();
    let mut buf = [0u8; 1];
    let err = conn.read(&mut buf).await.unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
}

#[path = "interop/h3.rs"]
mod h3_tests;

#[path = "interop/h3_lifecycle.rs"]
mod h3_lifecycle;
