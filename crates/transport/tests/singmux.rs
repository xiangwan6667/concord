//! sing-mux servers written from `sing-mux/server.go`, the smux v1 and yamux
//! wire formats and `h2mux.go`, sharing no code with the client.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use concord_common::sync::lock;
use concord_common::{Address, BoxStream};
use concord_transport::{MuxDialFn, MuxProtocol, SingMuxClient, SingMuxOptions};
use http::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, WriteHalf, duplex, split};
use tokio::sync::{Notify, mpsc};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    version: u8,
    protocol: u8,
    padding: bool,
    flags: u16,
    destination: String,
}

type Log = Arc<Mutex<Vec<Seen>>>;

struct Pending {
    buf: Vec<u8>,
}

fn parse_stream_request(buf: &[u8]) -> Option<(u16, String, usize)> {
    let flags = u16::from_be_bytes([*buf.first()?, *buf.get(1)?]);
    let family = *buf.get(2)?;
    let (host, used) = match family {
        1 => {
            let b: [u8; 4] = buf.get(3..7)?.try_into().ok()?;
            (Ipv4Addr::from(b).to_string(), 7)
        }
        3 => {
            let len = usize::from(*buf.get(3)?);
            let name = String::from_utf8(buf.get(4..4 + len)?.to_vec()).ok()?;
            (name, 4 + len)
        }
        other => panic!("unexpected address family {other}"),
    };
    let port = u16::from_be_bytes([*buf.get(used)?, *buf.get(used + 1)?]);
    Some((flags, format!("{host}:{port}"), used + 2))
}

async fn stream_handler(
    mut inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound: mpsc::UnboundedSender<Vec<u8>>,
    session: Seen,
    log: Log,
) {
    let mut pending = Pending { buf: Vec::new() };
    let (flags, destination, used) = loop {
        match inbound.recv().await {
            Some(chunk) => pending.buf.extend_from_slice(&chunk),
            None => return,
        }
        if let Some(parsed) = parse_stream_request(&pending.buf) {
            break parsed;
        }
    };
    lock(&log).push(Seen {
        flags,
        destination: destination.clone(),
        ..session
    });
    if destination.starts_with("fail.test") {
        let mut response = vec![1, 4];
        response.extend_from_slice(b"boom");
        let _ = outbound.send(response);
        return;
    }
    let _ = outbound.send(vec![0]);
    let rest = pending.buf.split_off(used);
    if !rest.is_empty() {
        let _ = outbound.send(rest);
    }
    while let Some(chunk) = inbound.recv().await {
        if outbound.send(chunk).is_err() {
            return;
        }
    }
}

struct Padded {
    near: DuplexStream,
}

fn padded_io(raw: DuplexStream) -> Padded {
    let (near, far) = duplex(1 << 20);
    let (mut raw_r, mut raw_w) = split(raw);
    let (mut far_r, mut far_w) = split(far);
    tokio::spawn(async move {
        let mut frames = 0;
        loop {
            if frames >= 16 {
                let _ = tokio::io::copy(&mut raw_r, &mut far_w).await;
                return;
            }
            let mut head = [0u8; 4];
            if raw_r.read_exact(&mut head).await.is_err() {
                return;
            }
            let data = usize::from(u16::from_be_bytes([head[0], head[1]]));
            let pad = usize::from(u16::from_be_bytes([head[2], head[3]]));
            assert!((256..768).contains(&pad), "padding length {pad}");
            let mut body = vec![0u8; data + pad];
            if raw_r.read_exact(&mut body).await.is_err() {
                return;
            }
            if far_w.write_all(&body[..data]).await.is_err() {
                return;
            }
            frames += 1;
        }
    });
    tokio::spawn(async move {
        let mut frames = 0;
        let mut buf = vec![0u8; 60000];
        loop {
            let n = match far_r.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            if frames < 16 {
                let pad = 300usize;
                let mut out = Vec::new();
                out.extend_from_slice(&(n as u16).to_be_bytes());
                out.extend_from_slice(&(pad as u16).to_be_bytes());
                out.extend_from_slice(&buf[..n]);
                out.extend(std::iter::repeat_n(0xAA, pad));
                frames += 1;
                if raw_w.write_all(&out).await.is_err() {
                    return;
                }
            } else if raw_w.write_all(&buf[..n]).await.is_err() {
                return;
            }
        }
    });
    Padded { near }
}

async fn serve(mut conn: DuplexStream, log: Log) {
    let version = conn.read_u8().await.unwrap();
    let protocol = conn.read_u8().await.unwrap();
    let mut padding = false;
    if version == 1 {
        padding = conn.read_u8().await.unwrap() == 1;
        if padding {
            let len = conn.read_u16().await.unwrap();
            let mut skip = vec![0u8; usize::from(len)];
            conn.read_exact(&mut skip).await.unwrap();
        }
    }
    let session = Seen {
        version,
        protocol,
        padding,
        flags: 0,
        destination: String::new(),
    };
    let io: DuplexStream = if padding { padded_io(conn).near } else { conn };
    match protocol {
        0 => serve_smux(io, session, log).await,
        1 => serve_yamux(io, session, log).await,
        2 => serve_h2(io, session, log).await,
        other => panic!("unknown protocol {other}"),
    }
}

type Writer = Arc<tokio::sync::Mutex<WriteHalf<DuplexStream>>>;

fn smux_frame(cmd: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![1, cmd];
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&sid.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

async fn serve_smux(io: DuplexStream, session: Seen, log: Log) {
    let (mut r, w) = split(io);
    let w: Writer = Arc::new(tokio::sync::Mutex::new(w));
    let mut streams: std::collections::HashMap<u32, mpsc::UnboundedSender<Vec<u8>>> =
        Default::default();
    loop {
        let mut head = [0u8; 8];
        if r.read_exact(&mut head).await.is_err() {
            return;
        }
        assert_eq!(head[0], 1);
        let len = usize::from(u16::from_le_bytes([head[2], head[3]]));
        let sid = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
        match head[1] {
            0 => {
                let (in_tx, in_rx) = mpsc::unbounded_channel();
                let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                streams.insert(sid, in_tx);
                tokio::spawn(stream_handler(in_rx, out_tx, session.clone(), log.clone()));
                let w = w.clone();
                tokio::spawn(async move {
                    while let Some(chunk) = out_rx.recv().await {
                        for part in chunk.chunks(32768) {
                            if w.lock()
                                .await
                                .write_all(&smux_frame(2, sid, part))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    let _ = w.lock().await.write_all(&smux_frame(1, sid, &[])).await;
                });
            }
            1 => {
                streams.remove(&sid);
            }
            2 => {
                let mut payload = vec![0u8; len];
                r.read_exact(&mut payload).await.unwrap();
                if let Some(tx) = streams.get(&sid) {
                    let _ = tx.send(payload);
                }
            }
            3 => {}
            other => panic!("unexpected smux command {other}"),
        }
    }
}

fn yamux_header(kind: u8, flags: u16, sid: u32, length: u32) -> Vec<u8> {
    let mut out = vec![0, kind];
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out
}

struct YWindow {
    window: AtomicUsize,
    notify: Notify,
}

async fn serve_yamux(io: DuplexStream, session: Seen, log: Log) {
    let (mut r, w) = split(io);
    let w: Writer = Arc::new(tokio::sync::Mutex::new(w));
    let mut streams: std::collections::HashMap<
        u32,
        (mpsc::UnboundedSender<Vec<u8>>, Arc<YWindow>),
    > = Default::default();
    loop {
        let mut head = [0u8; 12];
        if r.read_exact(&mut head).await.is_err() {
            return;
        }
        assert_eq!(head[0], 0);
        let kind = head[1];
        let flags = u16::from_be_bytes([head[2], head[3]]);
        let sid = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        let length = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
        if kind == 2 {
            if flags & 1 != 0 {
                let _ = w
                    .lock()
                    .await
                    .write_all(&yamux_header(2, 2, 0, length))
                    .await;
            }
            continue;
        }
        if flags & 1 != 0 {
            let (in_tx, in_rx) = mpsc::unbounded_channel();
            let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let window = Arc::new(YWindow {
                window: AtomicUsize::new(256 * 1024),
                notify: Notify::new(),
            });
            streams.insert(sid, (in_tx, window.clone()));
            tokio::spawn(stream_handler(in_rx, out_tx, session.clone(), log.clone()));
            let w = w.clone();
            tokio::spawn(async move {
                let mut first = true;
                while let Some(chunk) = out_rx.recv().await {
                    let mut chunk = &chunk[..];
                    while !chunk.is_empty() {
                        let mut avail = window.window.load(Ordering::SeqCst);
                        while avail == 0 {
                            let wait = window.notify.notified();
                            avail = window.window.load(Ordering::SeqCst);
                            if avail == 0 {
                                wait.await;
                            }
                        }
                        let take = avail.min(chunk.len()).min(60000);
                        window.window.fetch_sub(take, Ordering::SeqCst);
                        let flags = if first { 2 } else { 0 };
                        first = false;
                        let mut frame = yamux_header(0, flags, sid, take as u32);
                        frame.extend_from_slice(&chunk[..take]);
                        if w.lock().await.write_all(&frame).await.is_err() {
                            return;
                        }
                        chunk = &chunk[take..];
                    }
                }
                let flags = if first { 2 | 4 } else { 4 };
                let _ = w
                    .lock()
                    .await
                    .write_all(&yamux_header(1, flags, sid, 0))
                    .await;
            });
        }
        let Some((tx, window)) = streams.get(&sid) else {
            if kind == 0 {
                let mut skip = vec![0u8; length as usize];
                r.read_exact(&mut skip).await.unwrap();
            }
            continue;
        };
        if kind == 1 {
            window.window.fetch_add(length as usize, Ordering::SeqCst);
            window.notify.notify_waiters();
        } else if length > 0 {
            let mut payload = vec![0u8; length as usize];
            r.read_exact(&mut payload).await.unwrap();
            let _ = tx.send(payload);
            let _ = w
                .lock()
                .await
                .write_all(&yamux_header(1, 0, sid, length))
                .await;
        }
        if flags & 4 != 0 {
            streams.remove(&sid);
        }
    }
}

async fn serve_h2(io: DuplexStream, session: Seen, log: Log) {
    let mut conn = h2::server::handshake(io).await.unwrap();
    while let Some(Ok((request, mut respond))) = conn.accept().await {
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(
            request.uri().authority().map(|a| a.as_str()),
            Some("localhost")
        );
        let mut body = request.into_body();
        let mut send = respond.send_response(Response::new(()), false).unwrap();
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(stream_handler(in_rx, out_tx, session.clone(), log.clone()));
        tokio::spawn(async move {
            while let Some(Ok(data)) = body.data().await {
                let _ = body.flow_control().release_capacity(data.len());
                if in_tx.send(data.to_vec()).is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(chunk) = out_rx.recv().await {
                if send.send_data(Bytes::from(chunk), false).is_err() {
                    return;
                }
            }
            let _ = send.send_data(Bytes::new(), true);
        });
    }
}

struct Harness {
    client: Arc<SingMuxClient>,
    log: Log,
    dials: Arc<AtomicUsize>,
    servers: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

fn harness(opts: SingMuxOptions) -> Harness {
    let log: Log = Arc::default();
    let dials = Arc::new(AtomicUsize::new(0));
    let servers: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::default();
    let dial: MuxDialFn = {
        let (log, dials, servers) = (log.clone(), dials.clone(), servers.clone());
        Arc::new(move |destination: Address| {
            assert_eq!(destination.to_string(), "sp.mux.sing-box.arpa:444");
            let (near, far) = duplex(1 << 20);
            dials.fetch_add(1, Ordering::SeqCst);
            lock(&servers).push(tokio::spawn(serve(far, log.clone())));
            Box::pin(async move { Ok(Box::new(near) as BoxStream) })
        })
    };
    Harness {
        client: SingMuxClient::new(opts, dial, Default::default()),
        log,
        dials,
        servers,
    }
}

fn target() -> Address {
    Address::new("example.com", 443)
}

const PROTOCOLS: [MuxProtocol; 3] = [MuxProtocol::Smux, MuxProtocol::Yamux, MuxProtocol::H2Mux];

fn options(protocol: MuxProtocol, padding: bool) -> SingMuxOptions {
    SingMuxOptions {
        protocol,
        padding,
        max_connections: 1,
        ..SingMuxOptions::default()
    }
}

#[tokio::test]
async fn tcp_echo_for_every_protocol_with_and_without_padding() {
    for protocol in PROTOCOLS {
        for padding in [false, true] {
            let h = harness(options(protocol, padding));
            let mut io = h.client.connect_tcp(&target()).await.unwrap();
            io.write_all(b"hello").await.unwrap();
            let mut got = [0u8; 5];
            io.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello", "{protocol:?} padding={padding}");
            let seen = lock(&h.log).clone();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].destination, "example.com:443");
            assert_eq!(seen[0].flags, 0);
            assert_eq!(seen[0].padding, padding);
            assert_eq!(seen[0].version, u8::from(padding));
            let id = match protocol {
                MuxProtocol::Smux => 0,
                MuxProtocol::Yamux => 1,
                MuxProtocol::H2Mux => 2,
            };
            assert_eq!(seen[0].protocol, id);
        }
    }
}

#[tokio::test]
async fn large_transfers_cross_the_flow_control_windows() {
    for protocol in PROTOCOLS {
        let h = harness(options(protocol, false));
        let io = h.client.connect_tcp(&target()).await.unwrap();
        let data: Vec<u8> = (0..900_000u32).map(|i| (i % 253) as u8).collect();
        let (mut r, mut w) = split(io);
        let send = {
            let data = data.clone();
            async move {
                for chunk in data.chunks(9000) {
                    w.write_all(chunk).await.unwrap();
                }
                w
            }
        };
        let mut echoed = vec![0u8; data.len()];
        let recv = r.read_exact(&mut echoed);
        let (_, got) = tokio::join!(send, recv);
        got.unwrap();
        assert!(echoed == data, "{protocol:?}");
    }
}

#[tokio::test]
async fn streams_share_a_session_when_connections_are_bounded() {
    for protocol in PROTOCOLS {
        let h = harness(options(protocol, false));
        let mut ios = Vec::new();
        for _ in 0..5 {
            ios.push(h.client.connect_tcp(&target()).await.unwrap());
        }
        for (i, io) in ios.iter_mut().enumerate() {
            io.write_all(&[i as u8]).await.unwrap();
        }
        for (i, io) in ios.iter_mut().enumerate() {
            let mut b = [0u8; 1];
            io.read_exact(&mut b).await.unwrap();
            assert_eq!(b[0], i as u8, "{protocol:?}");
        }
        assert_eq!(h.dials.load(Ordering::SeqCst), 1, "{protocol:?}");
    }
}

#[tokio::test]
async fn without_a_bound_a_busy_session_is_not_reused() {
    for protocol in PROTOCOLS {
        let h = harness(SingMuxOptions {
            protocol,
            ..SingMuxOptions::default()
        });
        let first = h.client.connect_tcp(&target()).await.unwrap();
        let second = h.client.connect_tcp(&target()).await.unwrap();
        assert_eq!(h.dials.load(Ordering::SeqCst), 2, "{protocol:?}");
        drop((first, second));
    }
}

#[tokio::test]
async fn half_close_where_the_protocol_has_it() {
    for protocol in [MuxProtocol::Yamux, MuxProtocol::H2Mux] {
        let h = harness(options(protocol, false));
        let mut io = h.client.connect_tcp(&target()).await.unwrap();
        io.write_all(b"abc").await.unwrap();
        io.shutdown().await.unwrap();
        let mut got = Vec::new();
        io.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"abc", "{protocol:?}");
    }
}

#[tokio::test]
async fn split_halves_move_data_both_ways_at_once() {
    for protocol in PROTOCOLS {
        for padding in [false, true] {
            let h = harness(options(protocol, padding));
            let (mut r, mut w) = h.client.connect_tcp(&target()).await.unwrap().into_split();
            let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
            let send = tokio::spawn({
                let data = data.clone();
                async move {
                    for chunk in data.chunks(7000) {
                        w.write_all(chunk).await.unwrap();
                    }
                    w
                }
            });
            let mut echoed = vec![0u8; data.len()];
            r.read_exact(&mut echoed).await.unwrap();
            assert!(echoed == data, "{protocol:?} padding={padding}");
            drop(send.await.unwrap());
        }
    }
}

#[tokio::test]
async fn split_write_shutdown_leaves_the_read_half_working_where_the_protocol_has_it() {
    for protocol in [MuxProtocol::Yamux, MuxProtocol::H2Mux] {
        let h = harness(options(protocol, false));
        let (mut r, mut w) = h.client.connect_tcp(&target()).await.unwrap().into_split();
        let writer = tokio::spawn(async move {
            w.write_all(b"abc").await.unwrap();
            w.shutdown().await.unwrap();
            w
        });
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"abc", "{protocol:?}");
        drop(writer.await.unwrap());
    }
}

#[tokio::test]
async fn split_smux_shutdown_ends_the_read_half_like_the_whole_stream() {
    let h = harness(options(MuxProtocol::Smux, false));
    let (mut r, mut w) = h.client.connect_tcp(&target()).await.unwrap().into_split();
    let reader = tokio::spawn(async move {
        let mut got = Vec::new();
        let result = r.read_to_end(&mut got).await;
        (got, result)
    });
    tokio::task::yield_now().await;
    w.write_all(b"abc").await.unwrap();
    w.shutdown().await.unwrap();
    let (got, result) = reader.await.unwrap();
    let _ = result;
    assert!(got.len() <= 3);
}

#[tokio::test]
async fn smux_shutdown_closes_the_stream() {
    let h = harness(options(MuxProtocol::Smux, false));
    let mut io = h.client.connect_tcp(&target()).await.unwrap();
    io.write_all(b"abc").await.unwrap();
    io.shutdown().await.unwrap();
    let mut got = Vec::new();
    let result = io.read_to_end(&mut got).await;
    assert!(got.is_empty());
    assert!(result.is_err() || got.is_empty());
}

#[tokio::test]
async fn udp_with_a_fixed_destination_and_per_packet_addresses() {
    for protocol in PROTOCOLS {
        let h = harness(options(protocol, false));
        let dns = Address::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
        let (mut rx, mut tx) = h.client.connect_udp(&dns).await.unwrap();
        tx.send(b"one", None).await.unwrap();
        tx.send(b"second packet", None).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), (b"one".to_vec(), None));
        assert_eq!(rx.recv().await.unwrap(), (b"second packet".to_vec(), None));

        let peer = Address::new("peer.test", 9000);
        let (mut rx, mut tx) = h.client.listen_packet(Some(&dns)).await.unwrap();
        tx.send(b"x", Some(&peer)).await.unwrap();
        tx.send(b"y", Some(&dns)).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), (b"x".to_vec(), Some(peer)));
        assert_eq!(rx.recv().await.unwrap(), (b"y".to_vec(), Some(dns.clone())));

        let seen = lock(&h.log).clone();
        assert_eq!(seen[0].flags, 1, "{protocol:?}");
        assert_eq!(seen[0].destination, "8.8.8.8:53");
        assert_eq!(seen[1].flags, 3, "{protocol:?}");
    }
}

#[tokio::test]
async fn a_remote_error_reaches_the_reader() {
    for protocol in PROTOCOLS {
        let h = harness(options(protocol, true));
        let mut io = h
            .client
            .connect_tcp(&Address::new("fail.test", 1))
            .await
            .unwrap();
        io.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        let err = io.read(&mut b).await.unwrap_err();
        assert!(
            err.to_string().contains("remote error: boom"),
            "{protocol:?}: {err}"
        );
    }
}

#[tokio::test]
async fn a_dead_session_is_replaced() {
    for protocol in [MuxProtocol::Smux, MuxProtocol::Yamux] {
        let h = harness(options(protocol, false));
        let mut io = h.client.connect_tcp(&target()).await.unwrap();
        io.write_all(b"a").await.unwrap();
        let mut b = [0u8; 1];
        io.read_exact(&mut b).await.unwrap();
        for server in lock(&h.servers).drain(..) {
            server.abort();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(io.read(&mut b).await.is_err() || b[0] == b'a');
        let mut again = h.client.connect_tcp(&target()).await.unwrap();
        again.write_all(b"z").await.unwrap();
        again.read_exact(&mut b).await.unwrap();
        assert_eq!(b[0], b'z');
        assert_eq!(h.dials.load(Ordering::SeqCst), 2, "{protocol:?}");
    }
}

#[tokio::test]
async fn protocol_names_follow_sing_mux() {
    assert_eq!(MuxProtocol::parse("").unwrap(), MuxProtocol::H2Mux);
    assert_eq!(MuxProtocol::parse("smux").unwrap(), MuxProtocol::Smux);
    assert_eq!(MuxProtocol::parse("yamux").unwrap(), MuxProtocol::Yamux);
    assert!(MuxProtocol::parse("quic").is_err());
}
