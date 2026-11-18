#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "the tests run a loopback server on plain sockets"
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use concord_common::sync::lock;
use concord_common::{Address, DialCx, Initiator, Outbound, PacketBuf, recv_packet, send_packet};
use concord_config::proxy::ProxyKind;
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::{TlsOptions, TrustStore};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::wire::{control_entry, datagram, read_control_entry, split_datagram};
use super::{Settings, ShadowQuic, Shared, controller};
use crate::addr_codec::SOCKS;
use crate::ctx::BuildCtx;
use crate::node::Egress;
use crate::quic::{BbrProfile, Crypto, DatagramHub, ObfsSpec, QuicLink, SwitchFactory};
use crate::testing::{HeldLookup, quic_server, test_env};

type Routes = Arc<Mutex<HashMap<u16, (Arc<UdpSocket>, SocketAddr)>>>;

#[derive(Default)]
struct Seen {
    accepted: AtomicUsize,
    brutal_rx: Mutex<Option<u64>>,
    control_entries: Mutex<Vec<(Address, u16)>>,
}

#[derive(Clone, Copy, Default)]
struct Quirks {
    reply_before_introduction: bool,
}

async fn serve(endpoint: quinn::Endpoint, seen: Arc<Seen>, quirks: Quirks) {
    while let Some(incoming) = endpoint.accept().await {
        seen.accepted.fetch_add(1, Ordering::SeqCst);
        let (seen, routes) = (seen.clone(), Routes::default());
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else {
                return;
            };
            tokio::spawn(relay_datagrams(conn.clone(), routes.clone()));
            tokio::spawn(relay_streams(conn.clone(), routes.clone()));
            while let Ok((send, recv)) = conn.accept_bi().await {
                tokio::spawn(command(
                    conn.clone(),
                    send,
                    recv,
                    routes.clone(),
                    seen.clone(),
                    quirks,
                ));
            }
        });
    }
}

async fn relay_datagrams(conn: quinn::Connection, routes: Routes) {
    while let Ok(message) = conn.read_datagram().await {
        let Some((id, payload)) = split_datagram(&message) else {
            continue;
        };
        for _ in 0..40 {
            let route = lock(&routes).get(&id).cloned();
            if let Some((socket, to)) = route {
                socket.send_to(payload, to).await.unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

async fn relay_streams(conn: quinn::Connection, routes: Routes) {
    while let Ok(mut stream) = conn.accept_uni().await {
        let routes = routes.clone();
        tokio::spawn(async move {
            let id = stream.read_u16().await.unwrap();
            loop {
                let Ok(len) = stream.read_u16().await else {
                    return;
                };
                let mut payload = vec![0u8; usize::from(len)];
                stream.read_exact(&mut payload).await.unwrap();
                let route = lock(&routes).get(&id).cloned();
                if let Some((socket, to)) = route {
                    socket.send_to(&payload, to).await.unwrap();
                }
            }
        });
    }
}

async fn command(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    routes: Routes,
    seen: Arc<Seen>,
    quirks: Quirks,
) {
    match recv.read_u8().await.unwrap() {
        0x01 => {
            let target = SOCKS.read(&mut recv).await.unwrap();
            let socket = tokio::net::TcpStream::connect(target.to_string())
                .await
                .unwrap();
            let (mut read, mut write) = socket.into_split();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(Some(n)) = recv.read(&mut buf).await {
                    if write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = read.read(&mut buf).await {
                if n == 0 || send.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = send.finish();
        }
        kind @ (0x03 | 0x04) => {
            associate(conn, send, recv, routes, seen, quirks, kind == 0x04).await
        }
        0xff => {
            let mut opcode = [0u8; 8];
            recv.read_exact(&mut opcode).await.unwrap();
            assert_eq!(u64::from_be_bytes(opcode), 0x6d69_686f_6d6f_0001);
            let mut frame = [0u8; 12];
            recv.read_exact(&mut frame).await.unwrap();
            *lock(&seen.brutal_rx) = Some(u64::from_be_bytes(frame[4..12].try_into().unwrap()));
            let mut reply = vec![1u8, 1, 0, 8];
            reply.extend_from_slice(&0u64.to_be_bytes());
            send.write_all(&reply).await.unwrap();
            let _ = send.finish();
        }
        other => panic!("unexpected command {other}"),
    }
}

async fn associate(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    routes: Routes,
    seen: Arc<Seen>,
    quirks: Quirks,
    over_stream: bool,
) {
    assert_eq!(
        SOCKS.read(&mut recv).await.unwrap(),
        Address::new("0.0.0.0", 0)
    );
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let announced = Arc::new(Mutex::new(HashMap::<SocketAddr, u16>::new()));
    let replies = {
        let (socket, conn, announced) = (socket.clone(), conn.clone(), announced.clone());
        let (announce_tx, mut announce_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(entry) = announce_rx.recv().await {
                if send.write_all(&entry).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut streams: HashMap<u16, quinn::SendStream> = HashMap::new();
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let fresh = !lock(&announced).contains_key(&from);
                let id = {
                    let mut announced = lock(&announced);
                    let next = 900 + announced.len() as u16;
                    *announced.entry(from).or_insert(next)
                };
                let entry = control_entry(&Address::Socket(from), id).unwrap();
                if fresh && !quirks.reply_before_introduction {
                    announce_tx.send(entry.clone()).unwrap();
                }
                if over_stream {
                    if let std::collections::hash_map::Entry::Vacant(slot) = streams.entry(id) {
                        let mut stream = conn.open_uni().await.unwrap();
                        stream.write_all(&id.to_be_bytes()).await.unwrap();
                        slot.insert(stream);
                    }
                    let stream = streams.get_mut(&id).unwrap();
                    stream.write_all(&(n as u16).to_be_bytes()).await.unwrap();
                    stream.write_all(&buf[..n]).await.unwrap();
                } else {
                    conn.send_datagram(Bytes::from(datagram(id, &buf[..n])))
                        .unwrap();
                }
                if fresh && quirks.reply_before_introduction {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    announce_tx.send(entry).unwrap();
                }
            }
        })
    };
    while let Ok((addr, id)) = read_control_entry(&mut recv).await {
        lock(&seen.control_entries).push((addr.clone(), id));
        let Address::Socket(to) = addr else {
            continue;
        };
        lock(&routes).insert(id, (socket.clone(), to));
    }
    replies.abort();
}

fn client_link(port: u16) -> QuicLink {
    let options = TlsOptions {
        server_name: Some("localhost".to_string()),
        alpn: vec!["h3".to_string()],
        skip_cert_verify: true,
        ..TlsOptions::default()
    };
    let tls = concord_tls::quic_client_config(&options, TrustStore::new(b"", Vec::new()), &["h3"])
        .unwrap();
    let controllers = SwitchFactory::new(controller("", 32, BbrProfile::Standard));
    let mut link = QuicLink {
        tasks: Default::default(),
        egress: Egress::new("sq", &Default::default()),
        server: Address::new("127.0.0.1", port),
        server_name: Some("localhost".to_string()),
        crypto: Crypto::Rustls(tls),
        transport: Default::default(),
        obfs: ObfsSpec::None,
        hop: None,
        datagram_frame: None,
    };
    link.transport = super::transport(&Default::default(), controllers);
    link
}

fn outbound(port: u16, settings: Settings) -> ShadowQuic {
    ShadowQuic {
        info: crate::node::info(
            "sq",
            concord_common::OutboundKind::ShadowQuic,
            "127.0.0.1",
            port,
            true,
        ),
        link: client_link(port),
        settings,
        controllers: SwitchFactory::new(controller("", 32, BbrProfile::Standard)),
        current: crate::session_slot::SessionSlot::default(),
        connecting: tokio::sync::Mutex::new(()),
    }
}

fn plain() -> Settings {
    Settings {
        over_stream: false,
        up: 0,
        down: 0,
        cwnd: 32,
        profile: BbrProfile::Standard,
    }
}

async fn running(quirks: Quirks) -> (u16, Arc<Seen>, quinn::Endpoint) {
    let (endpoint, port) = quic_server(b"h3", |socket| socket);
    let seen = Arc::new(Seen::default());
    tokio::spawn(serve(endpoint.clone(), seen.clone(), quirks));
    (port, seen, endpoint)
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

fn address(addr: SocketAddr) -> Address {
    Address::Socket(addr)
}

async fn exchange(session: &dyn concord_common::PacketSession, to: SocketAddr, size: usize) {
    let data: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
    let mut packet = PacketBuf::with_headroom(session.headroom());
    packet.extend_from_slice(&data);
    send_packet(session, &mut packet, &address(to))
        .await
        .unwrap();
    let (got, from) = tokio::time::timeout(Duration::from_secs(10), recv_packet(session))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.as_slice(), data);
    assert_eq!(from, address(to));
}

#[tokio::test]
async fn a_connect_stream_carries_bytes_to_the_target() {
    let (port, _seen, _server) = running(Quirks::default()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let mut stream = outbound(port, plain())
        .connect(&cx, &address(target))
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
}

#[tokio::test]
async fn a_connection_made_across_a_reset_is_not_kept() {
    let (port, seen, _server) = running(Quirks::default()).await;
    let target = concord_test_support::tcp_echo().await;
    let mut node = outbound(port, plain());
    node.link.server = Address::new("localhost", port);
    let node = Arc::new(node);
    let held = HeldLookup::new();
    let straddling = {
        let (node, env) = (node.clone(), held.env());
        tokio::spawn(async move {
            let cx = DialCx::new(&env, Initiator::Direct, None);
            node.connect(&cx, &address(target)).await.map(drop)
        })
    };
    held.entered().await;
    node.reset_sessions();
    held.release();
    let outcome = crate::testing::settled(straddling).await;
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    node.connect(&cx, &address(target)).await.unwrap();
    assert_eq!(
        seen.accepted.load(Ordering::SeqCst),
        2,
        "the next request went over the connection made before the reset"
    );
    assert!(outcome.is_err());
}

async fn udp_session(over_stream: bool, quirks: Quirks) -> Arc<Seen> {
    let (port, seen, _server) = running(quirks).await;
    let (first, second) = (udp_echo().await, udp_echo().await);
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let node = outbound(
        port,
        Settings {
            over_stream,
            ..plain()
        },
    );
    let session = node.associate(&cx, &address(first)).await.unwrap();
    for size in [10usize, 1000] {
        exchange(&*session, first, size).await;
        exchange(&*session, second, size).await;
    }
    drop(session);
    seen
}

#[tokio::test]
async fn datagram_mode_keeps_one_id_per_destination() {
    let seen = udp_session(false, Quirks::default()).await;
    assert_eq!(lock(&seen.control_entries).len(), 2);
}

#[tokio::test]
async fn stream_mode_carries_packets_both_ways() {
    udp_session(true, Quirks::default()).await;
}

#[tokio::test]
async fn peer_disconnect_wakes_udp_receivers() {
    for over_stream in [false, true] {
        let (port, _seen, server) = running(Quirks::default()).await;
        let target = udp_echo().await;
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let node = outbound(
            port,
            Settings {
                over_stream,
                ..plain()
            },
        );
        let active = node.associate(&cx, &address(target)).await.unwrap();
        let idle = node.associate(&cx, &address(target)).await.unwrap();
        exchange(&*active, target, 10).await;

        let receive = async { tokio::join!(recv_packet(&*active), recv_packet(&*idle)) };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(biased; receive, async {
                server.close(0u32.into(), b"peer disconnected");
            })
        })
        .await
        .expect("UDP receivers stayed pending after the QUIC peer closed");
        for result in [result.0, result.1] {
            assert_eq!(result.err().unwrap().kind(), std::io::ErrorKind::BrokenPipe);
        }
    }
}

#[tokio::test]
async fn control_eof_wakes_udp_receiver_with_an_open_uni_stream() {
    let (server, port) = quic_server(b"h3", |socket| socket);
    let node = outbound(
        port,
        Settings {
            over_stream: true,
            ..plain()
        },
    );
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let target = Address::new("127.0.0.1", 53);
    let (session, (peer, mut control, mut request)) =
        tokio::join!(node.associate(&cx, &target), async {
            let peer = server.accept().await.unwrap().await.unwrap();
            let (control, mut request) = peer.accept_bi().await.unwrap();
            assert_eq!(request.read_u8().await.unwrap(), super::ASSOCIATE_STREAM);
            assert_eq!(
                SOCKS.read(&mut request).await.unwrap(),
                super::unspecified()
            );
            (peer, control, request)
        });
    let session = session.unwrap();
    let id = 42;
    control
        .write_all(&control_entry(&target, id).unwrap())
        .await
        .unwrap();
    let mut reply = peer.open_uni().await.unwrap();
    reply.write_u16(id).await.unwrap();
    reply.write_u16(4).await.unwrap();
    reply.write_all(b"echo").await.unwrap();

    let limit = Duration::from_secs(2);
    let (data, from) = tokio::time::timeout(limit, recv_packet(&*session))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data.as_slice(), b"echo");
    assert_eq!(from, target);

    let (result, ()) = tokio::time::timeout(limit, async {
        tokio::join!(biased; recv_packet(&*session), async {
            control.finish().unwrap();
        })
    })
    .await
    .expect("UDP receiver stayed pending after control EOF");
    assert_eq!(result.err().unwrap().kind(), std::io::ErrorKind::BrokenPipe);
    let request_end = tokio::time::timeout(limit, request.read(&mut [0]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request_end, None);
    assert!(peer.close_reason().is_none());
    drop(reply);
}

#[tokio::test]
async fn connection_close_wakes_a_stream_waiting_for_its_udp_id() {
    let hub = Shared::default();
    let waiting = tokio::time::timeout(Duration::from_secs(2), hub.target(42));
    let (result, ()) = tokio::join!(biased; waiting, async { hub.close_all() });
    assert_eq!(
        result.unwrap().err().unwrap().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn a_reply_ahead_of_its_introduction_is_held() {
    udp_session(
        false,
        Quirks {
            reply_before_introduction: true,
        },
    )
    .await;
}

#[tokio::test]
async fn the_bandwidth_exchange_tells_the_server_the_download_rate() {
    let (port, seen, _server) = running(Quirks::default()).await;
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let node = outbound(
        port,
        Settings {
            up: 1_000_000,
            down: 2_000_000,
            ..plain()
        },
    );
    let target = udp_echo().await;
    let session = node.associate(&cx, &address(target)).await.unwrap();
    exchange(&*session, target, 20).await;
    for _ in 0..50 {
        if lock(&seen.brutal_rx).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(*lock(&seen.brutal_rx), Some(2_000_000));
}

fn built(extra: Value) -> Result<(), crate::ctx::BuildError> {
    let mut proxy = json!({"name": "s", "type": "shadowquic", "server": "127.0.0.1", "port": 1});
    if let (Some(base), Some(more)) = (proxy.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("quarantined");
    };
    let ProxyKind::ShadowQuic(opts) = &def.kind else {
        unreachable!()
    };
    super::build(&def, opts, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).map(drop)
}

#[test]
fn build_options_follow_the_go_adapter() {
    assert!(built(json!({})).is_ok());
    assert!(built(json!({"quic-versions": ["V1", "rfc-9000", "v2"]})).is_ok());
    assert!(built(json!({"quic-versions": ["v3"]})).is_err());
    let v2 = built(json!({"quic-versions": ["v2"]})).err().unwrap();
    assert!(v2.is_unsupported());
    assert!(built(json!({"congestion-controller": "bbr", "up": "5 Mbps", "alpn": ["h3"]})).is_ok());
}

#[tokio::test]
async fn a_server_that_cannot_prove_itself_is_refused() {
    let (port, _seen, _server) = running(Quirks::default()).await;
    let proxy = json!({"name": "s", "type": "shadowquic", "server": "127.0.0.1", "port": port,
        "username": "u", "password": "p", "sni": "localhost"});
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("quarantined");
    };
    let ProxyKind::ShadowQuic(opts) = &def.kind else {
        unreachable!()
    };
    let node = super::build(&def, opts, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap();
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        node.connect(&cx, &Address::new("127.0.0.1", 9)),
    )
    .await
    .unwrap()
    .err()
    .unwrap();
    assert!(
        err.to_string().contains("jls authentication failed"),
        "{err}"
    );
}
