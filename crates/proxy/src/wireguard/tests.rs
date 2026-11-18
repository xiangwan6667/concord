#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests talk to loopback sockets and assert on fixed shapes"
)]

mod direct;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use concord_common::{Address, DialCx, Initiator, Outbound, PacketBuf, recv_packet, send_packet};
use concord_config::proxy::ProxyKind;
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::udp::socket::UdpSocketFactory;
use gotatun::x25519::{PublicKey, StaticSecret};
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::WireGuard;
use crate::stack::{Stack, StackConfig, StackRecv, StackSend};
use crate::testing::{HeldLookup, LoopbackHop, test_env, test_env_with};

const SERVER_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
const CLIENT_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 2);

struct Server {
    _device: Device<(UdpSocketFactory, StackSend, StackRecv)>,
    _stack: Arc<Stack>,
    port: u16,
    public: PublicKey,
}

fn secret(seed: u8) -> StaticSecret {
    StaticSecret::from([seed; 32])
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    let request = Message::from_vec(query).ok()?;
    let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
    for question in &request.queries {
        reply.add_query(question.clone());
        if question.query_type == hickory_proto::rr::RecordType::A {
            reply.add_answer(Record::from_rdata(
                question.name.clone(),
                60,
                RData::A(A(SERVER_TUNNEL_IP)),
            ));
        }
    }
    reply.to_vec().ok()
}

async fn server(client_public: PublicKey) -> Server {
    let secret = secret(1);
    let public = PublicKey::from(&secret);
    let port = free_udp_port();
    let wired = Stack::start(
        &StackConfig {
            addrs: vec![SERVER_TUNNEL_IP.into()],
            mtu: 1408,
        },
        &Default::default(),
    );
    wired.stack.serve_tcp_echo(7);
    wired.stack.serve_udp(7001, |data| Some(data.to_vec()));
    wired.stack.serve_udp(53, dns_answer);
    let peer = Peer::new(client_public)
        .with_allowed_ip(ipnetwork::IpNetwork::new(CLIENT_TUNNEL_IP.into(), 32).unwrap());
    let device = DeviceBuilder::new()
        .with_default_udp()
        .with_ip_pair(wired.send, wired.recv)
        .with_listen_port(port)
        .with_private_key(secret)
        .with_peer(peer)
        .build()
        .await
        .unwrap();
    Server {
        _device: device,
        _stack: wired.stack,
        port,
        public,
    }
}

fn client(port: u16, public: &PublicKey, extra: Value) -> Arc<WireGuard> {
    client_at("127.0.0.1", port, public, extra)
}

fn client_at(host: &str, port: u16, public: &PublicKey, extra: Value) -> Arc<WireGuard> {
    client_with(host, port, public, extra, Default::default())
}

fn client_with(
    host: &str,
    port: u16,
    public: &PublicKey,
    extra: Value,
    tasks: concord_common::Tasks,
) -> Arc<WireGuard> {
    let mut proxy = json!({
        "name": "wg", "type": "wireguard", "udp": true,
        "private-key": b64(&[2; 32]),
        "ip": CLIENT_TUNNEL_IP.to_string(),
        "server": host, "port": port,
        "public-key": b64(public.as_bytes()),
        "persistent-keepalive": 25,
    });
    if let (Some(base), Some(more)) = (proxy.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    let Some(map) = proxy.as_object() else {
        unreachable!()
    };
    let ProxyParse::Ok(def) = parse_proxy(map, &Capabilities::full()).unwrap() else {
        unreachable!()
    };
    let ProxyKind::WireGuard(opts) = &def.kind else {
        unreachable!()
    };
    Arc::new(super::construct(&def, opts, tasks).unwrap())
}

async fn setup(extra: Value) -> (Server, Arc<WireGuard>) {
    let client_public = PublicKey::from(&secret(2));
    let server = server(client_public).await;
    let outbound = client(server.port, &server.public, extra);
    (server, outbound)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 7 % 251).unwrap_or(0))
        .collect()
}

async fn echo(outbound: &dyn Outbound, target: Address, size: usize) {
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let stream = tokio::time::timeout(Duration::from_secs(10), outbound.connect(&cx, &target))
        .await
        .expect("connect timed out")
        .unwrap();
    let data = pattern(size);
    let (mut read, mut write) = stream.into_split();
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        write.write_all(&sent).await.unwrap();
        write.flush().await.unwrap();
        write
    });
    let reader = tokio::spawn(async move {
        let mut got = vec![0u8; size];
        read.read_exact(&mut got).await.unwrap();
        (read, got)
    });
    let ((mut read, got), mut write) = tokio::time::timeout(Duration::from_secs(20), async {
        (reader.await.unwrap(), writer.await.unwrap())
    })
    .await
    .expect("echo timed out");
    write.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), read.read_to_end(&mut rest))
        .await
        .expect("the read half did not finish after the write half shut down")
        .unwrap();
    assert!(rest.is_empty());
    assert_eq!(got, data);
}

#[tokio::test]
async fn tcp_echoes_through_the_tunnel() {
    let (_server, outbound) = setup(json!({})).await;
    let target = Address::new(&SERVER_TUNNEL_IP.to_string(), 7);
    echo(&*outbound, target.clone(), 5).await;
    echo(&*outbound, target.clone(), 300_000).await;
}

#[tokio::test]
async fn concurrent_connections_share_one_tunnel() {
    let (_server, outbound) = setup(json!({})).await;
    let target = Address::new(&SERVER_TUNNEL_IP.to_string(), 7);
    tokio::join!(
        echo(&*outbound, target.clone(), 20_000),
        echo(&*outbound, target.clone(), 20_000),
        echo(&*outbound, target.clone(), 20_000),
    );
}

#[tokio::test]
async fn callers_that_wait_for_the_tunnel_share_it_and_mark_it_used() {
    let (_server, outbound) = setup(json!({})).await;
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let shared = &outbound.shared;
    let (first, second, third) =
        tokio::join!(shared.tunnel(&cx), shared.tunnel(&cx), shared.tunnel(&cx));
    let first = first.unwrap();
    assert!(Arc::ptr_eq(&first, &second.unwrap()));
    assert!(Arc::ptr_eq(&first, &third.unwrap()));
    assert_eq!(
        first.touch(),
        3,
        "only the two callers that waited count as uses of the new tunnel"
    );
}

#[tokio::test]
async fn udp_echoes_through_the_tunnel() {
    let (_server, outbound) = setup(json!({})).await;
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let dst = Address::new(&SERVER_TUNNEL_IP.to_string(), 7001);
    let session = outbound.associate(&cx, &dst).await.unwrap();
    for size in [4usize, 700, 1200] {
        let data = pattern(size);
        let mut packet = PacketBuf::with_headroom(session.headroom());
        packet.extend_from_slice(&data);
        send_packet(&*session, &mut packet, &dst).await.unwrap();
        let (got, from) = tokio::time::timeout(Duration::from_secs(10), recv_packet(&*session))
            .await
            .expect("no udp answer")
            .unwrap();
        assert_eq!(got.as_slice(), data);
        assert_eq!(from, dst);
    }
}

async fn assert_parked<F: Future>(waiting: Pin<&mut F>) {
    let mut waiting = Some(waiting);
    std::future::poll_fn(|cx| {
        assert!(waiting.take().unwrap().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn closing_a_udp_session_wakes_its_parked_receive() {
    let (_server, outbound) = setup(json!({})).await;
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let dst = Address::new(&SERVER_TUNNEL_IP.to_string(), 7001);
    let session = outbound.associate(&cx, &dst).await.unwrap();
    let mut waiting = std::pin::pin!(recv_packet(&*session));
    assert_parked(waiting.as_mut()).await;
    session.close();
    let woken = tokio::time::timeout(Duration::from_secs(2), waiting).await;
    assert!(woken.expect("the receive stayed parked").is_err());
}

#[tokio::test]
async fn a_failed_wire_fails_the_flows_parked_on_the_tunnel() {
    let server = server(PublicKey::from(&secret(2))).await;
    let outbound = client(server.port, &server.public, json!({"dialer-proxy": "hop"}));
    let hop = Arc::new(LoopbackHop::default());
    let env = test_env_with(hop.clone());
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let udp_dst = Address::new(&SERVER_TUNNEL_IP.to_string(), 7001);
    let session = outbound.associate(&cx, &udp_dst).await.unwrap();
    let tcp_dst = Address::new(&SERVER_TUNNEL_IP.to_string(), 7);
    let stream = tokio::time::timeout(Duration::from_secs(10), outbound.connect(&cx, &tcp_dst))
        .await
        .expect("connect timed out")
        .unwrap();
    let (mut read, _write) = stream.into_split();
    let mut byte = [0u8; 1];
    let mut udp = std::pin::pin!(recv_packet(&*session));
    let mut tcp = std::pin::pin!(read.read(&mut byte));
    assert_parked(udp.as_mut()).await;
    assert_parked(tcp.as_mut()).await;
    hop.cut.set();
    let udp = tokio::time::timeout(Duration::from_secs(2), udp).await;
    assert!(udp.expect("the UDP receive stayed parked").is_err());
    let tcp = tokio::time::timeout(Duration::from_secs(2), tcp).await;
    assert!(tcp.expect("the TCP read stayed parked").is_err());
    assert!(outbound.shared.current().is_none());
}

#[tokio::test]
async fn names_resolve_through_the_tunnel_when_asked() {
    let (_server, outbound) = setup(json!({
        "remote-dns-resolve": true,
        "dns": [SERVER_TUNNEL_IP.to_string()],
    }))
    .await;
    echo(&*outbound, Address::new("echo.example", 7), 64).await;
    echo(&*outbound, Address::new("echo.example", 7), 64).await;

    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let hint = Address::new("echo.example", 7001);
    let session = outbound.associate(&cx, &hint).await.unwrap();
    let mut packet = PacketBuf::with_headroom(session.headroom());
    packet.extend_from_slice(b"ping");
    send_packet(&*session, &mut packet, &hint).await.unwrap();
    let (got, _) = tokio::time::timeout(Duration::from_secs(10), recv_packet(&*session))
        .await
        .expect("no udp answer")
        .unwrap();
    assert_eq!(got.as_slice(), b"ping");

    let ip = outbound.resolve_udp(&cx, "echo.example").await;
    assert_eq!(ip.unwrap().unwrap(), IpAddr::from(SERVER_TUNNEL_IP));
}

#[tokio::test]
async fn a_wrong_server_key_times_out_instead_of_hanging() {
    let (server, _) = setup(json!({})).await;
    let outbound = client(
        server.port,
        &server.public,
        json!({"public-key": b64(&[9; 32])}),
    );
    let env = test_env();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let cx = DialCx::new(&env, Initiator::Direct, Some(deadline));
    let result = outbound
        .connect(&cx, &Address::new(&SERVER_TUNNEL_IP.to_string(), 7))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn a_tunnel_made_across_a_reset_is_not_kept() {
    let server = server(PublicKey::from(&secret(2))).await;
    let outbound = client_at("localhost", server.port, &server.public, json!({}));
    let target = Address::new(&SERVER_TUNNEL_IP.to_string(), 7);
    let held = HeldLookup::new();
    let straddling = {
        let (outbound, env, target) = (outbound.clone(), held.env(), target.clone());
        tokio::spawn(async move {
            let cx = DialCx::new(&env, Initiator::Direct, None);
            outbound.connect(&cx, &target).await.map(drop)
        })
    };
    held.entered().await;
    outbound.reset_sessions();
    held.release();
    let outcome = crate::testing::settled(straddling).await;
    assert!(
        outbound.shared.current().is_none(),
        "the tunnel made before the reset is still held"
    );
    assert!(outcome.is_err());
    echo(&*outbound, target, 16).await;
}

#[tokio::test(start_paused = true)]
async fn an_idle_tunnel_is_dropped_and_comes_back_on_demand() {
    let (_server, outbound) = setup(json!({})).await;
    let target = Address::new(&SERVER_TUNNEL_IP.to_string(), 7);
    echo(&*outbound, target.clone(), 16).await;
    assert!(outbound.shared.current().is_some());
    tokio::time::sleep(Duration::from_secs(200)).await;
    assert!(outbound.shared.current().is_none());
    echo(&*outbound, target, 16).await;
    assert!(outbound.shared.current().is_some());
}

struct GoServer(std::process::Child);

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "needs CONCORD_WGSERVER, a wireguard-go server built from the mihomo module"]
async fn talks_to_wireguard_go() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let binary = concord_test_support::peer("CONCORD_WGSERVER");
    let server_public = PublicKey::from(&secret(1));
    for (name, psk) in [("plain", None), ("psk", Some([5u8; 32]))] {
        let port = free_udp_port();
        let mut command = Command::new(&binary);
        command
            .arg(hex::encode([1u8; 32]))
            .arg(hex::encode(PublicKey::from(&secret(2)).as_bytes()))
            .arg(port.to_string())
            .arg(SERVER_TUNNEL_IP.to_string())
            .arg(CLIENT_TUNNEL_IP.to_string());
        if let Some(psk) = psk {
            command.arg(hex::encode(psk));
        }
        let mut child = GoServer(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "ready");

        let extra = match psk {
            Some(psk) => json!({"pre-shared-key": b64(&psk)}),
            None => json!({}),
        };
        let outbound = client(port, &server_public, extra);
        let target = Address::new(&SERVER_TUNNEL_IP.to_string(), 7);
        echo(&*outbound, target, 5).await;
        echo(
            &*outbound,
            Address::new(&SERVER_TUNNEL_IP.to_string(), 7),
            400_000,
        )
        .await;
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let dst = Address::new(&SERVER_TUNNEL_IP.to_string(), 7001);
        let session = outbound.associate(&cx, &dst).await.unwrap();
        for size in [4usize, 900] {
            let data = pattern(size);
            let mut packet = PacketBuf::with_headroom(session.headroom());
            packet.extend_from_slice(&data);
            send_packet(&*session, &mut packet, &dst).await.unwrap();
            let (got, _) = tokio::time::timeout(Duration::from_secs(10), recv_packet(&*session))
                .await
                .expect("no udp answer")
                .unwrap();
            assert_eq!(got.as_slice(), data);
        }
        eprintln!("wireguard-go {name}: ok");
    }
}

struct ContainerServer {
    container: String,
    pid: String,
    child: std::process::Child,
}

impl Drop for ContainerServer {
    fn drop(&mut self) {
        let signal = |name: &str| {
            std::process::Command::new("docker")
                .args(["exec", &self.container, "kill", name, &self.pid])
                .output()
                .is_ok_and(|out| out.status.success())
        };
        signal("-TERM");
        for _ in 0..50 {
            if !signal("-0") {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_container_server(
    container: &str,
    binary: &str,
    mode: &str,
    port: u16,
    extra: &[String],
) -> ContainerServer {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let mut command = Command::new("docker");
    command
        .args([
            "exec",
            "-i",
            container,
            "sh",
            "-c",
            "echo $$; exec \"$@\"",
            "sh",
        ])
        .arg(binary)
        .arg(mode)
        .arg(hex::encode([1u8; 32]))
        .arg(hex::encode(PublicKey::from(&secret(2)).as_bytes()))
        .arg(port.to_string())
        .arg(SERVER_TUNNEL_IP.to_string())
        .arg(CLIENT_TUNNEL_IP.to_string())
        .args(extra);
    let stderr = if std::env::var_os("CONCORD_AWG_LOG").is_some() {
        Stdio::inherit()
    } else {
        Stdio::null()
    };
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    let mut pid = String::new();
    lines.read_line(&mut pid).unwrap();
    let guard = ContainerServer {
        container: container.to_string(),
        pid: pid.trim().to_string(),
        child,
    };
    let mut ready = String::new();
    lines.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), "ready");
    guard
}

#[tokio::test]
#[ignore = "needs CONCORD_AWG_CONTAINER, a container with a TUN that holds the awgserver binary at CONCORD_AWG_BIN, and its UDP ports 51821 to 51830 reachable at CONCORD_AWG_HOST"]
async fn talks_to_amneziawg_go() {
    let container = concord_test_support::peer("CONCORD_AWG_CONTAINER");
    let binary = concord_test_support::peer("CONCORD_AWG_BIN");
    let only = std::env::var("CONCORD_CASE").unwrap_or_default();
    let host = std::env::var("CONCORD_AWG_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let key = STANDARD.encode([7u8; 32]);
    let key_hex = hex::encode([7u8; 32]);
    let legacy_wire = |extra: &[&str]| -> Vec<String> {
        let mut lines: Vec<String> = [
            "jc=4",
            "jmin=20",
            "jmax=60",
            "s1=15",
            "s2=27",
            "s3=9",
            "s4=5",
            "h1=1234567",
            "h2=7654321",
            "h3=11111",
            "h4=22222",
        ]
        .iter()
        .chain(extra)
        .map(ToString::to_string)
        .collect();
        lines.shrink_to_fit();
        lines
    };
    let legacy_client = json!({
        "jc": 4, "jmin": 20, "jmax": 60, "s1": 15, "s2": 27, "s3": 9, "s4": 5,
        "h1": 1234567, "h2": 7654321, "h3": 11111, "h4": 22222,
    });
    let with = |base: &Value, more: Value| -> Value {
        let mut merged = base.clone();
        if let (Some(into), Some(from)) = (merged.as_object_mut(), more.as_object()) {
            into.extend(from.clone());
        }
        merged
    };
    let v3_server: Vec<String> = [
        "jc=3",
        "jmin=30",
        "jmax=50",
        "s1=20",
        "s2=21",
        "s3=22",
        "s4=23",
        "h1=100000-200000",
        "h2=300000-400000",
        "h3=500000-600000",
        "h4=700000-800000",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let v3_client = json!({
        "version": 3, "jc": 3, "jmin": 30, "jmax": 50, "s1": 20, "s2": 21, "s3": 22, "s4": 23,
        "h1": "100000-200000", "h2": "300000-400000", "h3": "500000-600000", "h4": "700000-800000",
    });
    let protected_server: Vec<String> = v3_server
        .iter()
        .cloned()
        .chain([
            format!("header_protection_key={key_hex}"),
            "random_trailers=true".to_string(),
        ])
        .collect();

    let cases: Vec<(&str, &str, Vec<String>, Option<Value>)> = vec![
        ("plain", "plain", vec![], None),
        ("empty-options", "plain", vec![], Some(json!({}))),
        (
            "legacy",
            "v1",
            legacy_wire(&[]),
            Some(legacy_client.clone()),
        ),
        (
            "legacy-ranges",
            "v1",
            vec![
                "s1=11".into(),
                "s2=12".into(),
                "s3=13".into(),
                "s4=14".into(),
                "h1=5000-5100".into(),
                "h2=6000-6100".into(),
                "h3=7000-7100".into(),
                "h4=8000-8100".into(),
            ],
            Some(json!({
                "s1": 11, "s2": 12, "s3": 13, "s4": 14,
                "h1": "5000-5100", "h2": "6000-6100", "h3": "7000-7100", "h4": "8000-8100",
            })),
        ),
        (
            "legacy-special-junk",
            "v1",
            legacy_wire(&[]),
            Some(with(
                &legacy_client,
                json!({
                    "i1": "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>",
                    "i2": "<r 20><rc 4><rd 4>",
                    "j1": "<b 0xaa><r 30>",
                    "itime": 20,
                }),
            )),
        ),
        ("v3", "v3", v3_server.clone(), Some(v3_client.clone())),
        (
            "v3-protected",
            "v3",
            protected_server,
            Some(with(
                &v3_client,
                json!({
                    "header-protection-key": key,
                    "random-trailers": true,
                    "i1": "<b 0xc0ffee><t><r 12><dz 2>",
                }),
            )),
        ),
    ];
    let server_public = PublicKey::from(&secret(1));
    for (index, (name, mode, wire, amnezia)) in cases.into_iter().enumerate() {
        if !only.is_empty() && !name.contains(&only) {
            continue;
        }
        let port = 51821 + u16::try_from(index).unwrap();
        let _server = start_container_server(&container, &binary, mode, port, &wire);
        let extra = match amnezia {
            Some(options) => json!({"amnezia-wg-option": options}),
            None => json!({}),
        };
        let outbound = client_at(&host, port, &server_public, extra);
        let target = Address::new(&SERVER_TUNNEL_IP.to_string(), 7);
        echo(&*outbound, target.clone(), 5).await;
        echo(&*outbound, target, 400_000).await;
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let dst = Address::new(&SERVER_TUNNEL_IP.to_string(), 7001);
        let session = outbound.associate(&cx, &dst).await.unwrap();
        for size in [4usize, 900] {
            let data = pattern(size);
            let mut packet = PacketBuf::with_headroom(session.headroom());
            packet.extend_from_slice(&data);
            send_packet(&*session, &mut packet, &dst).await.unwrap();
            let (got, _) = tokio::time::timeout(Duration::from_secs(10), recv_packet(&*session))
                .await
                .expect("no udp answer")
                .unwrap();
            assert_eq!(got.as_slice(), data);
        }
        eprintln!("amneziawg-go {name}: ok");
    }
    if only.is_empty() || "mismatch".contains(&only) {
        let port = 51830;
        let _server = start_container_server(&container, &binary, "v1", port, &legacy_wire(&[]));
        let outbound = client_at(&host, port, &server_public, json!({}));
        let env = test_env();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(2500);
        let cx = DialCx::new(&env, Initiator::Direct, Some(deadline));
        let result = outbound
            .connect(&cx, &Address::new(&SERVER_TUNNEL_IP.to_string(), 7))
            .await;
        assert!(
            result.is_err(),
            "a plain client got through an obfuscated server"
        );
    }
}

#[tokio::test]
async fn a_tunnel_s_tasks_end_when_its_outbound_is_dropped() {
    let server = server(PublicKey::from(&secret(2))).await;
    let tracked = crate::testing::Tracked::new();
    let outbound = client_with(
        "127.0.0.1",
        server.port,
        &server.public,
        json!({}),
        tracked.tasks.clone(),
    );
    echo(
        &*outbound,
        Address::new(&SERVER_TUNNEL_IP.to_string(), 7),
        16,
    )
    .await;
    assert!(tracked.running() > 0, "the tunnel is not tracked");
    drop(outbound);
    assert!(tracked.ended_within(Duration::from_secs(5)).await);
}

#[tokio::test]
async fn a_stop_ends_a_tunnel_s_tasks_once_the_outbound_is_gone() {
    let server = server(PublicKey::from(&secret(2))).await;
    let tracked = crate::testing::Tracked::new();
    let outbound = client_with(
        "127.0.0.1",
        server.port,
        &server.public,
        json!({}),
        tracked.tasks.clone(),
    );
    echo(
        &*outbound,
        Address::new(&SERVER_TUNNEL_IP.to_string(), 7),
        16,
    )
    .await;
    tracked.stop();
    drop(outbound);
    assert!(tracked.ended_within(Duration::from_secs(5)).await);
}
