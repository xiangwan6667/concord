#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests talk to loopback sockets and assert on fixed shapes"
)]

mod server;
mod server_obfs;

use std::sync::Arc;
use std::time::Duration;

use concord_common::{
    Address, DialCx, DialEnv, Initiator, Outbound, PacketBuf, recv_packet, send_packet,
};
use concord_config::proxy::ProxyKind;
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use self::server::{Fixture, serve_tcp, serve_udp};
use super::chain::Rc4;
use super::cipher::SsrCipher;
use super::obfs::ObfsFactory;
use super::protocol::{ProtocolFactory, adler32};
use crate::ctx::{BuildCtx, BuildError};
use crate::testing::{LoopbackHop, test_env, test_env_with};

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 13 % 251).unwrap_or(0))
        .collect()
}

fn ctx() -> BuildCtx {
    BuildCtx::new(TrustStore::new(b"", Vec::new()))
}

#[derive(Clone)]
struct Combo {
    cipher: &'static str,
    obfs: &'static str,
    protocol: &'static str,
}

fn proxy(port: u16, combo: &Combo, params: (&str, &str)) -> Value {
    json!({
        "name": "ssr", "type": "ssr", "server": "127.0.0.1", "port": port, "udp": true,
        "password": "ssr-test-password", "cipher": combo.cipher,
        "obfs": combo.obfs, "obfs-param": params.0,
        "protocol": combo.protocol, "protocol-param": params.1,
    })
}

fn client(proxy: &Value) -> Result<Arc<dyn Outbound>, BuildError> {
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        unreachable!()
    };
    let ProxyKind::Ssr(opts) = &def.kind else {
        unreachable!()
    };
    super::build(&def, opts, &ctx())
}

fn fixture(port: u16, combo: &Combo, params: (&str, &str)) -> Arc<Fixture> {
    let clock = ctx().clock;
    let cipher = SsrCipher::pick(
        if combo.cipher == "none" {
            "dummy"
        } else {
            combo.cipher
        },
        "ssr-test-password",
    )
    .unwrap();
    let (obfs, overhead) = ObfsFactory::pick(
        combo.obfs,
        "127.0.0.1",
        port,
        cipher.key.clone(),
        cipher.iv_len(),
        params.0,
        clock.clone(),
    )
    .unwrap();
    let factory = ProtocolFactory::pick(
        combo.protocol,
        cipher.key.clone(),
        overhead,
        params.1,
        clock,
    )
    .unwrap();
    Arc::new(Fixture {
        cipher,
        factory: Arc::new(factory),
        obfs,
    })
}

async fn echo(env: &DialEnv, outbound: &dyn Outbound, size: usize) {
    let cx = DialCx::new(env, Initiator::Direct, None);
    let target = Address::new("echo.example", 7);
    let stream = tokio::time::timeout(Duration::from_secs(10), outbound.connect(&cx, &target))
        .await
        .expect("connect timed out")
        .unwrap();
    let data = pattern(size);
    let expected = data.clone();
    let (mut read, mut write) = stream.into_split();
    let writer = tokio::spawn(async move {
        write.write_all(&data).await.unwrap();
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
    read.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "the shutdown must end the read half");
    assert_eq!(got, expected, "{size} bytes");
}

async fn udp_echo(env: &DialEnv, outbound: &dyn Outbound) {
    let cx = DialCx::new(env, Initiator::Direct, None);
    let dst = Address::new("203.0.113.9", 5353);
    let session = outbound.associate(&cx, &dst).await.unwrap();
    for size in [1usize, 300, 1200] {
        let data = pattern(size);
        let mut packet = PacketBuf::with_headroom(session.headroom());
        packet.extend_from_slice(&data);
        send_packet(&*session, &mut packet, &dst).await.unwrap();
        let (got, from) = tokio::time::timeout(Duration::from_secs(5), recv_packet(&*session))
            .await
            .expect("no udp answer")
            .unwrap();
        assert_eq!(got.as_slice(), data);
        assert_eq!(from, dst);
    }
}

async fn same_port_listeners() -> (tokio::net::TcpListener, tokio::net::UdpSocket) {
    loop {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        match tokio::net::UdpSocket::bind(("127.0.0.1", port)).await {
            Ok(socket) => return (listener, socket),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(err) => panic!("{err}"),
        }
    }
}

async fn round_trip(combo: &Combo, params: (&str, &str), udp: bool) {
    let (listener, socket) = same_port_listeners().await;
    let port = listener.local_addr().unwrap().port();
    let fixture = fixture(port, combo, params);
    let tcp = tokio::spawn(serve_tcp(listener, fixture.clone()));
    let datagrams = tokio::spawn(serve_udp(socket, fixture));
    let outbound = client(&proxy(port, combo, params)).unwrap();
    let name = format!("{} {} {}", combo.cipher, combo.obfs, combo.protocol);
    eprintln!("{name}");
    let env = test_env();
    tokio::time::timeout(Duration::from_secs(60), async {
        echo(&env, &*outbound, 5).await;
        echo(&env, &*outbound, 70_000).await;
        if udp {
            udp_echo(&env, &*outbound).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{name} timed out"));
    tcp.abort();
    datagrams.abort();
}

const OBFS: [&str; 6] = [
    "plain",
    "http_simple",
    "http_post",
    "random_head",
    "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth",
];
const PROTOCOLS: [&str; 6] = [
    "origin",
    "auth_sha1_v4",
    "auth_aes128_md5",
    "auth_aes128_sha1",
    "auth_chain_a",
    "auth_chain_b",
];
const CIPHERS: [&str; 11] = [
    "none",
    "rc4-md5",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "chacha20-ietf",
    "chacha20",
    "xchacha20",
];

#[tokio::test]
async fn every_obfs_and_protocol_round_trips() {
    for obfs in OBFS {
        for protocol in PROTOCOLS {
            let combo = Combo {
                cipher: "aes-256-cfb",
                obfs,
                protocol,
            };
            round_trip(&combo, ("", ""), true).await;
        }
    }
}

#[tokio::test]
async fn udp_goes_through_a_dialer_proxy() {
    let combo = Combo {
        cipher: "aes-256-cfb",
        obfs: "plain",
        protocol: "auth_chain_a",
    };
    let (listener, socket) = same_port_listeners().await;
    let port = listener.local_addr().unwrap().port();
    let fixture = fixture(port, &combo, ("", ""));
    let tcp = tokio::spawn(serve_tcp(listener, fixture.clone()));
    let datagrams = tokio::spawn(serve_udp(socket, fixture));
    let mut chained = proxy(port, &combo, ("", ""));
    chained["dialer-proxy"] = json!("hop");
    let outbound = client(&chained).unwrap();
    let hop = Arc::new(LoopbackHop::default());
    let carried = hop.datagrams.clone();
    let env = test_env_with(hop);
    tokio::time::timeout(Duration::from_secs(30), async {
        echo(&env, &*outbound, 5).await;
        udp_echo(&env, &*outbound).await;
    })
    .await
    .expect("timed out");
    assert_eq!(carried.load(std::sync::atomic::Ordering::Relaxed), 3);
    tcp.abort();
    datagrams.abort();
}

#[tokio::test]
async fn every_cipher_round_trips() {
    for cipher in CIPHERS {
        for protocol in ["origin", "auth_chain_a"] {
            let combo = Combo {
                cipher,
                obfs: "plain",
                protocol,
            };
            round_trip(&combo, ("", ""), true).await;
        }
    }
}

#[tokio::test]
async fn parameters_are_honoured() {
    for protocol in [
        "auth_aes128_md5",
        "auth_aes128_sha1",
        "auth_chain_a",
        "auth_chain_b",
    ] {
        let combo = Combo {
            cipher: "aes-128-ctr",
            obfs: "http_simple",
            protocol,
        };
        round_trip(
            &combo,
            ("a.example,b.example#X-Test: 1\\nY: 2", "1234:secret"),
            true,
        )
        .await;
    }
    let combo = Combo {
        cipher: "aes-128-ctr",
        obfs: "tls1.2_ticket_auth",
        protocol: "origin",
    };
    round_trip(&combo, ("front.example", ""), false).await;
}

#[test]
fn rc4_and_adler_match_published_vectors() {
    let mut data = b"Plaintext".to_vec();
    Rc4::new(b"Key").apply(&mut data);
    assert_eq!(data, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
    assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
}

#[test]
fn unsupported_and_invalid_options_are_reported() {
    let base = Combo {
        cipher: "aes-256-cfb",
        obfs: "plain",
        protocol: "origin",
    };
    let mut gcm = base.clone();
    gcm.cipher = "aes-256-gcm";
    let err = client(&proxy(1, &gcm, ("", ""))).err().unwrap();
    assert!(
        err.to_string()
            .contains("not none or a supported stream cipher")
    );
    assert!(!err.is_unsupported());

    let mut obfs = base.clone();
    obfs.obfs = "nope";
    assert!(client(&proxy(1, &obfs, ("", ""))).is_err());
    let mut protocol = base;
    protocol.protocol = "nope";
    assert!(client(&proxy(1, &protocol, ("", ""))).is_err());
}

async fn go_client_against(combo: Combo, params: (&'static str, &'static str), binary: String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let socket = tokio::net::UdpSocket::bind(("127.0.0.1", port))
        .await
        .unwrap();
    let fixture = fixture(port, &combo, params);
    let tcp = tokio::spawn(serve_tcp(listener, fixture.clone()));
    let datagrams = tokio::spawn(serve_udp(socket, fixture));
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(binary)
            .arg(port.to_string())
            .args([combo.cipher, "ssr-test-password", combo.obfs, params.0])
            .args([combo.protocol, params.1])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    tcp.abort();
    datagrams.abort();
    assert!(
        output.status.success(),
        "{}: {}",
        combo.obfs,
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CONCORD_SSRCLIENT, a build of mihomo's own ssr client"]
async fn mihomo_client_talks_to_the_loopback_server() {
    let Ok(binary) = std::env::var("CONCORD_SSRCLIENT") else {
        return;
    };
    for obfs in OBFS {
        for protocol in PROTOCOLS {
            for cipher in ["aes-256-cfb", "none"] {
                eprintln!("go client: {cipher} {obfs} {protocol}");
                let combo = Combo {
                    cipher,
                    obfs,
                    protocol,
                };
                go_client_against(combo, ("", ""), binary.clone()).await;
            }
        }
    }
    for protocol in [
        "auth_aes128_md5",
        "auth_aes128_sha1",
        "auth_chain_a",
        "auth_chain_b",
    ] {
        let combo = Combo {
            cipher: "chacha20-ietf",
            obfs: "http_post",
            protocol,
        };
        go_client_against(
            combo,
            ("a.example,b.example", "1234:secret"),
            binary.clone(),
        )
        .await;
    }
}

/// IV, then 300 bytes `i * 7` under the `ssr-test-password` key, from the ChaCha20 mihomo's
/// stream ciphers call (`metacubex/chacha` v0.1.5 `NewChaCha20IgnoreCounterOverflow`).
const CHACHA_KAT: &str = include_str!("tests/chacha-kat.txt");

#[test]
fn djb_chacha20_and_xchacha20_match_mihomo_on_the_wire() {
    use super::stream::Layer as _;

    let plain: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
    for line in CHACHA_KAT.lines() {
        let (iv_len, wire) = line.split_once(' ').unwrap();
        let name = if iv_len == "8" {
            "chacha20"
        } else {
            "xchacha20"
        };
        let wire = hex::decode(wire).unwrap();
        let cipher = SsrCipher::pick(name, "ssr-test-password").unwrap();
        assert_eq!(cipher.iv_len().to_string(), iv_len);

        let mut packet = PacketBuf::from_slice(&wire);
        cipher.open_packet(&mut packet).unwrap();
        assert_eq!(packet.as_slice(), plain, "{name} datagram");

        let mut layer = cipher.layer().unwrap();
        let mut decoded = bytes::BytesMut::new();
        let mut input = bytes::BytesMut::new();
        for piece in wire.chunks(5) {
            input.extend_from_slice(piece);
            layer
                .decode(&mut input, &mut decoded, &mut Vec::new())
                .unwrap();
        }
        assert_eq!(&decoded[..], plain, "{name} stream");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CONCORD_SSRCLIENT, a build of mihomo's own ssr client"]
async fn legacy_chacha_streams_talk_to_mihomo_ssr_client() {
    let binary = concord_test_support::peer("CONCORD_SSRCLIENT");
    for cipher in ["chacha20", "xchacha20"] {
        for protocol in PROTOCOLS {
            go_client_against(
                Combo {
                    cipher,
                    obfs: "plain",
                    protocol,
                },
                ("", ""),
                binary.clone(),
            )
            .await;
        }
    }
}
