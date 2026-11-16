#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert fixture and wire shapes"
)]

use super::*;
use crate::anytls::padding::Padding;
use concord_config::proxy::{Capabilities, ProxyKind, ProxyParse, parse_proxy};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pool() -> Arc<Pool> {
    Pool::new(30, Padding::parse(b"stop=0").unwrap())
}

#[test]
fn parses_miu_credentials_tls_alias_and_reality_defaults() {
    for explicit in [None, Some(false), Some(true)] {
        let mut node = json!({"name":"m", "type":"miu", "server":"example.com", "port":443,
            "psk":"  0123456789abcdef  ", "servername":"tls.example", "udp":true,
            "reality-opts":{"public-key":"A".repeat(43), "short-id":"abcd"}});
        if let Some(enabled) = explicit {
            node["reality-opts"]["support-x25519mlkem768"] = enabled.into();
        }
        let ProxyParse::Ok(def) =
            parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap()
        else {
            panic!("Miu must parse");
        };
        let ProxyKind::Miu(opts) = def.kind else {
            panic!("Miu must retain its type")
        };
        assert_eq!(opts.psk, "0123456789abcdef");
        assert!(opts.tls.enabled);
        assert_eq!(opts.tls.server_name, "tls.example");
        assert_eq!(
            opts.tls.reality.unwrap().support_x25519_mlkem768,
            explicit.unwrap_or(true)
        );
    }
}

#[test]
fn rejects_invalid_keys_and_session_options() {
    for extra in [
        json!({"psk":"short"}),
        json!({"idle-session-timeout":-1}),
        json!({"idle-session-timeout":9_223_372_036_i64}),
        json!({"min-idle-session":33}),
    ] {
        let mut node = json!({"name":"m", "type":"miu", "server":"127.0.0.1", "port":443,
            "psk":"0123456789abcdef"});
        node.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert!(parse_proxy(node.as_object().unwrap(), &Capabilities::full()).is_err());
    }
}

#[tokio::test]
async fn fragmented_frames_and_half_close_reuse_the_lane() {
    let pool = pool();
    let (client, mut server) = tokio::io::duplex(65536);
    let mut stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool.clone(), 0);
    let peer = tokio::spawn(async move {
        let mut wire = Vec::new();
        frame(&mut wire, 2, b"v=2\nraw=1\nidle=180").unwrap();
        frame(&mut wire, 0, b"padding").unwrap();
        frame(&mut wire, 3, b"new padding scheme").unwrap();
        frame(&mut wire, 5, b"response").unwrap();
        frame(&mut wire, 7, &[]).unwrap();
        for part in wire.chunks(2) {
            server.write_all(part).await.unwrap();
        }
        let mut head = [0; 3];
        server.read_exact(&mut head).await.unwrap();
        assert_eq!(head, [5, 0, 7]);
        let mut data = [0; 7];
        server.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"request");
        server.read_exact(&mut head).await.unwrap();
        assert_eq!(head, [7, 0, 0]);
        server
    });
    stream.write_all(b"request").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut result = Vec::new();
    stream.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"response");
    let server = peer.await.unwrap();
    drop(stream);
    assert!(pool.take().1.is_some());
    drop(server);
}

#[tokio::test]
async fn raw_frames_and_truncation_discard_the_lane() {
    for wire in [vec![6, 0, 4, 0, 0, 0, 1], vec![5, 0, 4, 1, 2]] {
        let pool = pool();
        let (client, mut peer) = tokio::io::duplex(64);
        peer.write_all(&wire).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool.clone(), 0);
        assert!(stream.read_to_end(&mut Vec::new()).await.is_err());
        drop(stream);
        assert!(pool.take().1.is_none());
    }
}

#[tokio::test]
async fn resetting_sessions_prevents_an_active_lane_from_returning() {
    let pool = pool();
    let (client, mut peer) = tokio::io::duplex(64);
    peer.write_all(&[7, 0, 0]).await.unwrap();
    let mut stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool.clone(), 0);
    stream.shutdown().await.unwrap();
    stream.read_to_end(&mut Vec::new()).await.unwrap();
    pool.clear();
    drop(stream);
    assert!(pool.take().1.is_none());
}

#[tokio::test(start_paused = true)]
async fn reused_lanes_keep_the_peer_timeout_and_expire_without_another_open() {
    let pool = pool();
    let (client, mut peer) = tokio::io::duplex(64);
    peer.write_all(&[7, 0, 0]).await.unwrap();
    let lane = IdleLane::new(Box::new(client), Some(Duration::from_secs(20)));
    let mut stream = MiuStream::new(lane, pool.clone(), 0);
    stream.shutdown().await.unwrap();
    stream.read_to_end(&mut Vec::new()).await.unwrap();
    drop(stream);
    let (generation, lane) = pool.take();
    let lane = lane.unwrap();
    assert_eq!(lane.peer_idle, Some(Duration::from_secs(20)));
    pool.put(generation, lane);
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::task::yield_now().await;
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, [7, 0, 0]);
    assert!(pool.take().1.is_none());
}

#[test]
fn prewarming_is_supported_without_a_config_warning() {
    let node = json!({"name":"m", "type":"miu", "server":"example.com", "port":443,
        "psk":"0123456789abcdef", "min-idle-session":2});
    let ProxyParse::Ok(def) =
        parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("Miu must parse");
    };
    assert!(concord_config::proxy::proxy_warnings(&def).is_empty());
}

#[test]
fn derived_padding_matches_the_miu_protocol_vectors() {
    for (psk, expected) in [
        (
            "miu-test-psk-alpha-2026",
            "9e6f7e4c45d051d2e82c7e43d9cfa2a9",
        ),
        (
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "6c438b74d0a6fae73e6c9d11d3887f64",
        ),
        (
            "  miu-trimmed-psk-2026  ",
            "96adc3f9ccd96ed1de907b605173a78c",
        ),
        ("miu-测试-psk-2026", "be885c22d4d8fce77b56cfe2506d0559"),
    ] {
        let token = Sha256::digest(psk.trim().as_bytes()).into();
        assert_eq!(padding::derive(&token).unwrap().md5, expected);
    }
}

#[tokio::test]
#[ignore = "requires CONCORD_MIU_TLS and CONCORD_MIU_REALITY Go peer ports"]
#[allow(
    clippy::disallowed_methods,
    reason = "the external peer test binds only a local echo server"
)]
async fn go_peer_carries_tcp_udp_and_reality() {
    use concord_common::packet::{recv_packet, send_packet};
    use concord_common::{DialCx, Initiator, PacketBuf};
    use concord_tls::TrustStore;
    use tokio::net::{TcpListener, UdpSocket};

    let tls: u16 = std::env::var("CONCORD_MIU_TLS").unwrap().parse().unwrap();
    let reality: u16 = std::env::var("CONCORD_MIU_REALITY")
        .unwrap()
        .parse()
        .unwrap();
    for (port, hybrid) in [(tls, None), (reality, Some(true)), (reality, Some(false))] {
        let mut node = json!({"name":"interop", "type":"miu", "server":"127.0.0.1", "port":port,
            "psk":"miu-test-psk-alpha-2026", "udp":true, "skip-cert-verify":true, "sni":"localhost"});
        if let Some(enabled) = hybrid {
            node["client-fingerprint"] = "chrome".into();
            node["reality-opts"] = json!({
                "public-key":std::env::var("CONCORD_MIU_PUBLIC").unwrap(),
                "short-id":"0123456789abcdef", "support-x25519mlkem768":enabled,
            });
        }
        let ProxyParse::Ok(def) =
            parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap()
        else {
            panic!("Miu peer config must parse");
        };
        let outbound =
            crate::build_outbound(&def, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap();
        let env = crate::testing::test_env();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut io, _) = listener.accept().await.unwrap();
                let (mut read, mut write) = io.split();
                tokio::io::copy(&mut read, &mut write).await.unwrap();
                write.shutdown().await.unwrap();
            }
        });
        for _ in 0..2 {
            let mut io = outbound
                .connect(&cx, &Address::new("localhost", address.port()))
                .await
                .unwrap();
            let payload = vec![0x5a; 65536];
            io.write_all(&payload).await.unwrap();
            io.shutdown().await.unwrap();
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), io.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, payload);
        }
        echo.await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buf = [0; 2048];
            let (count, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket
                .send_to(buf.get(..count).unwrap(), peer)
                .await
                .unwrap();
        });
        let target = Address::new("127.0.0.1", address.port());
        let session = outbound.associate(&cx, &target).await.unwrap();
        let mut packet = PacketBuf::with_headroom(session.headroom());
        packet.extend_from_slice(b"miu UDP round trip");
        send_packet(session.as_ref(), &mut packet, &target)
            .await
            .unwrap();
        let (response, source) =
            tokio::time::timeout(Duration::from_secs(10), recv_packet(session.as_ref()))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(response.as_slice(), b"miu UDP round trip");
        assert_eq!(source, target);
        session.close();
        outbound.reset_sessions();
        echo.await.unwrap();
    }
}
