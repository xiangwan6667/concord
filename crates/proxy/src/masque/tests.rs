#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests use loopback peers and fixed wire shapes"
)]

mod fixture;
mod review;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::{Buf, Bytes};
use concord_common::{Address, DialCx, Initiator, Outbound, PacketBuf, recv_packet, send_packet};
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use gotatun::packet::PacketBufPool;
use gotatun::tun::{IpRecv, IpSend};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record, RecordType, rdata::A};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::stack::{Stack, StackConfig, Wired};
use crate::testing::test_env;

fn stack() -> Wired {
    let wired = Stack::start(
        &StackConfig {
            addrs: vec!["10.8.0.1".parse().unwrap(), "fd08::1".parse().unwrap()],
            mtu: 9000,
        },
        &Default::default(),
    );
    wired.stack.serve_tcp_echo(7);
    wired.stack.serve_udp(7, |data| Some(data.to_vec()));
    wired.stack.serve_udp(53, dns_answer);
    wired
}

fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    let request = Message::from_vec(query).ok()?;
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    for q in request.queries {
        response.add_query(q.clone());
        if q.query_type == RecordType::A {
            response.add_answer(Record::from_rdata(
                q.name,
                60,
                RData::A(A("10.8.0.1".parse().unwrap())),
            ));
        }
    }
    response.to_vec().ok()
}

fn definition(
    server: &fixture::Server,
    network: &str,
    extra: Value,
) -> concord_config::proxy::ProxyDef {
    let mut raw = json!({
        "name":"warp", "type":"masque", "server":server.addr.ip().to_string(), "port":server.addr.port(),
        "private-key":server.private, "public-key":server.public, "ip":"10.8.0.2", "ipv6":"fd08::2",
        "network":network, "udp":true, "sni":"name-is-not-the-endpoint.example"
    });
    raw.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let ProxyParse::Ok(def) = parse_proxy(raw.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("MASQUE was quarantined");
    };
    *def
}

fn client(server: &fixture::Server, network: &str, extra: Value) -> Arc<dyn Outbound> {
    let def = definition(server, network, extra);
    super::build(
        &def,
        match &def.kind {
            concord_config::proxy::ProxyKind::Masque(opts) => opts,
            _ => unreachable!(),
        },
        &BuildCtx::new(TrustStore::new(b"", vec![])),
    )
    .unwrap()
}

async fn tcp_echo(node: &dyn Outbound, target: &Address, suffix: &[u8]) {
    let env = test_env();
    let cx = DialCx::new(
        &env,
        Initiator::Direct,
        Some(tokio::time::Instant::now() + Duration::from_secs(10)),
    );
    let stream = node.connect(&cx, target).await.unwrap();
    let (mut read, mut write) = stream.into_split();
    let data: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
    let sent = data.clone();
    let sending = tokio::spawn(async move {
        write.write_all(&sent).await.unwrap();
        write.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), read.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    sending.await.unwrap();
    assert_eq!(&received[..data.len()], data);
    assert_eq!(&received[data.len()..], suffix);
}

async fn udp_echo(node: &dyn Outbound, target: &Address) {
    let env = test_env();
    let cx = DialCx::new(
        &env,
        Initiator::Direct,
        Some(tokio::time::Instant::now() + Duration::from_secs(10)),
    );
    let session = node.associate(&cx, target).await.unwrap();
    let data: Vec<u8> = (0..1200).map(|n| (n % 239) as u8).collect();
    let mut packet = PacketBuf::from_slice(&data);
    send_packet(&*session, &mut packet, target).await.unwrap();
    let (received, from) = tokio::time::timeout(Duration::from_secs(10), recv_packet(&*session))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.as_slice(), data);
    assert_eq!(from.port(), target.port());
    session.close();
}

#[tokio::test]
async fn masque_h3_and_h2_carry_tcp_udp_ipv4_ipv6_and_remote_dns() {
    for network in ["h3", "h2"] {
        let server = if network == "h2" {
            fixture::h2_server(200).await
        } else {
            fixture::h3_server(false, 200).await
        };
        let node = client(
            &server,
            network,
            json!({"remote-dns-resolve":true,"dns":["10.8.0.1"]}),
        );
        tcp_echo(&*node, &Address::new("10.8.0.1", 7), b"").await;
        tcp_echo(&*node, &Address::new("fd08::1", 7), b"").await;
        tcp_echo(&*node, &Address::new("inside-tunnel.invalid", 7), b"").await;
        udp_echo(&*node, &Address::new("10.8.0.1", 7)).await;
        udp_echo(&*node, &Address::new("fd08::1", 7)).await;
        udp_echo(&*node, &Address::new("inside-tunnel.invalid", 7)).await;
        assert_eq!(
            server
                .connections
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        node.reset_sessions();
        tcp_echo(&*node, &Address::new("10.8.0.1", 7), b"").await;
        assert_eq!(
            server
                .connections
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }
}

#[tokio::test]
async fn masque_l4_reuses_h3_streams_and_preserves_half_close_but_rejects_udp() {
    let server = fixture::h3_server(true, 200).await;
    let node = client(&server, "h3-l4proxy", json!({"ip":"", "ipv6":""}));
    assert!(!node.info().udp);
    for _ in 0..3 {
        tcp_echo(&*node, &Address::new("10.8.0.1", 7), b"after-fin").await;
    }
    assert_eq!(
        server
            .connections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    assert!(
        node.associate(&cx, &Address::new("10.8.0.1", 7))
            .await
            .is_err()
    );
    node.reset_sessions();
    tcp_echo(&*node, &Address::new("10.8.0.1", 7), b"after-fin").await;
}

#[tokio::test]
async fn masque_pins_the_endpoint_key_and_checks_connect_status() {
    for network in ["h3", "h2", "h3-l4proxy"] {
        let server = if network == "h2" {
            fixture::h2_server(200).await
        } else {
            fixture::h3_server(network == "h3-l4proxy", 200).await
        };
        let (_, wrong) = fixture::keys();
        let node = client(
            &server,
            network,
            json!({"public-key":STANDARD.encode(&wrong)}),
        );
        let env = test_env();
        let cx = DialCx::new(
            &env,
            Initiator::Direct,
            Some(tokio::time::Instant::now() + Duration::from_secs(2)),
        );
        assert!(
            node.connect(&cx, &Address::new("10.8.0.1", 7))
                .await
                .is_err()
        );
        let node = client(
            &server,
            network,
            json!({"public-key":STANDARD.encode(wrong),"skip-cert-verify":true}),
        );
        tcp_echo(
            &*node,
            &Address::new("10.8.0.1", 7),
            if network == "h3-l4proxy" {
                b"after-fin"
            } else {
                b""
            },
        )
        .await;
        let reject = if network == "h2" {
            fixture::h2_server(403).await
        } else {
            fixture::h3_server(network == "h3-l4proxy", 403).await
        };
        let node = client(&reject, network, json!({}));
        assert!(
            node.connect(&cx, &Address::new("10.8.0.1", 7))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn masque_capsules_have_exact_bytes_and_skip_unknown_types_without_buffering_them() {
    let (mut a, mut b) = tokio::io::duplex(64);
    let sending = tokio::spawn(async move {
        capsule::send(&mut a, 123, b"unknown").await.unwrap();
        capsule::send(&mut a, 0, b"\x45\0ip").await.unwrap();
    });
    assert_eq!(capsule::varint(&mut b).await.unwrap(), 123);
    let len = capsule::varint(&mut b).await.unwrap();
    capsule::skip(&mut b, len).await.unwrap();
    let mut rest = Vec::new();
    b.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"\0\x04\x45\0ip");
    sending.await.unwrap();
    // Fixed IPv4/UDP fixture; RFC 1071 checksum, cross-checked against mihomo's
    // transport/masque/client_h2.go::calculateIPv4Checksum (full 20-byte header).
    let mut ipv4 =
        hex::decode("450000211234400040113c61c0000201c633640230390035000d000068656c6c6f").unwrap();
    assert!(capsule::decrement_hop(&mut ipv4));
    assert_eq!(
        &ipv4[..20],
        hex::decode("45000021123440003f113d61c0000201c6336402").unwrap()
    );
    ipv4[8] = 1;
    assert!(!capsule::decrement_hop(&mut ipv4));
    let mut invalid = vec![0; 20];
    invalid[0] = 0x45;
    invalid[8] = 64;
    invalid[10..12].copy_from_slice(&0xfeffu16.to_be_bytes());
    assert!(capsule::decrement_hop(&mut invalid));
    assert_eq!(&invalid[10..12], &0x7bffu16.to_be_bytes());
    let mut ipv6 = vec![0; 40];
    ipv6[0] = 0x60;
    ipv6[7] = 64;
    assert!(capsule::decrement_hop(&mut ipv6));
    assert_eq!(ipv6[7], 63);
}

#[tokio::test]
async fn masque_reset_and_close_wake_parked_udp_readers() {
    for network in ["h3", "h2"] {
        let server = if network == "h2" {
            fixture::h2_server(200).await
        } else {
            fixture::h3_server(false, 200).await
        };
        let node = client(&server, network, json!({}));
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let target = Address::new("10.8.0.1", 7);
        let session = node.associate(&cx, &target).await.unwrap();
        let mut waiting = std::pin::pin!(recv_packet(&*session));
        std::future::poll_fn(|cx| {
            use std::future::Future;
            assert!(waiting.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        node.reset_sessions();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), waiting)
                .await
                .unwrap()
                .is_err()
        );
        let session = node.associate(&cx, &target).await.unwrap();
        let mut waiting = std::pin::pin!(recv_packet(&*session));
        std::future::poll_fn(|cx| {
            use std::future::Future;
            assert!(waiting.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        session.close();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), waiting)
                .await
                .unwrap()
                .is_err()
        );
    }
}

#[tokio::test]
async fn masque_l4_remote_tcp_dns_travels_over_the_proxy_stream() {
    let server = fixture::h3_server(true, 200).await;
    let node = client(
        &server,
        "h3-l4proxy",
        json!({"remote-dns-resolve":true,"dns":["tcp://10.8.0.1"]}),
    );
    tcp_echo(
        &*node,
        &Address::new("inside-proxy.invalid", 7),
        b"after-fin",
    )
    .await;
    assert_eq!(
        server
            .connections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn masque_h2_honors_an_inner_mtu_larger_than_the_packet_pool_default() {
    let server = fixture::h2_server(200).await;
    let node = client(&server, "h2", json!({"mtu":9000}));
    tcp_echo(&*node, &Address::new("10.8.0.1", 7), b"").await;
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let target = Address::new("10.8.0.1", 7);
    let session = node.associate(&cx, &target).await.unwrap();
    let data = vec![42; 8000];
    let mut packet = PacketBuf::from_slice(&data);
    send_packet(&*session, &mut packet, &target).await.unwrap();
    let (received, _) = tokio::time::timeout(Duration::from_secs(2), recv_packet(&*session))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.as_slice(), data);
}
