#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "tests validate protocol framing and configuration"
)]

use super::*;
use concord_common::sync::lock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixtures() -> Vec<serde_json::Value> {
    serde_json::from_str(
        &std::fs::read_to_string(std::env::var("CONCORD_VLESS_ENCRYPTION_PEERS").unwrap()).unwrap(),
    )
    .unwrap()
}

async fn exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(stream: &mut S, payload: &[u8]) {
    let (mut read, mut write) = tokio::io::split(stream);
    let sent = async {
        write.write_all(payload).await?;
        write.shutdown().await
    };
    let received = async {
        let mut received = Vec::new();
        read.read_to_end(&mut received).await?;
        Ok::<_, io::Error>(received)
    };
    let (_, received) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::try_join!(sent, received)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
#[ignore = "requires CONCORD_VLESS_ENCRYPTION_PEERS from the Go encryption peer"]
async fn go_peer_accepts_both_ciphers_all_modes_keys_and_resumption() {
    for fixture in fixtures() {
        for aes in [true, false] {
            let client = Client::parse(fixture["config"].as_str().unwrap())
                .unwrap()
                .unwrap();
            for round in 0..3 {
                let socket = tokio::net::TcpStream::connect((
                    std::net::Ipv4Addr::LOCALHOST,
                    fixture["raw"].as_u64().unwrap() as u16,
                ))
                .await
                .unwrap();
                let mut io = client
                    .handshake_with_cipher(Box::new(socket), aes)
                    .await
                    .unwrap();
                exchange(&mut io, &vec![0x15; 65536]).await;
                if client.resume {
                    assert!(lock(&client.ticket).is_some());
                }
                eprintln!(
                    "VLESS Encryption peer {} cipher {aes} round {round}",
                    fixture["name"]
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires CONCORD_VLESS_ENCRYPTION_PEERS from the Go encryption peer"]
async fn go_peer_serves_the_vless_tcp_udp_and_vision_entry_points() {
    use concord_common::packet::{recv_packet, send_packet};
    use concord_common::{Address, DialCx, Initiator, PacketBuf};
    use concord_config::proxy::{Capabilities, ProxyParse, parse_proxy};
    use concord_tls::{TlsConnector, TlsOptions, TrustStore};
    use serde_json::json;
    for fixture in fixtures() {
        for (vision, encoding) in [
            (false, "packetaddr"),
            (true, "packetaddr"),
            (false, "xudp"),
            (true, "xudp"),
        ] {
            let port = fixture[if vision { "vision" } else { "vless" }]
                .as_u64()
                .unwrap() as u16;
            let node = json!({"name":"encrypted", "type":"vless", "server":"127.0.0.1", "port":port,
                "uuid":"00000000-0000-0000-0000-000000000001", "udp":true, "packet-encoding":encoding,
                "flow":if vision { "xtls-rprx-vision" } else { "" }, "encryption":fixture["config"]});
            let ProxyParse::Ok(def) =
                parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap()
            else {
                panic!("VLESS must parse");
            };
            let outbound = crate::build_outbound(
                &def,
                &crate::BuildCtx::new(TrustStore::new(b"", Vec::new())),
            )
            .unwrap();
            let env = crate::testing::test_env();
            let cx = DialCx::new(&env, Initiator::Direct, None);
            for _ in 0..2 {
                let mut stream = outbound
                    .connect(&cx, &Address::new("test.example", 443))
                    .await
                    .unwrap();
                if vision {
                    let connector = TlsConnector::new(
                        TlsOptions {
                            skip_cert_verify: true,
                            ..TlsOptions::default()
                        },
                        TrustStore::new(b"", Vec::new()),
                    )
                    .unwrap();
                    let mut tls = connector.connect(stream, "localhost").await.unwrap();
                    exchange(&mut tls, &vec![0x15; 128 * 1024]).await;
                } else {
                    exchange(&mut stream, &vec![0x15; 32768]).await;
                }
            }
            {
                let target = Address::new("127.0.0.1", 5353);
                let session = outbound.associate(&cx, &target).await.unwrap();
                let mut packet = PacketBuf::with_headroom(session.headroom());
                packet.extend_from_slice(b"encrypted UDP");
                send_packet(session.as_ref(), &mut packet, &target)
                    .await
                    .unwrap();
                let (response, _) =
                    tokio::time::timeout(Duration::from_secs(5), recv_packet(session.as_ref()))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(response.as_slice(), b"encrypted UDP");
                session.close();
            }
            outbound.reset_sessions();
            eprintln!(
                "VLESS entry-point peer {} Vision {vision} UDP {encoding}",
                fixture["name"]
            );
        }
    }
}

#[test]
fn configuration_validates_keys_modes_and_padding() {
    let key = URL_SAFE_NO_PAD.encode([9; 32]);
    for mode in ["native", "xorpub", "random"] {
        for rtt in ["1rtt", "0rtt"] {
            assert!(
                Client::parse(&format!("mlkem768x25519plus.{mode}.{rtt}.{key}"))
                    .unwrap()
                    .is_some()
            );
        }
    }
    for text in [
        "broken",
        "mlkem768x25519plus.native.1rtt",
        "mlkem768x25519plus.wrong.1rtt.key",
    ] {
        assert!(Client::parse(text).is_err());
    }
}

#[test]
fn utf8_contexts_match_the_blake3_api() {
    for context in ["", "VLESS", "context with unicode 测试"] {
        assert_eq!(
            kdf::derive(context.as_bytes(), b"material"),
            blake3::derive_key(context, b"material")
        );
    }
}
