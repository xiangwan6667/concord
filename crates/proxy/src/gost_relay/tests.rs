#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "loopback fixtures assert protocol bytes"
)]

use super::*;
use crate::dgram::{Decoded, Decoder, Encoder};
use crate::testing::{LoopbackHop, test_env_with};
use concord_common::{Initiator, PacketBuf, recv_packet, send_packet};
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[test]
fn gost_relay_connect_and_forward_requests_match_mihomo() {
    // mihomo transport/gost/relay.go:231-285 writes auth, address, then network.
    let target = Address::new("example.com", 443);
    let mut expected = vec![1, 1, 0, 30, 1, 0, 4, 1, b'u', 1, b'p', 2, 0, 15, 3, 11];
    expected.extend_from_slice(b"example.com");
    expected.extend_from_slice(&[1, 187, 4, 0, 2, 0, 0]);
    assert_eq!(
        wire::request(Some(&target), false, "u", "p").unwrap(),
        expected
    );
    assert_eq!(
        wire::request(None, true, "", "").unwrap(),
        [1, 129, 0, 5, 4, 0, 2, 0, 1]
    );
    assert_eq!(
        wire::request(Some(&Address::new("1.2.3.4", 53)), true, "", "").unwrap(),
        [1, 129, 0, 15, 2, 0, 7, 1, 1, 2, 3, 4, 0, 53, 4, 0, 2, 0, 1]
    );
    let mapped = Address::Socket("[::ffff:1.2.3.4]:53".parse().unwrap());
    assert_eq!(
        wire::request(Some(&mapped), true, "", "").unwrap(),
        wire::request(Some(&Address::new("1.2.3.4", 53)), true, "", "").unwrap()
    );
    assert!(wire::request(None, false, &"u".repeat(256), "").is_err());
    assert!(wire::request(None, false, "", &"p".repeat(256)).is_err());
    let v6 = wire::request(Some(&Address::new("::1", 443)), false, "", "").unwrap();
    assert_eq!(v6.len(), 31);
    assert_eq!(v6[7], 4);
}

#[tokio::test]
async fn gost_relay_response_consumes_features_without_eating_payload_and_rejects_status() {
    for (status, text) in [
        (1, "bad request"),
        (2, "unauthorized"),
        (3, "forbidden"),
        (4, "timeout"),
        (5, "service unavailable"),
        (6, "host unreachable"),
        (7, "network unreachable"),
        (8, "internal server error"),
        (255, "unknown"),
    ] {
        let (mut near, mut far) = duplex(16);
        far.write_all(&[1, status, 0, 0]).await.unwrap();
        assert!(
            wire::response(&mut near)
                .await
                .unwrap_err()
                .to_string()
                .contains(&format!("0x{status:02x} ({text})"))
        );
    }
    for version in [0, 2, 255] {
        let (mut near, mut far) = duplex(16);
        far.write_all(&[version, 0, 0, 0]).await.unwrap();
        assert!(wire::response(&mut near).await.is_err());
    }
    let (mut near, mut far) = duplex(16);
    far.write_all(&[1, 0, 0, 3, 1, 2, 3, b'o', b'k'])
        .await
        .unwrap();
    wire::response(&mut near).await.unwrap();
    let mut data = [0; 2];
    near.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"ok");
    let (mut large_near, mut large_far) = duplex(256);
    let writer = tokio::spawn(async move {
        large_far.write_all(&[1, 0, 255, 255]).await.unwrap();
        large_far.write_all(&vec![7; 65535]).await.unwrap();
        large_far.write_all(b"ok").await.unwrap();
    });
    wire::response(&mut large_near).await.unwrap();
    large_near.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"ok");
    writer.await.unwrap();
    let (mut near, mut far) = duplex(16);
    far.write_all(&[1, 0, 0, 3, 1]).await.unwrap();
    drop(far);
    assert_eq!(
        wire::response(&mut near).await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn gost_relay_udp_lengths_and_destination_binding_match_mihomo() {
    let target = Address::new("1.2.3.4", 53);
    let mut codec = wire::Frames(target.clone());
    for len in [0, 1, 65535] {
        let mut packet = PacketBuf::with_headroom(2);
        packet.extend_from_slice(&vec![7; len]);
        codec.encode(&mut packet, &target).unwrap();
        assert_eq!(&packet.as_slice()[..2], &(len as u16).to_be_bytes());
        let mut bytes = packet.as_slice().to_vec();
        let Decoded::Packet {
            payload, consumed, ..
        } = codec.decode(&mut bytes).unwrap()
        else {
            panic!("short")
        };
        assert_eq!(payload.len(), len);
        assert_eq!(consumed, len + 2);
    }
    let mut packet = PacketBuf::with_headroom(2);
    packet.extend_from_slice(b"hi");
    assert!(
        codec
            .encode(&mut packet, &Address::new("1.2.3.5", 53))
            .is_err()
    );
    assert!(matches!(
        codec.decode(&mut [0, 3, 1, 2]).unwrap(),
        Decoded::NeedMore
    ));
    let mut packet = PacketBuf::with_headroom(2);
    packet.extend_from_slice(&vec![0; 65536]);
    assert!(codec.encode(&mut packet, &target).is_err());
}

#[tokio::test]
async fn gost_relay_outbound_handshakes_before_payload_and_binds_udp_through_dialer_proxy() {
    for (forward, udp, mux, tls) in [
        (false, false, false, false),
        (true, false, false, false),
        (false, true, false, false),
        (true, true, false, false),
        (false, false, true, false),
        (true, true, true, false),
        (false, false, true, true),
        (true, true, true, true),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = Address::new("127.0.0.1", 53);
        let want = wire::request((!forward).then_some(&target), udp, "u", "p").unwrap();
        let made = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(made.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![made.cert.der().clone()], key.into())
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let server = tokio::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            let mut io: Box<dyn TestIo> = if tls {
                let io = acceptor.accept(io).await.unwrap();
                assert_eq!(io.get_ref().1.server_name(), Some("localhost"));
                Box::new(io)
            } else {
                Box::new(io)
            };
            if mux {
                let mut syn = [0; 8];
                io.read_exact(&mut syn).await.unwrap();
                assert_eq!(syn, [1, 0, 0, 0, 3, 0, 0, 0]);
                read_smux_header(&mut io, want.len()).await;
            }
            let mut request = vec![0; want.len()];
            io.read_exact(&mut request).await.unwrap();
            assert_eq!(request, want);
            if mux {
                write_smux_header(&mut io, 6).await;
            }
            for byte in [1, 0, 0, 2, 0xaa, 0xbb] {
                io.write_all(&[byte]).await.unwrap();
            }
            io.flush().await.unwrap();
            if mux {
                read_smux_header(&mut io, if udp { 4 } else { 2 }).await;
            }
            let mut data = vec![0; if udp { 4 } else { 2 }];
            io.read_exact(&mut data).await.unwrap();
            assert_eq!(
                data,
                if udp {
                    vec![0, 2, b'h', b'i']
                } else {
                    b"hi".to_vec()
                }
            );
            if mux {
                write_smux_header(&mut io, data.len()).await;
            }
            io.write_all(&data).await.unwrap();
            io.flush().await.unwrap();
        });
        let config = json!({"name":"relay", "type":"gost-relay", "server":"127.0.0.1", "port":port,
            "forward":forward, "mux":mux, "tls":tls, "sni":"localhost", "skip-cert-verify":true, "username":"u", "password":"p", "udp":true, "dialer-proxy":"hop"});
        let ProxyParse::Ok(def) =
            parse_proxy(config.as_object().unwrap(), &Capabilities::full()).unwrap()
        else {
            panic!("quarantined")
        };
        let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
        let outbound = crate::build_outbound(&def, &ctx).unwrap();
        assert!(!outbound.multi_destination_udp());
        let env = test_env_with(Arc::new(LoopbackHop::default()));
        let cx = DialCx::new(&env, Initiator::App, None);
        if udp {
            let session = outbound
                .associate(&cx, &Address::new("localhost", 53))
                .await
                .unwrap();
            let mut packet = PacketBuf::with_headroom(session.headroom());
            packet.extend_from_slice(b"hi");
            send_packet(session.as_ref(), &mut packet, &target)
                .await
                .unwrap();
            let (received, from) = recv_packet(session.as_ref()).await.unwrap();
            assert_eq!(from, target);
            assert_eq!(received.as_slice(), b"hi");
        } else {
            let mut stream = outbound.connect(&cx, &target).await.unwrap();
            stream.write_all(b"hi").await.unwrap();
            let mut received = [0; 2];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"hi");
        }
        crate::testing::settled(server).await;
    }
}

trait TestIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestIo for T {}

async fn read_smux_header(io: &mut Box<dyn TestIo>, len: usize) {
    let mut header = [0; 8];
    io.read_exact(&mut header).await.unwrap();
    let [a, b] = (len as u16).to_le_bytes();
    assert_eq!(header, [1, 2, a, b, 3, 0, 0, 0]);
}

async fn write_smux_header(io: &mut Box<dyn TestIo>, len: usize) {
    let [a, b] = (len as u16).to_le_bytes();
    io.write_all(&[1, 2, a, b, 3, 0, 0, 0]).await.unwrap();
}
