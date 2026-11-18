use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::reality_server::{Fault, MockReality};
use super::support::{Ca, ServerSpec, echo_server, server_config};
use crate::{ClientFingerprint, JlsAuth, TlsConnector, TlsOptions, TrustStore};

fn options() -> TlsOptions {
    TlsOptions {
        server_name: Some("cover.test".into()),
        alpn: vec!["h2".into(), "http/1.1".into()],
        jls: Some(JlsAuth {
            username: "name".into(),
            password: "secret".into(),
        }),
        ..TlsOptions::default()
    }
}

#[tokio::test]
async fn jls_tcp_authenticates_fragmented_hellos_and_transfers_tls_records() {
    for fp in [
        None,
        Some(ClientFingerprint::Chrome),
        Some(ClientFingerprint::Firefox),
        Some(ClientFingerprint::Safari),
    ] {
        for (hybrid, suite) in [(false, 0x1301), (true, 0x1302), (false, 0x1303)] {
            let mut peer = MockReality::new();
            peer.jls = true;
            peer.hybrid = hybrid;
            peer.suite = suite;
            peer.fragmented = true;
            let (near, far) = tokio::io::duplex(1 << 20);
            let server = tokio::spawn(async move { peer.serve(far).await });
            let connector = TlsConnector::new(
                TlsOptions {
                    client_fingerprint: fp,
                    ..options()
                },
                TrustStore::new(b"", vec![]),
            )
            .unwrap();
            let mut stream = tokio::time::timeout(
                Duration::from_secs(10),
                connector.connect(Box::new(near), ""),
            )
            .await
            .unwrap()
            .unwrap();
            let payload = vec![0x5a; 35_000];
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = vec![0; payload.len()];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, payload, "{fp:?} hybrid={hybrid}");
            drop(stream);
            server.await.unwrap().unwrap();
        }
    }
}

#[tokio::test]
async fn jls_tcp_keeps_certificate_verify_finished_and_session_echo_checks() {
    for fault in [
        Fault::BadCertificateVerify,
        Fault::BadFinished,
        Fault::NoSessionIdEcho,
        Fault::HelloRetry,
    ] {
        let mut peer = MockReality::new();
        peer.jls = true;
        peer.fault = fault;
        let (near, far) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let _ = peer.serve(far).await;
        });
        let connector = TlsConnector::new(options(), TrustStore::new(b"", vec![])).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect(Box::new(near), ""),
        )
        .await
        .unwrap();
        let err = result.err().unwrap();
        assert!(!err.to_string().starts_with("REALITY:"), "{fault:?}: {err}");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn jls_tcp_rejects_an_untrusted_fallback_even_with_skip_cert_verify() {
    let ca = Ca::new();
    let config = server_config(
        &ca.leaf(&["cover.test"]),
        &ServerSpec {
            tls13_only: true,
            ..ServerSpec::default()
        },
    );
    let (near, server) = echo_server(config);
    let connector = TlsConnector::new(
        TlsOptions {
            skip_cert_verify: true,
            ..options()
        },
        TrustStore::new(b"", vec![]),
    )
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), connector.connect(near, ""))
        .await
        .unwrap();
    assert!(result.is_err());
    server.await.unwrap();
}

#[tokio::test]
async fn jls_tcp_browses_a_verified_http1_fallback_without_proxy_payload() {
    let ca = Ca::new();
    let config = server_config(
        &ca.leaf(&["cover.test"]),
        &ServerSpec {
            tls13_only: true,
            alpn: vec![b"http/1.1"],
            ..ServerSpec::default()
        },
    );
    let (near, far) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(async move {
        let mut stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(far)
            .await
            .unwrap();
        let mut request = vec![];
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        assert!(request.starts_with(b"GET / HTTP/1.1\r\nHost: cover.test\r\n"));
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("Accept-Encoding: gzip\r\n"));
        assert!(!request.to_ascii_lowercase().contains("connection: close"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();
    });
    let connector = TlsConnector::new(
        TlsOptions {
            client_fingerprint: Some(ClientFingerprint::Chrome),
            ..options()
        },
        ca.trust(),
    )
    .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(Box::new(near), ""),
    )
    .await
    .unwrap();
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("jls authentication failed")
    );
    server.await.unwrap();
}

#[tokio::test]
async fn jls_tcp_preserves_explicit_empty_alpn_and_removes_alps() {
    let (near, mut far) = tokio::io::duplex(1 << 16);
    let connector = TlsConnector::new(
        TlsOptions {
            alpn: vec![],
            client_fingerprint: Some(ClientFingerprint::Chrome),
            ..options()
        },
        TrustStore::new(b"", vec![]),
    )
    .unwrap();
    let client = tokio::spawn(async move {
        let _ = connector.connect(Box::new(near), "").await;
    });
    let mut header = [0; 5];
    far.read_exact(&mut header).await.unwrap();
    let mut hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
    far.read_exact(&mut hello).await.unwrap();
    let parsed = super::hello::parse_hello("jls", &hello);
    assert!(parsed.alpn.is_empty());
    assert!(parsed.alps.is_empty());
    drop(far);
    client.await.unwrap();
}

#[tokio::test]
async fn jls_tcp_browses_a_verified_http2_fallback() {
    for (host, authority) in [("cover.test", "cover.test"), ("::1", "[::1]")] {
        let ca = Ca::new();
        let config = server_config(
            &ca.leaf(&[host]),
            &ServerSpec {
                tls13_only: true,
                alpn: vec![b"h2"],
                ..ServerSpec::default()
            },
        );
        let (near, far) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let stream = tokio_rustls::TlsAcceptor::from(config)
                .accept(far)
                .await
                .unwrap();
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let (request, mut response) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), "GET");
            assert_eq!(request.headers()["accept-encoding"], "gzip");
            assert_eq!(request.uri().authority().unwrap(), authority);
            assert!(
                request.headers()["cookie"]
                    .to_str()
                    .unwrap()
                    .starts_with("padding=")
            );
            response
                .send_response(
                    http::Response::builder().status(200).body(()).unwrap(),
                    true,
                )
                .unwrap();
            while connection.accept().await.is_some() {}
        });
        let connector = TlsConnector::new(
            TlsOptions {
                client_fingerprint: Some(ClientFingerprint::Chrome),
                server_name: Some(host.into()),
                ..options()
            },
            ca.trust(),
        )
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect(Box::new(near), ""),
        )
        .await
        .unwrap();
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("jls authentication failed")
        );
        server.await.unwrap();
    }
}

#[test]
fn jls_native_hello_matches_the_go_capture() {
    // Go 1.27.3 darwin/arm64, mihomo 3c0d10a5 / jls-tls 67adc0e2f796: the first record a
    // transport/jls NewClient (server name example.com, user name/secret, ALPN h2 and http/1.1)
    // writes into a net.Pipe, with the random, session ID and every key share zeroed.
    let got = crate::reality::build_client_hello(
        &crate::jls::NATIVE,
        &crate::reality::HelloParams {
            server_name: Some("example.com"),
            jls: true,
            alpn: None,
            random: &[0; 32],
            x25519_public: &[0; 32],
            mlkem_encapsulation_key: Some(&[0; 1184]),
        },
    )
    .unwrap();
    assert_eq!(
        hex::encode(got),
        include_str!("../../testdata/jls-native-go.hex").trim()
    );
}

#[tokio::test]
async fn jls_native_fallback_does_not_send_http() {
    let ca = Ca::new();
    let config = server_config(
        &ca.leaf(&["cover.test"]),
        &ServerSpec {
            tls13_only: true,
            ..Default::default()
        },
    );
    let (near, far) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(async move {
        let mut stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(far)
            .await
            .unwrap();
        let mut byte = [0];
        match stream.read(&mut byte).await {
            Ok(n) => assert_eq!(n, 0),
            Err(err) => assert!(matches!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            )),
        }
    });
    let connector = TlsConnector::new(options(), ca.trust()).unwrap();
    assert!(
        connector
            .connect(Box::new(near), "")
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("jls authentication failed")
    );
    server.await.unwrap();
}

#[tokio::test]
async fn jls_http1_fallback_uses_an_ip_host_and_waits_for_all_headers() {
    let ca = Ca::new();
    let config = server_config(
        &ca.leaf(&["127.0.0.1"]),
        &ServerSpec {
            tls13_only: true,
            alpn: vec![b"http/1.1"],
            ..Default::default()
        },
    );
    let (near, far) = tokio::io::duplex(1 << 20);
    let (head_tx, head_rx) = tokio::sync::oneshot::channel();
    let (tail_tx, tail_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(far)
            .await
            .unwrap();
        let mut request = vec![];
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .contains("Host: 127.0.0.1\r\n")
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();
        head_tx.send(()).unwrap();
        tail_rx.await.unwrap();
        stream.write_all(b"\r\n").await.unwrap();
        stream.flush().await.unwrap();
    });
    let connector = TlsConnector::new(
        TlsOptions {
            server_name: Some("127.0.0.1".into()),
            client_fingerprint: Some(ClientFingerprint::Chrome),
            ..options()
        },
        ca.trust(),
    )
    .unwrap();
    let task = tokio::spawn(async move { connector.connect(Box::new(near), "").await });
    head_rx.await.unwrap();
    assert!(!task.is_finished());
    tail_tx.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    server.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn jls_fallback_is_bounded_by_the_handshake_deadline() {
    let ca = Ca::new();
    let config = server_config(
        &ca.leaf(&["cover.test"]),
        &ServerSpec {
            tls13_only: true,
            alpn: vec![b"http/1.1"],
            ..Default::default()
        },
    );
    let (near, far) = tokio::io::duplex(1 << 20);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(far)
            .await
            .unwrap();
        let mut request = vec![];
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        ready_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let connector = TlsConnector::new(
        TlsOptions {
            client_fingerprint: Some(ClientFingerprint::Chrome),
            ..options()
        },
        ca.trust(),
    )
    .unwrap();
    let task = tokio::spawn(async move { connector.connect(Box::new(near), "").await });
    ready_rx.await.unwrap();
    let err = task.await.unwrap().err().unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(err.to_string().starts_with("JLS:"));
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn jls_http2_timeout_aborts_the_driver_and_closes_the_peer() {
    let ca = Ca::new();
    let config = server_config(
        &ca.leaf(&["cover.test"]),
        &ServerSpec {
            tls13_only: true,
            alpn: vec![b"h2"],
            ..Default::default()
        },
    );
    let (near, far) = tokio::io::duplex(1 << 20);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(far)
            .await
            .unwrap();
        let mut http = h2::server::handshake(stream).await.unwrap();
        let (_, response) = http.accept().await.unwrap().unwrap();
        ready_tx.send(()).unwrap();
        let next = http.accept().await;
        assert!(next.is_none_or(|result| result.is_err()));
        drop(response);
    });
    let connector = TlsConnector::new(
        TlsOptions {
            client_fingerprint: Some(ClientFingerprint::Chrome),
            ..options()
        },
        ca.trust(),
    )
    .unwrap();
    let client = tokio::spawn(async move { connector.connect(Box::new(near), "").await });
    ready_rx.await.unwrap();
    tokio::time::advance(crate::jls::HANDSHAKE_TIMEOUT).await;
    let err = client.await.unwrap().err().unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}
