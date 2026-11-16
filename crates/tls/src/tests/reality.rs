use std::sync::Arc;
use std::time::Duration;

use rand::{Rng, SeedableRng, rngs::StdRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use super::reality_server::{Fault, MockReality};
use super::support::{Ca, ServerSpec, server_config};
use crate::fingerprints::ClientFingerprint;
use crate::{RealityOptions, TlsConn, TlsConnector, TlsError, TlsOptions, TrustStore};

const TLS13_FINGERPRINTS: [ClientFingerprint; 10] = [
    ClientFingerprint::Chrome,
    ClientFingerprint::Chrome120,
    ClientFingerprint::Firefox,
    ClientFingerprint::Firefox120,
    ClientFingerprint::Safari,
    ClientFingerprint::Safari16,
    ClientFingerprint::Ios,
    ClientFingerprint::Edge,
    ClientFingerprint::Qq,
    ClientFingerprint::Random,
];

fn empty_trust() -> Arc<TrustStore> {
    TrustStore::from_parts(Vec::new(), b"", Vec::new())
}

fn connector(server: &MockReality, fp: ClientFingerprint, mlkem: bool) -> TlsConnector {
    connector_with(server, fp, mlkem, server.short_id, empty_trust())
}

fn connector_with(
    server: &MockReality,
    fp: ClientFingerprint,
    mlkem: bool,
    short_id: [u8; 8],
    trust: Arc<TrustStore>,
) -> TlsConnector {
    TlsConnector::new(
        TlsOptions {
            server_name: Some("cover.test".into()),
            client_fingerprint: Some(fp),
            reality: Some(RealityOptions {
                public_key: server.public_key,
                short_id,
                support_x25519mlkem768: mlkem,
                client_version: [1, 8, 2],
                mldsa65_verify: None,
            }),
            ..TlsOptions::default()
        },
        trust,
    )
    .unwrap()
}

async fn dial(server: Arc<MockReality>, connector: &TlsConnector) -> std::io::Result<TlsConn> {
    let (client, far) = duplex(1 << 20);
    tokio::spawn(async move {
        let _ = server.serve(far).await;
    });
    tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(Box::new(client), ""),
    )
    .await
    .expect("handshake hung")
}

#[tokio::test]
async fn authenticates_mldsa_and_the_configured_client_version() {
    use aws_lc_rs::signature::{KeyPair, ML_DSA_65_SIGNING, PqdsaKeyPair};

    for (signed, wrong_key) in [(true, false), (true, true), (false, false)] {
        let mut server = MockReality::new();
        server.client_version = [26, 3, 27];
        let signer = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let mut verification_key = signer.public_key().as_ref().to_vec();
        if wrong_key {
            verification_key = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
                .unwrap()
                .public_key()
                .as_ref()
                .to_vec();
        }
        if signed {
            server.mldsa = Some(signer);
        }
        let options = TlsOptions {
            server_name: Some("cover.test".into()),
            client_fingerprint: Some(ClientFingerprint::Chrome),
            reality: Some(RealityOptions {
                public_key: server.public_key,
                short_id: server.short_id,
                support_x25519mlkem768: true,
                client_version: server.client_version,
                mldsa65_verify: Some(verification_key),
            }),
            ..TlsOptions::default()
        };
        let connector = TlsConnector::new(options, empty_trust()).unwrap();
        let result = dial(Arc::new(server), &connector).await;
        if signed && !wrong_key {
            let mut connection = result.unwrap();
            connection.write_all(b"hello").await.unwrap();
            connection.flush().await.unwrap();
            let mut echoed = [0; 5];
            connection.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"hello");
        } else {
            assert!(result.err().unwrap().to_string().contains("ML-DSA-65"));
        }
    }
}

#[tokio::test]
async fn round_trips_for_every_fingerprint_and_key_exchange() {
    for (client_mlkem, server_hybrid) in [(false, false), (true, false), (true, true)] {
        for fp in TLS13_FINGERPRINTS {
            let mut server = MockReality::new();
            server.hybrid = server_hybrid;
            let server = Arc::new(server);
            let mut conn = dial(server.clone(), &connector(&server, fp, client_mlkem))
                .await
                .unwrap_or_else(|err| panic!("{fp} {client_mlkem} {server_hybrid}: {err}"));
            assert_eq!(conn.negotiated_alpn(), Some(b"h2".as_slice()));
            assert!(conn.is_tls13());
            let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
            let (mut reader, mut writer) = tokio::io::split(&mut conn);
            let send = payload.clone();
            let writing = async move {
                writer.write_all(&send).await.unwrap();
                writer.flush().await.unwrap();
            };
            let reading = async {
                let mut got = vec![0u8; payload.len()];
                reader.read_exact(&mut got).await.unwrap();
                got
            };
            let (_, got) = tokio::join!(writing, reading);
            assert_eq!(got, payload, "{fp}");
            if let TlsConn::Reality(inner) = &conn {
                let offered = fp.resolve_random().spec().is_none_or(|s| s.offers_mlkem());
                let expect_hybrid = client_mlkem && server_hybrid && offered;
                if fp != ClientFingerprint::Random {
                    let want = if expect_hybrid && fp.spec().is_some_and(|s| s.offers_mlkem()) {
                        0x11ec
                    } else {
                        0x001d
                    };
                    assert_eq!(inner.key_exchange_group(), want, "{fp}");
                }
            }
        }
    }
}

#[tokio::test]
async fn a_chacha_server_suite_completes() {
    let mut server = MockReality::new();
    server.suite = 0x1303;
    let server = Arc::new(server);
    let mut conn = dial(
        server.clone(),
        &connector(&server, ClientFingerprint::Chrome, false),
    )
    .await
    .unwrap();
    conn.write_all(b"chacha").await.unwrap();
    let mut got = [0u8; 6];
    conn.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"chacha");
}

#[tokio::test]
async fn strangers_and_wrong_keys_are_refused() {
    let server = Arc::new(MockReality::new());
    let wrong_id = connector_with(
        &server,
        ClientFingerprint::Chrome,
        false,
        [9; 8],
        empty_trust(),
    );
    assert!(dial(server.clone(), &wrong_id).await.is_err());

    let mut forged = MockReality::new();
    forged.short_id = server.short_id;
    let wrong_key = connector(&forged, ClientFingerprint::Chrome, false);
    assert!(dial(server, &wrong_key).await.is_err());
}

#[tokio::test]
async fn a_misbehaving_server_fails_closed() {
    for fault in [
        Fault::BadFinished,
        Fault::NoSessionIdEcho,
        Fault::HelloRetry,
        Fault::BadHmac,
        Fault::BadCertificateVerify,
        Fault::UnsupportedCipher,
        Fault::HugeRecord,
        Fault::Garbage,
    ] {
        let mut server = MockReality::new();
        server.fault = fault;
        let server = Arc::new(server);
        let err = dial(
            server.clone(),
            &connector(&server, ClientFingerprint::Chrome, true),
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("{fault:?} was accepted"));
        eprintln!("{fault:?}: {err}");
    }
}

#[tokio::test]
async fn a_forged_certificate_mac_is_not_taken_for_the_cover_site() {
    let mut server = MockReality::new();
    server.fault = Fault::BadHmac;
    let server = Arc::new(server);
    let err = dial(
        server.clone(),
        &connector(&server, ClientFingerprint::Chrome, false),
    )
    .await
    .err()
    .unwrap();
    assert!(
        err.to_string().contains("certificate verify failed"),
        "{err}"
    );
}

#[tokio::test]
async fn truncated_server_flights_end_in_errors() {
    let server = Arc::new(MockReality::new());
    for cut in (0..580).step_by(7) {
        let (client, mut near) = duplex(1 << 20);
        let (mut far_server_side, far) = duplex(1 << 20);
        let s = server.clone();
        tokio::spawn(async move {
            let _ = s.serve(far).await;
        });
        tokio::spawn(async move {
            let mut hello = vec![0u8; 4096];
            let n = near.read(&mut hello).await.unwrap_or(0);
            let _ = far_server_side.write_all(&hello[..n]).await;
            let mut sent = 0usize;
            let mut buf = vec![0u8; 4096];
            while sent < cut {
                let n = far_server_side.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                let take = n.min(cut - sent);
                let _ = near.write_all(&buf[..take]).await;
                sent += take;
            }
            let _ = near.shutdown().await;
        });
        let conn = connector(&server, ClientFingerprint::Safari, false);
        let result =
            tokio::time::timeout(Duration::from_secs(5), conn.connect(Box::new(client), ""))
                .await
                .expect("hung on a truncated flight");
        assert!(result.is_err(), "cut at {cut}");
    }
}

#[tokio::test]
async fn random_server_bytes_never_panic_or_hang() {
    let server = MockReality::new();
    let mut rng = StdRng::seed_from_u64(99);
    for round in 0..150 {
        let len = rng.random_range(0..2000usize);
        let mut bytes: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        if round % 3 == 0 && bytes.len() > 10 {
            bytes[0] = 22;
            bytes[1] = 3;
            bytes[2] = 3;
            let body = u16::try_from(bytes.len() - 5).unwrap().to_be_bytes();
            bytes[3..5].copy_from_slice(&body);
            bytes[5] = 2;
        }
        let (client, mut far) = duplex(1 << 16);
        tokio::spawn(async move {
            let mut sink = vec![0u8; 8192];
            let _ = far.read(&mut sink).await;
            let _ = far.write_all(&bytes).await;
            let _ = far.shutdown().await;
        });
        let conn = connector(&server, ClientFingerprint::Chrome, round % 2 == 0);
        let result =
            tokio::time::timeout(Duration::from_secs(5), conn.connect(Box::new(client), ""))
                .await
                .expect("hung on garbage");
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn leaving_the_record_layer_between_records_keeps_every_byte() {
    let server = Arc::new(MockReality::new());
    let mut conn = dial(
        server.clone(),
        &connector(&server, ClientFingerprint::Chrome, false),
    )
    .await
    .unwrap();
    let parts = [vec![1u8; 100], vec![2u8; 700], vec![3u8; 31]];
    for part in &parts {
        conn.write_all(part).await.unwrap();
        conn.flush().await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut first = vec![0u8; 100];
    conn.read_exact(&mut first).await.unwrap();
    assert_eq!(first, parts[0]);
    assert!(conn.at_record_boundary());
    assert!(!conn.has_pending_plaintext());

    let mut head = vec![0u8; 10];
    conn.read_exact(&mut head).await.unwrap();
    assert!(conn.has_pending_plaintext());
    let mut rest_of_second = Vec::new();
    conn.drain_plaintext(&mut rest_of_second);
    assert_eq!([head, rest_of_second].concat(), parts[1]);

    conn.shutdown().await.unwrap();
    let mut raw = Vec::new();
    conn.raw_mut().read_to_end(&mut raw).await.unwrap();
    let mut lens = Vec::new();
    let mut at = 0;
    while at + 5 <= raw.len() {
        assert_eq!(raw[at], 23);
        let len = usize::from(u16::from_be_bytes([raw[at + 3], raw[at + 4]]));
        lens.push(len);
        at += 5 + len;
    }
    assert_eq!(at, raw.len());
    assert_eq!(lens, [31 + 1 + 16, 2 + 1 + 16]);
}

#[tokio::test]
async fn the_cover_site_gets_a_browser_visit_and_the_caller_an_error() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["cover.test"]);
    let config = server_config(
        &leaf,
        &ServerSpec {
            tls13_only: true,
            ..ServerSpec::default()
        },
    );
    let server = MockReality::new();
    for (trusted, expect_visit) in [(true, true), (false, false)] {
        let (client, far) = duplex(1 << 20);
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let config = config.clone();
        tokio::spawn(async move {
            let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(config).accept(far).await else {
                let _ = seen_tx.send(Vec::new());
                return;
            };
            let mut preface = vec![0u8; 24];
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut preface))
                .await
                .map(|r| r.map(|_| 24).unwrap_or(0))
                .unwrap_or(0);
            preface.truncate(n);
            let _ = seen_tx.send(preface);
        });
        let trust = if trusted {
            ca.trust()
        } else {
            Ca::new().trust()
        };
        let connector = connector_with(
            &server,
            ClientFingerprint::Chrome,
            true,
            server.short_id,
            trust,
        );
        let err = connector.connect(Box::new(client), "").await.err().unwrap();
        if trusted {
            assert!(
                err.to_string().contains("REALITY authentication failed"),
                "{err}"
            );
        } else {
            assert!(
                err.to_string().contains("certificate verify failed"),
                "{err}"
            );
        }
        let preface = tokio::time::timeout(Duration::from_secs(8), seen_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            preface == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            expect_visit,
            "trusted={trusted}"
        );
    }
}

#[test]
fn config_errors_do_not_need_a_network() {
    let server = MockReality::new();
    let mut opts = TlsOptions {
        reality: Some(RealityOptions {
            public_key: server.public_key,
            short_id: [0; 8],
            support_x25519mlkem768: false,
            client_version: [1, 8, 2],
            mldsa65_verify: None,
        }),
        certificate: Some("x".into()),
        private_key: Some("y".into()),
        ..TlsOptions::default()
    };
    let trust = TrustStore::from_parts(Vec::new(), b"", Vec::new());
    assert!(matches!(
        TlsConnector::new(opts.clone(), trust.clone()),
        Err(TlsError::Config(_))
    ));
    opts.certificate = None;
    opts.private_key = None;
    let connector = TlsConnector::new(opts, trust).unwrap();
    assert_eq!(connector.backend(), crate::Backend::Reality);
}
