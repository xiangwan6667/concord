use std::io;
use std::sync::{Arc, Mutex};

use concord_common::sync::lock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::support::{Ca, ServerSpec, echo_server, server_config};
use crate::{DecoyHandshake, TlsOptions};

const SESSION_ID_OFFSET: usize = 39;

fn options() -> TlsOptions {
    TlsOptions {
        server_name: Some("decoy.test".into()),
        alpn: vec!["http/1.1".into()],
        ..TlsOptions::default()
    }
}

#[tokio::test]
async fn decoy_handshake_uses_the_sealed_session_id_and_returns_the_raw_stream() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["decoy.test"]);
    let spec = ServerSpec {
        alpn: vec![b"http/1.1"],
        tls13_only: true,
        ..ServerSpec::default()
    };
    let (client, _server) = echo_server(server_config(&leaf, &spec));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_in = seen.clone();
    let sealer = move |hello: &[u8]| -> io::Result<[u8; 32]> {
        let slot = hello
            .get(SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32)
            .unwrap();
        assert_eq!(slot, [0u8; 32]);
        *lock(&seen_in) = hello.to_vec();
        Ok([0x5a; 32])
    };
    let handshake = DecoyHandshake::new(&options(), ca.trust(), false).unwrap();
    let (mut raw, alpn) = handshake.run(client, "ignored", &sealer).await.unwrap();
    assert_eq!(alpn.as_deref(), Some(b"http/1.1".as_slice()));
    assert_eq!(lock(&seen).first().copied(), Some(1));
    raw.write_all(b"\x17\x03\x03\x00\x01x").await.unwrap();
    raw.flush().await.unwrap();
    let mut byte = [0u8; 1];
    let _ = raw.read(&mut byte).await;
}

#[tokio::test]
async fn decoy_handshake_verifies_the_certificate() {
    let ca = Ca::new();
    let other = Ca::new();
    let leaf = other.leaf(&["decoy.test"]);
    let spec = ServerSpec {
        tls13_only: true,
        ..ServerSpec::default()
    };
    let (client, _server) = echo_server(server_config(&leaf, &spec));
    let handshake = DecoyHandshake::new(&options(), ca.trust(), false).unwrap();
    let sealer = |_: &[u8]| -> io::Result<[u8; 32]> { Ok([1; 32]) };
    assert!(handshake.run(client, "ignored", &sealer).await.is_err());
}

#[tokio::test]
async fn tls12_only_caps_the_version() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["decoy.test"]);
    let (client, _server) = echo_server(server_config(&leaf, &ServerSpec::default()));
    let connector = crate::TlsConnector::tls12_only(options(), ca.trust()).unwrap();
    let conn = connector.connect(client, "ignored").await.unwrap();
    assert!(!conn.is_tls13());
}

#[tokio::test]
async fn shadowtls_ws_chrome_hello_keeps_alps_with_http1_alpn() {
    let (near, mut far) = tokio::io::duplex(1 << 20);
    let handshake = DecoyHandshake::new(
        &TlsOptions {
            client_fingerprint: Some(crate::ClientFingerprint::Chrome),
            ..options()
        },
        Ca::new().trust(),
        true,
    )
    .unwrap();
    let task = tokio::spawn(async move {
        let sealer = |_: &[u8]| -> io::Result<[u8; 32]> { Ok([1; 32]) };
        let _ = handshake.run(Box::new(near), "", &sealer).await;
    });
    let mut head = [0; 5];
    far.read_exact(&mut head).await.unwrap();
    let mut hello = vec![0; usize::from(u16::from_be_bytes([head[3], head[4]]))];
    far.read_exact(&mut hello).await.unwrap();
    let parsed = super::hello::parse_hello("shadowtls-ws", &hello);
    assert_eq!(parsed.alpn, ["http/1.1"]);
    assert!(parsed.extensions.iter().any(|ext| ext == "44cd"));
    assert!(
        hello
            .windows(9)
            .any(|bytes| bytes == [0x44, 0xcd, 0, 5, 0, 3, 2, b'h', b'2'])
    );
    drop(far);
    task.await.unwrap();
}
