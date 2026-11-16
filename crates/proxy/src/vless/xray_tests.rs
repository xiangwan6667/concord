#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "tests connect to explicitly configured local official Xray peers"
)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use concord_common::Address;
use concord_tls::fingerprints::ClientFingerprint;
use concord_tls::{RealityOptions, TlsConnector, TlsOptions, TrustStore};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires CONCORD_XRAY_REALITY_PEERS from the official Xray harness"]
async fn official_xray_checks_reality_authentication_and_versions() {
    let fixtures: Vec<serde_json::Value> = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("CONCORD_XRAY_REALITY_PEERS").unwrap()).unwrap(),
    )
    .unwrap();
    for fixture in fixtures {
        let mut reality = RealityOptions::parse(
            fixture["public"].as_str().unwrap(),
            fixture["short_id"].as_str().unwrap(),
            fixture["hybrid"].as_bool().unwrap(),
        )
        .unwrap();
        reality.client_version = if fixture["version"].as_bool().unwrap() {
            [26, 3, 27]
        } else {
            [1, 8, 2]
        };
        if let Some(key) = fixture["mldsa"].as_str() {
            reality.mldsa65_verify = Some(URL_SAFE_NO_PAD.decode(key).unwrap());
        }
        let connector = TlsConnector::new(
            TlsOptions {
                server_name: Some("localhost".into()),
                client_fingerprint: Some(ClientFingerprint::Chrome),
                reality: Some(reality),
                ..TlsOptions::default()
            },
            TrustStore::new(b"", Vec::new()),
        )
        .unwrap();
        let socket =
            tokio::net::TcpStream::connect(("127.0.0.1", fixture["port"].as_u64().unwrap() as u16))
                .await
                .unwrap();
        let connected = tokio::time::timeout(
            Duration::from_secs(25),
            connector.connect(Box::new(socket), "localhost"),
        )
        .await
        .unwrap();
        if !fixture["success"].as_bool().unwrap() {
            assert!(connected.is_err(), "{}", fixture["name"]);
        } else {
            let tls = connected.unwrap_or_else(|error| panic!("{} {error}", fixture["name"]));
            let mut user = [0; 16];
            user[15] = 1;
            let header = super::stream::request_header(
                &user,
                None,
                1,
                &Address::new("127.0.0.1", fixture["echo"].as_u64().unwrap() as u16),
            )
            .unwrap();
            let mut stream =
                super::stream::ResponseSkip::new(crate::lazy::HeadFirst::new(tls, header));
            stream.write_all(b"official Xray echo").await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0; 18];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&response, b"official Xray echo");
        }
        eprintln!("official Xray {}", fixture["name"]);
    }
}
