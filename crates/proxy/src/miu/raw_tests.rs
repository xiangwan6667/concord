#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "protocol tests use generated certificates and loopback peers"
)]

use super::*;
use concord_common::Initiator;
use concord_config::proxy::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::{TlsConnector, TlsOptions, TrustStore};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn server_config() -> Arc<rustls::ServerConfig> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )
        .unwrap(),
    )
}

fn connector() -> TlsConnector {
    TlsConnector::new(
        TlsOptions {
            skip_cert_verify: true,
            ..TlsOptions::default()
        },
        TrustStore::new(b"", Vec::new()),
    )
    .unwrap()
}

#[tokio::test]
async fn raw_header_must_end_its_outer_tls_record() {
    let (client, peer) = tokio::io::duplex(65536);
    let accept = tokio_rustls::TlsAcceptor::from(server_config());
    let server = tokio::spawn(async move {
        let mut tls = accept.accept(peer).await.unwrap();
        let mut packet = Vec::new();
        frame(&mut packet, 6, &1_u32.to_be_bytes()).unwrap();
        frame(&mut packet, 5, b"not a raw boundary").unwrap();
        tls.write_all(&packet).await.unwrap();
        tls.flush().await.unwrap();
    });
    let tls = connector()
        .connect(Box::new(client), "localhost")
        .await
        .unwrap();
    let pool = Pool::new(
        30,
        padding::derive(&[7; 32]).unwrap(),
        concord_common::Tasks::default(),
    );
    let mut stream = MiuStream::new(IdleLane::tls(tls), pool.clone(), 0);
    let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
    assert!(error.to_string().contains("record boundary"));
    drop(stream);
    assert!(pool.take().1.is_none());
    server.await.unwrap();
}

#[tokio::test]
#[ignore = "requires the Go Miu peer used by go_peer_carries_tcp_udp_and_reality"]
async fn go_peer_carries_inner_tls13_over_raw_in_both_directions() {
    let tls: u16 = std::env::var("CONCORD_MIU_TLS").unwrap().parse().unwrap();
    let reality: u16 = std::env::var("CONCORD_MIU_REALITY")
        .unwrap()
        .parse()
        .unwrap();
    for (port, hybrid, fingerprint) in [
        (tls, None, ""),
        (tls, None, "chrome"),
        (reality, Some(true), "chrome"),
        (reality, Some(false), "chrome"),
    ] {
        let mut node = json!({"name":"raw-peer", "type":"miu", "server":"127.0.0.1", "port":port,
            "psk":"miu-test-psk-alpha-2026", "skip-cert-verify":true, "sni":"localhost",
            "client-fingerprint":fingerprint});
        if let Some(enabled) = hybrid {
            node["reality-opts"] = json!({
                "public-key":std::env::var("CONCORD_MIU_PUBLIC").unwrap(),
                "short-id":"0123456789abcdef", "support-x25519mlkem768":enabled,
            });
        }
        let ProxyParse::Ok(def) =
            parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap()
        else {
            panic!("Miu config did not parse");
        };
        let outbound =
            crate::build_outbound(&def, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config());
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(socket).await.unwrap();
                let (mut read, mut write) = tokio::io::split(&mut tls);
                tokio::io::copy(&mut read, &mut write).await.unwrap();
                write.shutdown().await.unwrap();
            }
        });
        let env = crate::testing::test_env();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        for _ in 0..2 {
            let stream = outbound
                .connect(&cx, &Address::new("localhost", address.port()))
                .await
                .unwrap();
            let mut tls = connector().connect(stream, "localhost").await.unwrap();
            let payload = vec![0x15; 256 * 1024];
            let (mut read, mut write) = tokio::io::split(&mut tls);
            let sent = async {
                write.write_all(&payload).await?;
                write.shutdown().await
            };
            let received = async {
                let mut received = Vec::new();
                read.read_to_end(&mut received).await?;
                Ok::<_, std::io::Error>(received)
            };
            let (_, received) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::try_join!(sent, received)
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(received, vec![0x15; 256 * 1024]);
        }
        echo.await.unwrap();
        outbound.reset_sessions();
    }
}
