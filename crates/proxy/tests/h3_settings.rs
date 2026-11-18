use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncReadExt;

fn endpoints() -> (quinn::Endpoint, quinn::Endpoint, SocketAddr) {
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = pair.cert.der().clone();
    let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(pair.signing_key.serialize_der()).into(),
    )
    .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
    )));
    (server, client, addr)
}

async fn capture_settings(datagrams: bool, legacy: Option<bool>) -> Vec<u8> {
    capture_settings_mode(datagrams, legacy, false).await
}

async fn capture_settings_mode(datagrams: bool, legacy: Option<bool>, minimal: bool) -> Vec<u8> {
    let (server, client, addr) = endpoints();
    let received = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        loop {
            let mut stream = conn.accept_uni().await.unwrap();
            if stream.read_u8().await.unwrap() != 0 {
                continue;
            }
            let mut frame = [0; 2];
            stream.read_exact(&mut frame).await.unwrap();
            assert_eq!(frame[0], 4);
            assert!(frame[1] < 64);
            let mut result = vec![0, frame[0], frame[1]];
            let mut payload = vec![0; usize::from(frame[1])];
            stream.read_exact(&mut payload).await.unwrap();
            result.extend_from_slice(&payload);
            return result;
        }
    });
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
    let mut builder = h3::client::builder();
    builder.send_grease(false).enable_datagram(datagrams);
    if minimal {
        builder
            .omit_zero_settings(true)
            .max_field_section_size(10 << 20);
    }
    if let Some(legacy) = legacy {
        builder.enable_legacy_datagram(legacy);
    }
    let (_driver, _requests) = builder
        .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), received)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn h3_settings_without_legacy_match_unpatched_upstream_bytes() {
    for (datagrams, golden) in [
        (
            false,
            "00041706ffffffffffffffff0800ab603742003300ab60374300",
        ),
        (true, "00041706ffffffffffffffff0800ab603742003301ab60374300"),
    ] {
        let expected = hex::decode(golden).unwrap();
        for legacy in [None, Some(false)] {
            assert_eq!(capture_settings(datagrams, legacy).await, expected);
        }
    }
}

#[tokio::test]
async fn h3_settings_legacy_switch_adds_the_exact_warp_setting_bytes() {
    let expected =
        hex::decode("00041a06ffffffffffffffff0800ab603742003301ab60374300427601").unwrap();
    assert_eq!(capture_settings(true, Some(true)).await, expected);
}

#[tokio::test]
async fn h3_cf_connect_ip_is_decoded_from_a_real_request_stream() {
    let (server, client, addr) = endpoints();
    let serving = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut h3 =
            h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                .await
                .unwrap();
        let resolver = h3.accept().await.unwrap().unwrap();
        let (request, mut stream) = resolver.resolve_request().await.unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri(), "https://cloudflareaccess.com/");
        assert_eq!(
            request
                .extensions()
                .get::<h3::ext::Protocol>()
                .unwrap()
                .as_str(),
            "cf-connect-ip"
        );
        assert_eq!(request.headers()["capsule-protocol"], "?1");
        stream.send_response(http::Response::new(())).await.unwrap();
        stream.finish().await.unwrap();
        // Keep the endpoint alive until the response is acknowledged by the client.
        while let Some(mut data) = stream.recv_data().await.unwrap() {
            use bytes::Buf;
            data.advance(data.remaining());
        }
    });
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut driver, mut requests) = h3::client::builder()
        .enable_extended_connect(true)
        .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    let drive = tokio::spawn(async move {
        driver.wait_idle().await;
    });
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://cloudflareaccess.com/")
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::CF_CONNECT_IP);
    let mut stream = requests.send_request(request).await.unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    stream.finish().await.unwrap();
    serving.await.unwrap();
    drive.abort();
    assert_eq!(
        "connect-udp".parse::<h3::ext::Protocol>().ok(),
        Some(h3::ext::Protocol::CONNECT_UDP)
    );
    assert_eq!(
        "webtransport".parse::<h3::ext::Protocol>().ok(),
        Some(h3::ext::Protocol::WEB_TRANSPORT)
    );
    assert_eq!(
        "cf-connect-ip".parse::<h3::ext::Protocol>().ok(),
        Some(h3::ext::Protocol::CF_CONNECT_IP)
    );
    assert!("unknown".parse::<h3::ext::Protocol>().is_err());
}

async fn read_varint(read: &mut quinn::RecvStream) -> u64 {
    let first = read.read_u8().await.unwrap();
    let mut value = u64::from(first & 63);
    for _ in 1..(1usize << (first >> 6)) {
        value = (value << 8) | u64::from(read.read_u8().await.unwrap());
    }
    value
}

async fn capture_request_headers(
    method: http::Method,
    protocol: Option<h3::ext::Protocol>,
) -> Vec<u8> {
    let (server, client, addr) = endpoints();
    let serving = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (_send, mut recv) = conn.accept_bi().await.unwrap();
        assert_eq!(read_varint(&mut recv).await, 1);
        let len = usize::try_from(read_varint(&mut recv).await).unwrap();
        let mut headers = vec![0; len];
        recv.read_exact(&mut headers).await.unwrap();
        headers
    });
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
    let (_driver, mut sender) = h3::client::builder()
        .send_grease(false)
        .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    let mut request = http::Request::builder()
        .method(method)
        .uri("https://cloudflareaccess.com/")
        .body(())
        .unwrap();
    if let Some(protocol) = protocol {
        request.extensions_mut().insert(protocol);
    }
    let _stream = sender.send_request(request).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), serving)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn h3_connect_qpack_omits_scheme_and_path_while_other_requests_match_upstream() {
    for (method, protocol, golden) in [
        (
            http::Method::CONNECT,
            None,
            "0000cf508e2507b649681d8519085421721e9f",
        ),
        (
            http::Method::POST,
            None,
            "0000d4d7508e2507b649681d8519085421721e9fc1",
        ),
        (
            http::Method::CONNECT,
            Some(h3::ext::Protocol::CF_CONNECT_IP),
            "0000cfd7508e2507b649681d8519085421721e9fc12f00b95d8749c87a3f8924ab10f55452256357",
        ),
    ] {
        assert_eq!(
            capture_request_headers(method, protocol).await,
            hex::decode(golden).unwrap()
        );
    }
}

#[tokio::test]
async fn h3_settings_omit_disabled_extensions_only_when_opted_in() {
    // quic-go 2548683b http3/client.go:33,123-127 and frames.go:263-296.
    for (ip, golden) in [
        (true, "00040a0680a000003301427601"),
        (false, "0004050680a00000"),
    ] {
        assert_eq!(
            capture_settings_mode(ip, Some(ip), true).await,
            hex::decode(golden).unwrap()
        );
    }
}
