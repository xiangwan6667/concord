use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use concord_common::intercept::{ConnMark, Offer};
use concord_common::sync::lock;
use concord_common::{Address, InboundKind};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::testing::{
    Client, Handler, Reply, Rig, Service, Wire, eventually, flow, flow_of, full_body, offer_on,
    rig_for, start_server, start_service,
};

fn echo() -> Handler {
    Arc::new(|seen| {
        let text = |name: &str| {
            seen.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let reply = match seen.path.as_str() {
            "/api" => Reply::ok(r#"{"ad":true,"items":[]}"#),
            _ => Reply::ok(&format!(
                "{}|{}|{}|{}",
                seen.host,
                seen.path,
                text("x-added"),
                String::from_utf8_lossy(&seen.body)
            )),
        };
        reply.with("X-Upstream", "yes")
    })
}

async fn rig(handler: Handler, tls: bool, alpn: &[&str]) -> (crate::testing::TestServer, Rig) {
    let server = start_server(tls, alpn, handler).await;
    let rig = rig_for(&server, None);
    (server, rig)
}

#[tokio::test]
async fn rewrites_decrypted_requests() {
    let (server, rig) = rig(echo(), true, &["http/1.1"]).await;
    let errors = rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "url-rewrite": [
            r"^https://example\.test/ad _ reject",
            r"^https://example\.test/go https://elsewhere.test/ 302",
            r"^https://example\.test/old/(.*) https://example.test/new/$1",
        ],
        "header-rewrite": [
            r"http-request ^https://example\.test header-add X-Added yes",
            r"http-response ^https://example\.test header-del X-Upstream",
        ],
        "body-rewrite": [r#"http-response ^https://example\.test/api "\"ad\":true" "\"ad\":false""#],
        "map-local": [r#"^https://example\.test/local data-type=text data="{}" header="Content-Type:application/json""#],
    }));
    assert!(errors.is_empty(), "{errors:?}");
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();

    let answer = client.get("/ad").await;
    assert_eq!((answer.status.as_u16(), answer.body.len()), (404, 0));
    let answer = client.get("/go").await;
    assert_eq!(
        (answer.status.as_u16(), answer.header("location").as_str()),
        (302, "https://elsewhere.test/")
    );
    let answer = client.get("/local").await;
    assert_eq!(
        (
            answer.status.as_u16(),
            answer.text(),
            answer.header("content-type")
        ),
        (200, "{}".to_string(), "application/json".to_string())
    );
    assert_eq!(
        rig.dialer.dialed().len(),
        1,
        "only the dial made before the handshake"
    );

    let answer = client.get("/old/x?y=1").await;
    assert_eq!(answer.text(), "example.test|/new/x?y=1|yes|");
    assert_eq!(answer.header("x-upstream"), "");
    let answer = client.get("/api").await;
    assert_eq!(answer.text(), r#"{"ad":false,"items":[]}"#);
    assert_eq!(
        answer.header("content-length"),
        answer.body.len().to_string()
    );
    let request = client.request("POST", "/echo", &[], "payload");
    assert_eq!(
        client.send(request).await.unwrap().text(),
        "example.test|/echo|yes|payload"
    );
    assert_eq!(rig.dialer.dialed(), vec![("example.test".to_string(), 443)]);
    assert_eq!(
        server.connections.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn rewrites_json_bodies_with_jq() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    let errors = rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "body-rewrite": [
            r"http-response-jq ^https://example\.test/api '.ad = false | del(.items)'",
            r"http-request-jq ^https://example\.test/echo '.a = 2'",
            r"http-response-jq ^https://example\.test/echo '.x = 1'",
            r"http-response-jq ^https://example\.test/bad '.a = '",
        ],
    }));
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("invalid jq expression"), "{errors:?}");
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let answer = client.get("/api").await;
    assert_eq!(answer.text(), r#"{"ad":false}"#);
    assert_eq!(
        answer.header("content-length"),
        answer.body.len().to_string()
    );
    let request = client.request("POST", "/echo", &[], r#"{"a":1}"#);
    assert_eq!(
        client.send(request).await.unwrap().text(),
        r#"example.test|/echo||{"a":2}"#,
        "the request body is rewritten, the echo that is not JSON is kept"
    );
}

#[tokio::test]
async fn url_and_header_rejects_by_the_request_head() {
    let config = json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "h2": true,
        "url-rewrite": [
            r#"^https?://example\.test/d "\r\nUser-Agent: httpdns[^\r\n]*\r\n" url-and-header reject-dict"#,
            r"^https?://example\.test/d ^POST\s url-and-header reject",
            r"^https?://example\.test/d \r\nHost:\sexample\.test\r\n url-and-header reject-array",
        ],
    });
    let (_plain, plain) = rig(echo(), false, &[]).await;
    assert!(plain.config(config.clone()).is_empty());
    let mut client = Client::plain(&plain, "example.test", 80).await;
    let request = client.request("GET", "/d", &[("User-Agent", "httpdns/2.1")], "");
    assert_eq!(client.send(request).await.unwrap().text(), "{}");
    let request = client.request("POST", "/d", &[("User-Agent", "app/1")], "x");
    assert_eq!(client.send(request).await.unwrap().status.as_u16(), 404);
    let request = client.request("GET", "/d?x", &[("User-Agent", "Httpdns/2.1")], "");
    assert_eq!(
        client.send(request).await.unwrap().text(),
        "[]",
        "matching is case-sensitive, so only the Host line matches"
    );

    let (_tls, tls) = rig(echo(), true, &["h2"]).await;
    assert!(tls.config(config).is_empty());
    let mut client = Client::tls(&tls, "example.test", 443, &["h2"])
        .await
        .unwrap();
    let request = client.request("GET", "/d", &[("User-Agent", "httpdns/2.1")], "");
    assert_eq!(client.send(request).await.unwrap().text(), "{}");
    let request = client.request("GET", "/d", &[("User-Agent", "app/1")], "");
    assert_eq!(
        client.send(request).await.unwrap().text(),
        "[]",
        "an HTTP/2 request's authority is its Host line"
    );
}

#[tokio::test]
async fn rewrites_follow_the_status_and_both_heads() {
    let handler: Handler = Arc::new(|seen| {
        let reply = match seen.path.as_str() {
            "/gone" => Reply {
                status: 404,
                ..Reply::ok("")
            },
            _ => Reply::ok(r#"{"ad":true}"#),
        };
        reply.with("X-Upstream", "yes")
    });
    let (_server, rig) = rig(handler, true, &["http/1.1"]).await;
    let errors = rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "header-rewrite": [
            r"http-response ^https://example\.test/ response-head ^HTTP/\S+\s200\s header-add X-Ok yes",
            r"http-response ^https://example\.test/ request-head (\r\n)X-Want:\sit\r\n header-add X-Wanted yes",
        ],
        "body-rewrite": [r"http-response-jq ^https://example\.test/ request-head ^POST\s '.ad = false'"],
    }));
    assert!(errors.is_empty(), "{errors:?}");
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let answer = client.get("/api").await;
    assert_eq!(
        (
            answer.header("x-ok"),
            answer.header("x-wanted"),
            answer.text()
        ),
        (
            "yes".to_string(),
            String::new(),
            r#"{"ad":true}"#.to_string()
        )
    );
    let answer = client.get("/gone").await;
    assert_eq!(
        (answer.status.as_u16(), answer.header("x-ok")),
        (404, String::new())
    );
    let request = client.request("POST", "/api", &[("X-Want", "it")], "x");
    let answer = client.send(request).await.unwrap();
    assert_eq!(
        (answer.header("x-wanted"), answer.text()),
        ("yes".to_string(), r#"{"ad":false}"#.to_string())
    );
    assert_eq!(
        answer.header("content-length"),
        answer.body.len().to_string()
    );
}

#[tokio::test]
async fn a_whole_head_rewrite_changes_the_head_but_not_the_host() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    let errors = rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "header-rewrite": [
            r#"http-request ^https://example\.test/old/ header-text-replace "^GET /old/(\S*) " "GET /new/${1} ""#,
            r#"http-request ^https://example\.test/ header-text-replace "(\r\n)User-Agent:[^\r]*(\r\n)" "${1}X-Added: from-ua${2}""#,
            r#"http-request ^https://example\.test/host header-text-replace "Host: example\.test" "Host: other.test""#,
            r#"http-response ^https://example\.test/r header-text-replace "(\r\n)X-Upstream: yes(\r\n)" "${1}Cache-Control: no-store${2}""#,
            r#"http-response ^https://example\.test/teapot header-text-replace "^(\S+) 200 OK" "${1} 418 I'm a teapot""#,
            r#"http-response ^https://example\.test/broken header-text-replace "(\r\n)X-Upstream" "${1}Bad Name""#,
        ],
    }));
    assert!(errors.is_empty(), "{errors:?}");
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(
        client.get("/old/x?y=1").await.text(),
        "example.test|/new/x?y=1||"
    );
    let request = client.request("GET", "/ua", &[("User-Agent", "app/1")], "");
    assert_eq!(
        client.send(request).await.unwrap().text(),
        "example.test|/ua|from-ua|"
    );
    assert_eq!(
        client.get("/host").await.text(),
        "example.test|/host||",
        "the request keeps going to its host"
    );
    let answer = client.get("/r").await;
    assert_eq!(
        (
            answer.header("x-upstream"),
            answer.header("cache-control"),
            answer.text()
        ),
        (
            String::new(),
            "no-store".to_string(),
            "example.test|/r||".to_string()
        )
    );
    let answer = client.get("/teapot").await;
    assert_eq!(
        (answer.status.as_u16(), answer.text()),
        (418, "example.test|/teapot||".to_string())
    );
    assert_eq!(
        client.get("/broken").await.header("x-upstream"),
        "yes",
        "a rewrite that leaves no head keeps the one it had"
    );
}

#[tokio::test]
async fn map_local_and_request_body_mocks_read_the_request_head() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    let errors = rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "map-local": [r#"^https://example\.test/m$ request-head ^POST\s data-type=text data="{}""#],
        "request-body-mock": [
            r#"^https://example\.test/mock data-type=text data="mocked" header="Content-Type:application/json""#,
            r#"^https://example\.test/only request-head (\r\n)X-Want:\sit\r\n data-type=base64 data="aGk=""#,
        ],
        "body-rewrite": [r"http-request ^https://example\.test/mock mocked changed"],
    }));
    assert!(errors.is_empty(), "{errors:?}");
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let request = client.request("POST", "/m", &[], "x");
    assert_eq!(client.send(request).await.unwrap().text(), "{}");
    assert_eq!(client.get("/m").await.text(), "example.test|/m||");
    assert_eq!(
        client.get("/mock").await.text(),
        "example.test|/mock||changed",
        "a request without a body goes with the mock, which later rules see"
    );
    let request = client.request("POST", "/mock", &[], "original");
    assert_eq!(
        client.send(request).await.unwrap().text(),
        "example.test|/mock||changed"
    );
    let request = client.request("POST", "/only", &[("X-Want", "it")], "original");
    assert_eq!(
        client.send(request).await.unwrap().text(),
        "example.test|/only||hi"
    );
    let request = client.request("POST", "/only", &[], "original");
    assert_eq!(
        client.send(request).await.unwrap().text(),
        "example.test|/only||original"
    );
}

#[tokio::test]
async fn skips_verifying_only_the_hosts_listed_for_it() {
    let wire = hello("example.test", &["http/1.1"]);
    for (listed, decrypted) in [("example.test", true), ("other.test", false)] {
        let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
        let errors = rig.config(json!({
            "enable": true,
            "hostname": ["example.test", "other.test"],
            "skip-server-cert-verify-hostname": [listed],
        }));
        assert!(errors.is_empty(), "{errors:?}");
        if decrypted {
            let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
                .await
                .unwrap();
            assert_eq!(client.get("/p").await.text(), "example.test|/p||");
        } else {
            assert_eq!(
                declined(&rig, flow("example.test", 443), &wire).await,
                wire,
                "the self-signed server of a host not listed still fails verification"
            );
        }
    }
}

#[tokio::test]
async fn decrypts_only_for_the_clients_listed() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "url-rewrite": [r"^http://example\.test/ad _ reject"],
        "client-source-address": ["-127.0.0.1, 0.0.0.0/0"],
    }));
    let engine = rig.mitm.engine().unwrap();
    assert!(!engine.match_tcp(&flow("example.test", 443)));
    assert!(!engine.match_tcp(&flow("example.test", 80)));
    let mut lan = flow("example.test", 443);
    lan.meta.src = "192.168.1.9:50000".parse().unwrap();
    assert!(engine.match_tcp(&lan));
    let errors = rig.config(json!({"enable": true, "client-source-address": ["lan"]}));
    assert_eq!(errors.len(), 1, "{errors:?}");
}

#[tokio::test]
async fn dials_the_host_a_rewrite_moves_to() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "url-rewrite": [r"^https://example\.test/(.*) https://other.test:8443/$1"],
    }));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(client.get("/p").await.text(), "other.test:8443|/p||");
    assert_eq!(rig.dialer.dialed()[1], ("other.test".to_string(), 8443));
}

#[tokio::test]
async fn decodes_a_gzip_body_it_rewrites() {
    let handler: Handler = Arc::new(|seen| {
        assert_eq!(seen.headers.get("accept-encoding").unwrap(), "identity");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"hello ad").unwrap();
        Reply {
            status: 200,
            headers: vec![("Content-Encoding".into(), "gzip".into())],
            body: gz.finish().unwrap(),
        }
    });
    let (_server, rig) = rig(handler, true, &["http/1.1"]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "body-rewrite": [r"http-response ^https://example\.test/ ad world"],
    }));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let request = client.request("GET", "/", &[("Accept-Encoding", "gzip")], "");
    let answer = client.send(request).await.unwrap();
    assert_eq!(
        (
            answer.text().as_str(),
            answer.header("content-encoding").as_str()
        ),
        ("hello world", "")
    );
}

#[tokio::test]
async fn relays_a_websocket() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(
        json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true}),
    );
    let (near, offer) = offer_on(rig.mitm.interceptor(), flow("example.test", 443));
    let name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
    let connector =
        tokio_rustls::TlsConnector::from(crate::testing::client_config(&rig.root, &["http/1.1"]));
    let mut tls = connector.connect(name, near).await.unwrap();
    tls.write_all(b"GET /socket HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tls.read_u8().await.unwrap());
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));
    tls.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    tls.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    drop(tls);
    let outcome = tokio::time::timeout(Duration::from_secs(10), offer)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(outcome, Offer::Taken));
}

#[tokio::test]
async fn serves_plain_http() {
    let (_server, rig) = rig(echo(), false, &[]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "url-rewrite": [r"^http://example\.test/ad _ reject-dict"],
    }));
    let mut client = Client::plain(&rig, "example.test", 80).await;
    let answer = client.get("/ad").await;
    assert_eq!(
        (answer.status.as_u16(), answer.text().as_str()),
        (200, "{}")
    );
    assert_eq!(client.get("/x").await.text(), "example.test|/x||");
}

async fn declined(
    rig: &Rig,
    flow: concord_common::intercept::InterceptFlow,
    wire: &[u8],
) -> Vec<u8> {
    let (mut near, offer) = offer_on(rig.mitm.interceptor(), flow);
    near.write_all(wire).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(10), offer)
        .await
        .unwrap()
        .unwrap()
    {
        Offer::Declined {
            mut stream,
            mut head,
        } => {
            let mut rest = vec![0u8; wire.len()];
            let read = tokio::time::timeout(
                Duration::from_millis(200),
                tokio::io::AsyncReadExt::read(&mut stream, &mut rest),
            )
            .await;
            if let Ok(Ok(read)) = read {
                head.extend_from_slice(&rest[..read]);
            }
            head
        }
        Offer::Taken => panic!("the connection was taken"),
    }
}

pub(crate) fn hello(name: &str, alpn: &[&str]) -> Vec<u8> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    let mut conn = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from(name.to_string()).unwrap(),
    )
    .unwrap();
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    out
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

#[tokio::test]
async fn leaves_what_it_cannot_decrypt() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(
        json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true}),
    );

    let unlisted = hello("unlisted.test", &["http/1.1"]);
    assert_eq!(
        declined(&rig, flow("unlisted.test", 443), &unlisted).await,
        unlisted
    );
    let listed = flow("example.test", 443);
    let h2_only = hello("example.test", &["h2"]);
    assert_eq!(declined(&rig, listed.clone(), &h2_only).await, h2_only);
    let ssh = b"SSH-2.0-OpenSSH_9.9\r\n".to_vec();
    assert!(declined(&rig, listed, &ssh).await.starts_with(b"SSH-2.0"));
    assert!(
        rig.dialer.dialed().is_empty(),
        "no dial for a connection that is left alone"
    );
}

#[tokio::test]
async fn leaves_a_connection_its_server_fails() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(
        json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true}),
    );
    rig.dialer.reject("example.test");
    let wire = hello("example.test", &["http/1.1"]);
    assert_eq!(declined(&rig, flow("example.test", 443), &wire).await, wire);
    assert_eq!(rig.dialer.marks().len(), 0);

    let (server, rig) = self::rig(echo(), true, &["http/1.1"]).await;
    rig.config(json!({"enable": true, "hostname": ["example.test"]}));
    let wire = hello("example.test", &["http/1.1"]);
    assert_eq!(
        declined(&rig, flow("example.test", 443), &wire).await,
        wire,
        "the self-signed server fails verification"
    );
    drop(server);
}

#[tokio::test]
async fn reads_the_server_name_when_only_the_address_is_known() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(
        json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true}),
    );
    let address = Address::new("203.0.113.9", 443);
    let flow = flow_of(InboundKind::Tun, address);
    let engine = rig.mitm.engine().unwrap();
    assert!(
        !engine.match_tcp(&flow_of(
            InboundKind::Tun,
            Address::new("203.0.113.9", 8443)
        )),
        "a bare address off port 443 is not offered"
    );
    let mut client = Client::tls_flow(&rig, flow, "example.test", &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(client.get("/p").await.text(), "example.test|/p||");
    let (dialed, _) = lock(&rig.dialer.flows)[0].clone();
    assert_eq!(
        (dialed.dst_ip, dialed.host.as_deref(), dialed.sniffed),
        (
            Some("203.0.113.9".parse().unwrap()),
            Some("example.test"),
            true
        ),
        "the address is dialed with the name the client sent"
    );
    let unlisted = flow_of(InboundKind::Tun, Address::new("203.0.113.10", 443));
    let wire = hello("unlisted.test", &["http/1.1"]);
    assert_eq!(declined(&rig, unlisted, &wire).await, wire);
}

#[tokio::test]
async fn marks_and_keeps_what_decrypting_a_client_refused() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(
        json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true}),
    );

    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/").await;
    assert_eq!(rig.dialer.marks(), vec![Some(ConnMark::Decrypted)]);

    let (near, offer) = offer_on(rig.mitm.interceptor(), flow("example.test", 443));
    let empty = rustls::RootCertStore::empty();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(empty)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
    let refused = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, near)
        .await;
    assert!(refused.is_err());
    drop(refused);
    let _ = tokio::time::timeout(Duration::from_secs(10), offer).await;
    eventually(|| rig.dialer.marks().len() == 2 && rig.dialer.marks()[1].is_some()).await;
    assert_eq!(rig.dialer.marks()[1], Some(ConnMark::Refused));

    let mut again = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(
        again.get("/p").await.text(),
        "example.test|/p||",
        "the host is still decrypted after a refusal"
    );
}

#[tokio::test]
async fn leaves_the_cores_own_connections_alone() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(
        json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true}),
    );
    let inner = flow_of(InboundKind::Inner, Address::new("example.test", 443));
    let wire = hello("example.test", &["http/1.1"]);
    assert_eq!(declined(&rig, inner, &wire).await, wire);
}

#[tokio::test]
async fn drops_quic_to_listed_hosts() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(json!({"enable": true, "hostname": ["example.test"]}));
    let interceptor = rig.mitm.interceptor();
    assert!(interceptor.drop_quic(&flow("example.test", 443)));
    assert!(!interceptor.drop_quic(&flow("other.test", 443)));
    let by_address = flow_of(InboundKind::Tun, Address::new("203.0.113.9", 443));
    assert!(
        !interceptor.drop_quic(&by_address),
        "a bare address matches no host"
    );
    rig.config(json!({"enable": true, "hostname": ["example.test"], "auto-quic-block": false}));
    assert!(!interceptor.drop_quic(&flow("example.test", 443)));
    rig.config(json!({"enable": true, "hostname": ["example.test"], "decrypt-tls": false}));
    assert!(!interceptor.drop_quic(&flow("example.test", 443)));
}

#[tokio::test]
async fn offers_http2_to_clients_only_when_asked_and_reaches_servers_over_it() {
    let (server, rig) = rig(echo(), true, &["h2", "http/1.1"]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "header-rewrite": [r"http-request ^https://example\.test header-add X-Added yes"],
    }));
    let mut h1 = Client::tls(&rig, "example.test", 443, &["h2", "http/1.1"])
        .await
        .unwrap();
    assert_eq!(
        h1.alpn.as_deref(),
        Some(&b"http/1.1"[..]),
        "h2 is off for clients by default"
    );
    h1.get("/one").await;
    assert_eq!(
        server.requests()[0].version,
        http::Version::HTTP_2,
        "servers are offered h2 regardless"
    );

    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "h2": true,
        "header-rewrite": [r"http-request ^https://example\.test header-add X-Added yes"],
    }));
    let mut h2 = Client::tls(&rig, "example.test", 443, &["h2", "http/1.1"])
        .await
        .unwrap();
    assert_eq!(h2.alpn.as_deref(), Some(&b"h2"[..]));
    let first = h2.get("/two").await;
    assert_eq!(first.text(), "example.test|/two|yes|");
    let before = server.connections.load(Ordering::SeqCst);
    let (a, b) = (
        h2.request("GET", "/a", &[], ""),
        h2.request("GET", "/b", &[], ""),
    );
    let Wire::H2(sender) = &mut h2.wire else {
        panic!("not h2")
    };
    let (mut left, mut right) = (sender.clone(), sender.clone());
    let (ra, rb) = tokio::join!(left.send_request(a), right.send_request(b));
    assert!(ra.unwrap().status().is_success() && rb.unwrap().status().is_success());
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        before,
        "streams share the one upstream connection"
    );
}

#[tokio::test]
async fn grpc_bodies_are_left_untouched() {
    let handler: Handler =
        Arc::new(|_| Reply::ok("ad ad").with("Content-Type", "application/grpc"));
    let (_server, rig) = rig(handler, true, &["h2"]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "h2": true,
        "body-rewrite": [r"http-response ^https://example\.test/ ad world"],
    }));
    let mut client = Client::tls(&rig, "example.test", 443, &["h2"])
        .await
        .unwrap();
    assert_eq!(client.get("/svc").await.text(), "ad ad");
}

#[tokio::test]
async fn a_connection_dropped_before_decrypting_lists_as_plain() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(
        json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true}),
    );
    let (near, offer) = offer_on(rig.mitm.interceptor(), flow("example.test", 443));
    let mut near = near;
    tokio::io::AsyncWriteExt::write_all(&mut near, &hello("example.test", &["http/1.1"]))
        .await
        .unwrap();
    drop(near);
    let _ = tokio::time::timeout(Duration::from_secs(10), offer).await;
    eventually(|| rig.dialer.marks() == vec![Some(ConnMark::Plain)]).await;
}

#[tokio::test]
async fn widens_a_bare_entry_to_a_port_it_sniffed_a_name_on() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(json!({"enable": true, "hostname": ["example.test", "-skip.test"]}));
    let engine = rig.mitm.engine().unwrap();
    let mut sniffed = flow_of(InboundKind::Tun, Address::new("203.0.113.7", 8443));
    sniffed.host = Some("example.test".into());
    sniffed.sniffed = true;
    assert!(engine.match_tcp(&sniffed));
    assert!(
        !engine.match_tcp(&flow("example.test", 8443)),
        "a bare entry covers 8443 only for a sniffed name"
    );
    sniffed.host = Some("skip.test".into());
    assert!(!engine.match_tcp(&sniffed));
}

#[tokio::test]
async fn rewrites_plain_http_without_decrypting_tls() {
    let config = |decrypt: bool| {
        let mut config = json!({
            "enable": true,
            "hostname": ["example.test"],
            "url-rewrite": [r"^http://example\.test/ad _ reject-dict"],
        });
        if !decrypt {
            config["decrypt-tls"] = json!(false);
        }
        config
    };
    let server = start_server(false, &[], echo()).await;
    let without_ca = crate::testing::rig_without_ca(&server, None);
    without_ca.config(config(true));
    let decrypt_off = rig_for(&server, None);
    decrypt_off.config(config(false));
    for rig in [&without_ca, &decrypt_off] {
        let engine = rig.mitm.engine().unwrap();
        assert!(!engine.match_tcp(&flow("example.test", 443)));
        assert!(engine.match_tcp(&flow("example.test", 80)));
        let mut client = Client::plain(rig, "example.test", 80).await;
        let answer = client.get("/ad").await;
        assert_eq!(
            (answer.status.as_u16(), answer.text().as_str()),
            (200, "{}")
        );
        let wire = hello("example.test", &["http/1.1"]);
        assert_eq!(declined(rig, flow("example.test", 8443), &wire).await, wire);
    }
}

#[tokio::test]
async fn reads_plain_http_to_any_host_while_a_rule_acts_on_requests() {
    let server = start_server(false, &[], echo()).await;
    let rig = rig_for(&server, None);
    rig.config(json!({"enable": true, "hostname": ["listed.test"]}));
    let engine = rig.mitm.engine().unwrap();
    let ip = flow_of(InboundKind::Tun, Address::new("203.107.1.33", 80));
    assert!(!engine.match_tcp(&ip), "no rule, no reason to read it");
    assert!(!engine.match_tcp(&flow("other.test", 80)));

    rig.config(json!({
        "enable": true,
        "hostname": ["listed.test"],
        "url-rewrite": [
            r#"^http://203\.107\.1\.33/d "\r\nUser-Agent: httpdns[^\r\n]*\r\n" url-and-header reject-dict"#,
        ],
    }));
    let engine = rig.mitm.engine().unwrap();
    assert!(engine.match_tcp(&ip));
    assert!(engine.match_tcp(&flow("other.test", 80)));
    assert!(!engine.match_tcp(&flow("other.test", 443)));
    assert!(!engine.match_tcp(&flow("other.test", 8080)));
    let wire = b"SSH-2.0-OpenSSH_9.9\r\n".to_vec();
    assert_eq!(declined(&rig, ip.clone(), &wire).await, wire);
}

#[tokio::test]
async fn plain_http_leaves_an_excluded_host_alone() {
    let server = start_server(false, &[], echo()).await;
    let rig = rig_for(&server, None);
    rig.config(json!({
        "enable": true,
        "hostname": ["-*.bank.test", "-203.0.113.9", "listed.test"],
        "url-rewrite": [r"^http://other\.test/never _ reject"],
    }));
    let engine = rig.mitm.engine().unwrap();
    assert!(!engine.match_tcp(&flow("www.bank.test", 80)));
    assert!(!engine.match_tcp(&flow_of(InboundKind::Tun, Address::new("203.0.113.9", 80))));
    assert!(engine.match_tcp(&flow("other.test", 80)));
    assert!(engine.match_tcp(&flow_of(InboundKind::Tun, Address::new("203.0.113.10", 80))));
}

#[tokio::test]
async fn plain_http_to_an_unlisted_host_is_not_peeked_without_a_rule() {
    let server = start_server(false, &[], echo()).await;
    let rig = rig_for(&server, None);
    rig.config(json!({"enable": true, "hostname": ["listed.test"]}));
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let (_near, offer) = offer_on(
        rig.mitm.interceptor(),
        flow_of(InboundKind::Tun, Address::new("203.107.1.33", 80)),
    );
    let Offer::Declined { head, .. } = offer.await.unwrap() else {
        panic!("taken")
    };
    assert!(head.is_empty());
    assert_eq!(
        started.elapsed(),
        Duration::ZERO,
        "a peek waits for the first byte, so the clock would have moved"
    );
}

#[tokio::test]
async fn the_certificate_cache_follows_the_limit() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(
        json!({"enable": true, "hostname": ["example.test"], "limits": {"certificate-cache": 2}}),
    );
    let ca = rig.mitm.authority().current().unwrap();
    for host in ["a.test", "b.test", "c.test"] {
        ca.issue_pem(host).unwrap();
    }
    assert_eq!(ca.cached_leaves(), 2);
}

#[tokio::test]
async fn a_full_body_buffer_passes_bodies_on() {
    let (_server, rig) = rig(echo(), true, &["http/1.1"]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "body-rewrite": [r#"http-response ^https://example\.test/api "\"ad\":true" "\"ad\":false""#],
        "limits": {"max-body-size": 1024, "body-buffer": 1024},
    }));
    let bodies = rig.mitm.engine().unwrap().core.bodies.clone();
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let taken = bodies.clone().try_acquire_many_owned(1024).unwrap();
    assert_eq!(
        client.get("/api").await.text(),
        r#"{"ad":true,"items":[]}"#,
        "with the buffer full"
    );
    drop(taken);
    assert_eq!(
        client.get("/api").await.text(),
        r#"{"ad":false,"items":[]}"#
    );
    assert!(
        bodies.try_acquire_many(1024).is_ok(),
        "the exchange gave its room back"
    );
}

#[tokio::test]
async fn speaks_http2_with_clients_when_asked_and_rewrites_its_bodies() {
    let handler: Handler = Arc::new(|seen| {
        let added = seen
            .headers
            .get("x-added")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        Reply::ok(&format!(r#"{{"ad":true,"added":"{added}"}}"#))
            .with("Content-Type", "application/json")
    });
    let (server, rig) = rig(handler, true, &["h2", "http/1.1"]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "h2": true,
        "header-rewrite": [r"http-request ^https://example\.test header-add X-Added yes"],
        "body-rewrite": [r#"http-response ^https://example\.test/api "\"ad\":true" "\"ad\":false""#],
    }));
    let mut client = Client::tls(&rig, "example.test", 443, &["h2"])
        .await
        .unwrap();
    assert_eq!(client.alpn.as_deref(), Some(&b"h2"[..]));
    assert_eq!(
        client.get("/api").await.text(),
        r#"{"ad":false,"added":"yes"}"#
    );
    assert_eq!(server.requests()[0].version, http::Version::HTTP_2);
}

fn upgrading_service() -> Service {
    Arc::new(|mut request| {
        Box::pin(async move {
            if request.version() != http::Version::HTTP_11 {
                return http::Response::builder()
                    .status(505)
                    .body(full_body(format!("upgrade over {:?}", request.version())))
                    .unwrap();
            }
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                let Ok(upgraded) = upgrade.await else { return };
                let mut io = hyper_util::rt::TokioIo::new(upgraded);
                let mut line = Vec::new();
                while let Ok(byte) = io.read_u8().await {
                    line.push(byte);
                    if byte == b'\n' {
                        break;
                    }
                }
                let mut echoed = b"echo ".to_vec();
                echoed.extend_from_slice(&line);
                let _ = io.write_all(&echoed).await;
            });
            http::Response::builder()
                .status(101)
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .body(full_body(""))
                .unwrap()
        })
    })
}

#[tokio::test]
async fn sends_an_upgrade_over_http1_to_a_server_that_speaks_http2() {
    let server = start_service(&["h2", "http/1.1"], upgrading_service()).await;
    let rig = rig_for(&server, None);
    rig.config(json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true, "h2": true}));
    let (near, offer) = offer_on(rig.mitm.interceptor(), flow("example.test", 443));
    let name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
    let connector =
        tokio_rustls::TlsConnector::from(crate::testing::client_config(&rig.root, &["http/1.1"]));
    let mut tls = connector.connect(name, near).await.unwrap();
    tls.write_all(b"GET /socket HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tls.read_u8().await.unwrap());
    }
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    tls.write_all(b"ping\n").await.unwrap();
    let mut echoed = [0u8; 10];
    tls.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"echo ping\n");
    drop(tls);
    let outcome = tokio::time::timeout(Duration::from_secs(10), offer)
        .await
        .expect("the offer did not end once the WebSocket closed")
        .unwrap();
    assert!(matches!(outcome, Offer::Taken));
}

#[tokio::test]
async fn carries_http2_streams_large_bodies_and_cancellations() {
    use futures_util::StreamExt;
    use http_body_util::{BodyExt, StreamBody};
    use sha2::{Digest, Sha256};

    const LARGE: usize = 16 << 20;
    let large: bytes::Bytes = b"0123456789abcdef".repeat(LARGE / 16).into();
    let (abandoned_tx, abandoned) = tokio::sync::oneshot::channel::<()>();
    let abandoned_tx = Arc::new(std::sync::Mutex::new(Some(abandoned_tx)));
    let service: Service = {
        let large = large.clone();
        Arc::new(move |request| {
            let (large, abandoned_tx) = (large.clone(), abandoned_tx.clone());
            Box::pin(async move {
                match request.uri().path() {
                    "/large" => http::Response::builder()
                        .header("Content-Length", large.len())
                        .body(full_body(large))
                        .unwrap(),
                    "/hang" => {
                        let (tx, rx) = tokio::sync::mpsc::channel::<
                            Result<hyper::body::Frame<bytes::Bytes>, std::io::Error>,
                        >(1);
                        tx.send(Ok(hyper::body::Frame::data(bytes::Bytes::from_static(
                            b"x",
                        ))))
                        .await
                        .unwrap();
                        tokio::spawn(async move {
                            tx.closed().await;
                            if let Some(abandoned) = lock(&abandoned_tx).take() {
                                let _ = abandoned.send(());
                            }
                        });
                        let stream = tokio_stream_from(rx);
                        http::Response::builder()
                            .body(BodyExt::boxed(StreamBody::new(stream)))
                            .unwrap()
                    }
                    _ => {
                        let n = request
                            .uri()
                            .query()
                            .unwrap_or_default()
                            .trim_start_matches("n=")
                            .to_string();
                        http::Response::builder().body(full_body(n)).unwrap()
                    }
                }
            })
        })
    };
    let server = start_service(&["h2"], service).await;
    let rig = rig_for(&server, None);
    rig.config(json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true, "h2": true}));
    let mut client = Client::tls(&rig, "example.test", 443, &["h2"])
        .await
        .unwrap();
    assert_eq!(client.get("/?n=warm").await.text(), "warm");

    let Wire::H2(sender) = &client.wire else {
        panic!("not h2")
    };
    let sender = sender.clone();
    let streams = (0..20).map(|n| {
        let mut sender = sender.clone();
        let request = client.request("GET", &format!("/?n={n}"), &[], "");
        async move {
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.version(), http::Version::HTTP_2);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, n.to_string().as_bytes(), "stream {n}");
        }
    });
    futures_util::future::join_all(streams).await;

    let answer = client.get("/large").await;
    assert_eq!(answer.header("content-length"), LARGE.to_string());
    assert_eq!(
        Sha256::digest(&answer.body),
        Sha256::digest(&large),
        "{} bytes",
        answer.body.len()
    );

    let mut sender = sender;
    let hung = sender
        .send_request(client.request("GET", "/hang", &[], ""))
        .await
        .unwrap();
    let mut body = hung.into_body().into_data_stream();
    assert_eq!(body.next().await.unwrap().unwrap(), &b"x"[..]);
    drop(body);
    tokio::time::timeout(Duration::from_secs(10), abandoned)
        .await
        .expect("the server never saw the stream cancelled")
        .unwrap();
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        1,
        "the streams were multiplexed upstream"
    );
}

fn tokio_stream_from<T: Send + 'static>(
    mut rx: tokio::sync::mpsc::Receiver<T>,
) -> impl futures_util::Stream<Item = T> + Send + 'static {
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

#[tokio::test]
async fn leaves_grpc_as_it_is() {
    use http_body_util::{BodyExt, StreamBody};

    const MESSAGE: &[u8] = b"\x00\x00\x00\x00\x02ad";
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let service: Service = {
        let received = received.clone();
        Arc::new(move |request| {
            let received = received.clone();
            Box::pin(async move {
                let body = request.into_body().collect().await.unwrap().to_bytes();
                *lock(&received) = body.to_vec();
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                let frames = futures_util::stream::iter([
                    Ok(hyper::body::Frame::data(bytes::Bytes::from_static(MESSAGE))),
                    Ok(hyper::body::Frame::trailers(trailers)),
                ]);
                http::Response::builder()
                    .header("Content-Type", "application/grpc")
                    .body(StreamBody::new(frames).boxed())
                    .unwrap()
            })
        })
    };
    let server = start_service(&["h2"], service).await;
    let rig = rig_for(&server, None);
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "h2": true,
        "body-rewrite": [
            r"http-request ^https://example\.test ad ok",
            r"http-response ^https://example\.test ad ok",
        ],
    }));
    let client = Client::tls(&rig, "example.test", 443, &["h2"])
        .await
        .unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("https://example.test/svc/Method")
        .header("Content-Type", "application/grpc")
        .header("TE", "trailers")
        .body(http_body_util::Full::new(bytes::Bytes::from_static(
            MESSAGE,
        )))
        .unwrap();
    let Wire::H2(sender) = &client.wire else {
        panic!("not h2")
    };
    let response = sender.clone().send_request(request).await.unwrap();
    let collected = response.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned().unwrap_or_default();
    assert_eq!(&collected.to_bytes()[..], MESSAGE);
    assert_eq!(lock(&received).as_slice(), MESSAGE);
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
}

/// What reading plain HTTP on port 80 costs once a rule acts on requests, run on the Linux VM:
/// `cargo test -p concord-mitm --release plain_http_cost -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, run by hand on the Linux VM"]
async fn plain_http_cost() {
    fn cpu_us() -> u64 {
        let stat = std::fs::read_to_string("/proc/self/stat").expect("Linux only");
        let fields: Vec<&str> = stat
            .rsplit(')')
            .next()
            .unwrap()
            .split_whitespace()
            .collect();
        let ticks: u64 = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
        ticks * 10_000
    }
    let rounds: usize = std::env::var("MM_ROUNDS").map_or(5000, |n| n.parse().unwrap());
    let server = start_server(false, &[], echo()).await;
    let plain = rig_for(&server, None);
    plain.config(json!({"enable": true, "hostname": ["listed.test"]}));
    let ruled = rig_for(&server, None);
    ruled.config(json!({
        "enable": true,
        "hostname": ["listed.test"],
        "url-rewrite": [r"^http://other\.test/never _ reject"],
    }));
    let ssh = b"SSH-2.0-OpenSSH_9.9\r\n";

    let peek = |rig: &Rig| {
        let interceptor = rig.mitm.interceptor();
        async move {
            let (mut near, offer) = offer_on(interceptor, flow("other.test", 80));
            near.write_all(ssh).await.unwrap();
            assert!(matches!(offer.await.unwrap(), Offer::Declined { .. }));
        }
    };
    #[allow(
        clippy::disallowed_methods,
        reason = "a loopback relay standing in for the core's, not a proxied socket"
    )]
    async fn relayed_get(rig: &Rig, server: std::net::SocketAddr) {
        let (near, offer) = offer_on(rig.mitm.interceptor(), flow("other.test", 80));
        let relay = tokio::spawn(async move {
            let Offer::Declined { stream, head } = offer.await.unwrap() else {
                panic!("taken")
            };
            let mut stream = concord_common::PeekedStream::new(head, stream);
            let mut upstream = tokio::net::TcpStream::connect(server).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        });
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(near))
                .await
                .unwrap();
        let conn = tokio::spawn(conn);
        let request = http::Request::get("/x")
            .header("Host", "other.test")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        use http_body_util::BodyExt;
        response.into_body().collect().await.unwrap();
        drop(sender);
        let _ = conn.await;
        let _ = relay.await;
    }
    async fn engine_get(rig: &Rig) {
        let mut client = Client::plain(rig, "other.test", 80).await;
        assert_eq!(client.get("/x").await.status.as_u16(), 200);
    }

    for (name, per) in [("connection, not HTTP", true), ("HTTP request", false)] {
        let mut arms = Vec::new();
        for (arm, rig) in [("no rule", &plain), ("a rule", &ruled)] {
            let started = cpu_us();
            let wall = std::time::Instant::now();
            for _ in 0..rounds {
                match (per, arm) {
                    (true, _) => peek(rig).await,
                    (false, "no rule") => relayed_get(rig, server.addr).await,
                    (false, _) => engine_get(rig).await,
                }
            }
            let us = (cpu_us() - started) as f64 / rounds as f64;
            println!(
                "MM-COST {name} | {arm}: {us:.1} CPU-us each, {:.1} us wall",
                wall.elapsed().as_micros() as f64 / rounds as f64
            );
            arms.push(us);
        }
        println!("MM-COST {name} | added: {:.1} CPU-us", arms[1] - arms[0]);
    }
}

/// What a head condition and a whole-head rewrite cost a request over a plain header rewrite,
/// run on the Linux VM: `cargo test -p concord-mitm --release head_rewrite_cost -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, run by hand on the Linux VM"]
async fn head_rewrite_cost() {
    fn cpu_us() -> u64 {
        let stat = std::fs::read_to_string("/proc/self/stat").expect("Linux only");
        let fields: Vec<&str> = stat
            .rsplit(')')
            .next()
            .unwrap()
            .split_whitespace()
            .collect();
        let ticks: u64 = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
        ticks * 10_000
    }
    let rounds: usize = std::env::var("MM_ROUNDS").map_or(5000, |n| n.parse().unwrap());
    let server = start_server(false, &[], echo()).await;
    let arms = [
        (
            "plain",
            vec![
                r"http-request ^http://example\.test/ header-add X-Added yes",
                r"http-response ^http://example\.test/ header-add X-Seen yes",
            ],
        ),
        (
            "request-head, response-head",
            vec![
                r"http-request ^http://example\.test/ request-head ^GET\s header-add X-Added yes",
                r"http-response ^http://example\.test/ response-head ^HTTP/\S+\s200\s header-add X-Seen yes",
            ],
        ),
        (
            "header-text-replace",
            vec![
                r#"http-request ^http://example\.test/ header-text-replace "^GET /x " "GET /y ""#,
                r#"http-response ^http://example\.test/ header-text-replace "(\r\n)X-Upstream: yes" "${1}X-Seen: yes""#,
            ],
        ),
    ];
    let mut costs = Vec::new();
    for (name, lines) in arms {
        let rig = rig_for(&server, None);
        let errors = rig.config(json!({
            "enable": true,
            "hostname": ["example.test"],
            "header-rewrite": lines,
        }));
        assert!(errors.is_empty(), "{errors:?}");
        let mut client = Client::plain(&rig, "example.test", 80).await;
        assert_eq!(client.get("/x").await.header("x-seen"), "yes");
        let started = cpu_us();
        let wall = std::time::Instant::now();
        for _ in 0..rounds {
            assert_eq!(client.get("/x").await.status.as_u16(), 200);
        }
        let us = (cpu_us() - started) as f64 / rounds as f64;
        println!(
            "MM-COST {name}: {us:.1} CPU-us each, {:.1} us wall",
            wall.elapsed().as_micros() as f64 / rounds as f64
        );
        costs.push(us);
    }
    println!(
        "MM-COST added: conditions {:.1}, whole head {:.1} CPU-us",
        costs[1] - costs[0],
        costs[2] - costs[0]
    );
}
