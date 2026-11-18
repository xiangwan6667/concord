use super::*;

/// A bare hostname covers 443 and 80 only, and the origins here are on free ports.
fn mitm_section(port: u16, lines: &str) -> String {
    format!("mitm:\n  enable: true\n  hostname: ['mitm.test:{port}']\n{lines}")
}

/// An HTTP/1.1 exchange through the core over SOCKS, as a client that names the host.
async fn http_through(mixed: u16, target: SocketAddr, host: &str, path: &str) -> String {
    let SocketAddr::V4(v4) = target else {
        panic!("IPv4 expected")
    };
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, mixed))
        .await
        .unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: {host}:{}\r\nConnection: close\r\n\r\n",
                v4.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    // Linux resets a socket closed with the request unread, as when the host does not resolve.
    let _ = timeout(PATIENCE, stream.read_to_end(&mut response))
        .await
        .expect("no HTTP answer");
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_rewrites_plain_http_on_the_way_through() {
    let (server, _) = http_server(HashMap::from([
        ("/kept", "from the server".to_string()),
        ("/after", "rewritten target".to_string()),
    ]))
    .await;
    let rig = Rig::new();
    let config = format!(
        "hosts:\n  mitm.test: 127.0.0.1\n{}rules:\n  - MATCH,DIRECT\n",
        mitm_section(
            server.port(),
            "  url-rewrite:\n    - ^http://mitm\\.test:\\d+/blocked$ - reject\n    - ^(http://mitm\\.test:\\d+)/before$ $1/after 302\n"
        )
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    let body = http_through(rig.mixed, server, "mitm.test", "/kept").await;
    assert!(body.ends_with("from the server"), "{body}");

    let body = http_through(rig.mixed, server, "mitm.test", "/before").await;
    assert!(body.starts_with("HTTP/1.1 302"), "{body}");
    assert!(body.contains("/after"), "{body}");

    let body = http_through(rig.mixed, server, "mitm.test", "/blocked").await;
    assert!(!body.contains("from the server"), "{body}");

    let other = http_through(rig.mixed, server, "not-matched.test", "/kept").await;
    assert!(other.is_empty() || other.starts_with("HTTP"), "{other}");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_intercepted_request_still_dialing_when_every_connection_closes_gets_no_answer() {
    let (server, _) = http_server(HashMap::from([("/kept", "from the server".to_string())])).await;
    let (upstream, _) = upstream_socks().await;
    let gate = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gated = gate.local_addr().unwrap().port();
    let (entered, dialing) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut client, _) = gate.accept().await.unwrap();
        let _ = entered.send(());
        let _ = released.await;
        let mut server = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream))
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    });
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {gated}}}\n\
         mitm:\n  enable: true\n  hostname: ['localhost:{}']\n\
         rules:\n  - MATCH,up\n",
        server.port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    let mixed = rig.mixed;
    let answer = tokio::spawn(async move {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, mixed))
            .await
            .unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await.unwrap();
        let mut request = vec![5, 1, 0, 3, 9];
        request.extend_from_slice(b"localhost");
        request.extend_from_slice(&server.port().to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        let get = format!(
            "GET /kept HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            server.port()
        );
        stream.write_all(get.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ = timeout(PATIENCE, stream.read_to_end(&mut response)).await;
        String::from_utf8_lossy(&response).into_owned()
    });
    timeout(PATIENCE, dialing)
        .await
        .expect("the intercepted request never dialed upstream")
        .unwrap();
    rig.engine.close_all_connections();
    release.send(()).unwrap();
    let body = answer.await.unwrap();
    assert!(
        !body.contains("from the server"),
        "the upstream dialled across close_all still answered: {body}"
    );
    assert_eq!(rig.engine.connection_count(), 0);
    rig.engine.shutdown().await;
}

/// An HTTPS server with a certificate no one trusts, which answers every request alike.
async fn tls_server(body: &'static str) -> SocketAddr {
    let certified = rcgen::generate_simple_self_signed(vec!["origin.test".to_string()]).unwrap();
    let key =
        rustls_pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_decrypts_a_listed_host_under_its_own_certificate() {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::RootCertStore;

    let server = tls_server("over tls").await;
    let rig = Rig::new();
    let info = rig.engine.mitm().generate_certificate().unwrap();
    let fingerprint = info["fingerprint"].as_str().unwrap().to_string();
    let certificate_pem = info["pem"].as_str().unwrap().to_string();
    let config = format!(
        "hosts:\n  mitm.test: 127.0.0.1\n{}rules:\n  - MATCH,DIRECT\n",
        mitm_section(
            server.port(),
            &format!(
                "  decrypt-tls: true\n  ca-fingerprint: {fingerprint}\n  skip-server-cert-verify: true\n"
            )
        )
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;

    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(certificate_pem.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let tls = tokio_rustls::TlsConnector::from(Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let SocketAddr::V4(v4) = server else {
        panic!("IPv4 expected")
    };
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
        .await
        .unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    let host = "mitm.test";
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();

    let mut secured = timeout(
        PATIENCE,
        tls.connect(ServerName::try_from(host).unwrap(), stream),
    )
    .await
    .expect("the handshake with the core stalled")
    .expect("the leaf must chain to the CA the core reported");
    secured
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: mitm.test:{}\r\nConnection: close\r\n\r\n",
                v4.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = timeout(PATIENCE, secured.read_to_end(&mut response))
        .await
        .expect("no answer through the decrypted connection");
    let response = String::from_utf8_lossy(&response);
    assert!(response.ends_with("over tls"), "{response}");

    assert!(
        eventually(|| rig.engine.connection_count() == 0).await,
        "the upstream connection stayed listed"
    );
    rig.engine.shutdown().await;
}

/// An HTTPS origin that keeps its connections open and answers the path and
/// the `X-Mitm` header of each request.
async fn tls_echo_server() -> SocketAddr {
    let certified = rcgen::generate_simple_self_signed(vec!["origin.test".to_string()]).unwrap();
    let key =
        rustls_pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                loop {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&head).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let mitm = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("x-mitm")
                                .then(|| value.trim().to_string())
                        })
                        .unwrap_or_default();
                    let body = format!("{path}|{mitm}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

type Secured = tokio_rustls::client::TlsStream<TcpStream>;

/// A TLS client through the core over SOCKS that trusts only the CA in `ca_pem`.
async fn tls_through(mixed: u16, host: &str, port: u16, ca_pem: &str) -> std::io::Result<Secured> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName};

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let tls = tokio_rustls::TlsConnector::from(Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, mixed)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    timeout(
        PATIENCE,
        tls.connect(ServerName::try_from(host.to_string()).unwrap(), stream),
    )
    .await
    .map_err(|_| std::io::Error::other("the handshake stalled"))?
}

/// One request on a kept connection: its status and its body.
async fn exchange(stream: &mut Secured, host: &str, port: u16, path: &str) -> (u16, String) {
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        timeout(PATIENCE, stream.read_exact(&mut byte))
            .await
            .expect("no answer")
            .unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    (status, String::from_utf8(body).unwrap())
}

fn verify_leaf(ca_pem: &str, leaf_pem: &str, host: &str) -> Result<(), String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let leaf = CertificateDer::from_pem_slice(leaf_pem.as_bytes()).map_err(|e| e.to_string())?;
    let verifier = tokio_rustls::rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    tokio_rustls::rustls::client::danger::ServerCertVerifier::verify_server_cert(
        verifier.as_ref(),
        &leaf,
        &[],
        &ServerName::try_from(host.to_string()).unwrap(),
        &[],
        UnixTime::now(),
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_makes_its_certificate_on_request_and_its_leaves_verify() {
    let rig = Rig::new();
    assert!(rig.engine.mitm().certificate().unwrap().is_none());
    assert!(
        rig.engine.mitm().issue_certificate("check.test").is_err(),
        "a leaf was issued without a CA"
    );
    let generated = rig.engine.mitm().generate_certificate().unwrap();
    let info = rig.engine.mitm().certificate().unwrap().unwrap();
    assert_eq!(info["fingerprint"], generated["fingerprint"]);
    assert!(rig.home.path().join("mitm/ca.crt").exists());
    let leaf = rig.engine.mitm().issue_certificate("check.test").unwrap();
    verify_leaf(info["pem"].as_str().unwrap(), &leaf, "check.test").unwrap();

    let validation = rig
        .engine
        .mitm()
        .validate(serde_json::json!({
            "hostname": ["a.test"],
            "url-rewrite": ["^ok _ reject", "(broken _ reject", "# note"],
        }))
        .unwrap();
    let issues = validation["issues"].as_object().unwrap();
    assert_eq!(issues.len(), 1, "{issues:?}");
    let listed = issues["url-rewrite"].as_array().unwrap();
    assert_eq!(
        (listed.len(), &listed[0]["index"]),
        (1, &serde_json::json!(1))
    );
    let read: Vec<&serde_json::Value> = validation["views"]["url-rewrite"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| &entry["index"])
        .collect();
    assert_eq!(read, [&serde_json::json!(0)]);
}

async fn decrypting_rig(rules: &str, lines: &str, capture: bool) -> (Rig, SocketAddr, String) {
    let server = tls_echo_server().await;
    let rig = Rig::new();
    let info = rig.engine.mitm().generate_certificate().unwrap();
    let config = format!(
        "hosts:\n  mitm.test: 127.0.0.1\n{}rules:\n{rules}",
        mitm_section(
            server.port(),
            &format!(
                "  ca-fingerprint: {}\n  skip-server-cert-verify: true\n{lines}",
                info["fingerprint"].as_str().unwrap()
            )
        )
    );
    rig.setup(
        &config,
        BTreeMap::new(),
        CoreOptions {
            mitm_capture: capture,
            ..CoreOptions::default()
        },
    )
    .await
    .unwrap();
    rig.engine.start_listeners().await;
    (rig, server, info["pem"].as_str().unwrap().to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_captures_the_exchanges_of_a_decrypted_connection() {
    let (rig, server, ca) = decrypting_rig(
        "  - MATCH,DIRECT\n",
        "  url-rewrite: ['/ad$ _ reject']\n  header-rewrite: ['http-request ^https://mitm\\.test header-add X-Mitm yes']\n",
        true,
    )
    .await;
    let port = server.port();
    let mut stream = tls_through(rig.mixed, "mitm.test", port, &ca)
        .await
        .unwrap();
    assert_eq!(exchange(&mut stream, "mitm.test", port, "/ad").await.0, 404);
    assert_eq!(
        exchange(&mut stream, "mitm.test", port, "/page").await,
        (200, "/page|yes".to_string())
    );

    let decrypted = rig
        .engine
        .connections()
        .into_iter()
        .find(|record| record.mitm.load(Ordering::SeqCst))
        .expect("no connection is marked as decrypted");
    let id = decrypted.id.clone();
    let mut list = serde_json::Value::Null;
    assert!(
        eventually(|| {
            list = rig.engine.mitm().exchanges(&id).unwrap();
            list["exchanges"]
                .as_array()
                .is_some_and(|all| all.len() == 1 && all[0].get("pending").is_none())
        })
        .await,
        "exchanges of {id}: {list}"
    );
    assert_eq!(
        (&list["capturing"], &list["closed"]),
        (&serde_json::json!(true), &serde_json::json!(false))
    );
    let exchange_id = list["exchanges"][0]["id"].as_i64().unwrap();
    let found = rig.engine.mitm().exchange(exchange_id).unwrap();
    assert_eq!(found["connection"], serde_json::json!(id));
    assert_eq!(found["status"], 200);
    assert_eq!(
        found["request-header"]["X-Mitm"],
        serde_json::json!(["yes"])
    );
    let body = rig.engine.mitm().body(exchange_id, true).unwrap();
    assert_eq!(body["data"], "L3BhZ2V8eWVz", "base64 of /page|yes");

    drop(stream);
    assert!(
        eventually(|| rig.engine.mitm().exchanges(&id).unwrap()["closed"] == true).await,
        "{id} is still listed open"
    );
    assert_eq!(
        rig.engine.mitm().exchanges(&id).unwrap()["exchanges"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_lists_the_requests_it_answers_or_the_rules_reject() {
    let (rig, server, ca) = decrypting_rig(
        "  - DST-PORT,1,REJECT\n  - MATCH,DIRECT\n",
        "  url-rewrite: ['/ad$ _ reject', '^https://.*/elsewhere$ https://127.0.0.1:1/']\n",
        true,
    )
    .await;
    let port = server.port();
    let mut stream = tls_through(rig.mixed, "mitm.test", port, &ca)
        .await
        .unwrap();
    exchange(&mut stream, "mitm.test", port, "/ad").await;
    exchange(&mut stream, "mitm.test", port, "/elsewhere").await;

    let rejected: Vec<_> = lock(&rig.events.seen)
        .iter()
        .filter_map(|event| match event {
            CoreEvent::Request(record)
                if record.mitm.load(Ordering::SeqCst)
                    && record.chains.iter().map(|c| c.as_ref()).eq(["REJECT"]) =>
            {
                Some(record.clone())
            }
            _ => None,
        })
        .collect();
    let mut listed: Vec<(String, String)> = rejected
        .iter()
        .filter_map(|record| {
            let list = rig.engine.mitm().exchanges(&record.id).unwrap();
            let exchanges = list["exchanges"].as_array()?;
            (exchanges.len() == 1).then(|| {
                (
                    format!("{}({})", record.rule, record.rule_payload),
                    exchanges[0]["url"].as_str().unwrap().to_string(),
                )
            })
        })
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            ("()".to_string(), format!("https://mitm.test:{port}/ad")),
            ("DstPort(1)".to_string(), "https://127.0.0.1:1/".to_string()),
        ]
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_leaves_a_listed_connection_the_rules_reject() {
    let (rig, server, ca) = decrypting_rig("  - MATCH,REJECT\n", "", false).await;
    assert!(
        tls_through(rig.mixed, "mitm.test", server.port(), &ca)
            .await
            .is_err(),
        "a connection the rules reject was answered"
    );
    rig.engine.shutdown().await;
}

impl Association {
    /// Whether a datagram to `host:port`, named as a SOCKS5 domain address or
    /// given as an address, comes back from the echo server behind it.
    async fn echoes_to(&self, host: &str, port: u16) -> bool {
        let mut packet = match host.parse::<Ipv4Addr>() {
            Ok(ip) => {
                let mut packet = vec![0, 0, 0, 1];
                packet.extend_from_slice(&ip.octets());
                packet
            }
            Err(_) => {
                let mut packet = vec![0, 0, 0, 3, u8::try_from(host.len()).unwrap()];
                packet.extend_from_slice(host.as_bytes());
                packet
            }
        };
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(b"datagram");
        let mut buf = [0u8; 256];
        for _ in 0..3 {
            self.socket.send_to(&packet, self.relay).await.unwrap();
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(500), self.socket.recv_from(&mut buf)).await
            {
                return buf[..len].ends_with(b"datagram");
            }
        }
        false
    }
}

/// A nameserver that answers every A query with the loopback address.
async fn loopback_nameserver() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            let Some(end) = buf[12..len]
                .iter()
                .position(|&b| b == 0)
                .map(|at| 12 + at + 5)
            else {
                continue;
            };
            let is_a = buf.get(end - 4..end - 2) == Some(&[0, 1]);
            let mut answer = buf[..end].to_vec();
            answer[2..4].copy_from_slice(&[0x81, 0x80]);
            answer[6..12].copy_from_slice(&[0, u8::from(is_a), 0, 0, 0, 0]);
            if is_a {
                answer
                    .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            }
            let _ = socket.send_to(&answer, from).await;
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_drops_quic_to_a_listed_host_by_name_or_fake_ip() {
    let echo = udp_echo().await;
    let port = echo.port();
    let nameserver = loopback_nameserver().await;
    let dns = free_port();
    let rig = Rig::new();
    let info = rig.engine.mitm().generate_certificate().unwrap();
    let config = format!(
        "dns:\n  enable: true\n  listen: 127.0.0.1:{dns}\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - {nameserver}\n\
         mitm:\n  enable: true\n  hostname: ['quic.test:{port}', 'faked.test:{port}']\n  ca-fingerprint: {}\n\
         rules:\n  - MATCH,DIRECT\n",
        info["fingerprint"].as_str().unwrap()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    let listed_fake = fake_ip_of(dns, "faked.test").await;
    let unlisted_fake = fake_ip_of(dns, "plain.test").await;
    assert_eq!(listed_fake.octets()[..2], [198, 18], "{listed_fake}");

    assert!(
        associate(rig.mixed)
            .await
            .echoes_to(&unlisted_fake.to_string(), port)
            .await,
        "UDP to an unlisted host was dropped"
    );
    assert!(
        !associate(rig.mixed)
            .await
            .echoes_to("quic.test", port)
            .await,
        "QUIC to a listed host went out"
    );
    assert!(
        !associate(rig.mixed)
            .await
            .echoes_to(&listed_fake.to_string(), port)
            .await,
        "QUIC to the fake IP of a listed host went out"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_tasks_follow_the_core_and_reach_the_network() {
    let (server, hits) = http_server(HashMap::from([
        ("/tool", "pong".to_string()),
        ("/engine-started", "ok".to_string()),
        ("/network-changed", "ok".to_string()),
    ]))
    .await;
    let rig = Rig::new();
    let resources = rig.home.path().join("mitm/resources");
    std::fs::create_dir_all(&resources).unwrap();
    std::fs::write(
        resources.join("event.js"),
        format!("$httpClient.get('http://{server}/' + $event.name, () => $done())"),
    )
    .unwrap();
    std::fs::write(
        resources.join("tool.js"),
        format!(
            "$httpClient.get('http://{server}/tool', (error, response, body) => {{ console.log(body); $done({{ title: $trigger }}) }})"
        ),
    )
    .unwrap();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    assert!(
        rig.engine.mitm().run_script("Tool").await.is_err(),
        "a script ran with decryption off"
    );

    rig.apply(
        "mitm:\n  enable: true\n  script:\n    - Started = type=event,event-name=engine-started,script-path=event.js\n    - Network = type=event,event-name=network-changed,script-path=event.js\n    - Tool = type=generic,script-path=tool.js\nrules:\n  - MATCH,DIRECT\n",
    )
    .await
    .unwrap();
    let output = rig.engine.mitm().run_script("Tool").await.unwrap();
    assert_eq!(output["result"], r#"{"title":"button"}"#, "{output}");
    assert_eq!(output["logs"], serde_json::json!(["pong"]));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    rig.engine.network_changed();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "an event script ran while stopped"
    );
    rig.engine.start_listeners().await;
    assert!(
        eventually(|| hits.load(Ordering::SeqCst) == 2).await,
        "engine-started"
    );
    rig.engine.network_changed();
    assert!(
        eventually(|| hits.load(Ordering::SeqCst) == 3).await,
        "network-changed"
    );
    rig.engine.stop_listeners().await;
    rig.engine.network_changed();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "an event script ran after the stop"
    );
    rig.engine.shutdown().await;
}
