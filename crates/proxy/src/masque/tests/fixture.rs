use super::*;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use rcgen::PublicKeyData;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::sync::atomic::{AtomicUsize, Ordering};
use x509_parser::prelude::parse_x509_certificate;

pub(super) fn keys() -> (String, Vec<u8>) {
    let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    let der = key.private_key().as_der().unwrap();
    let private = rustls::pki_types::PrivateKeyDer::try_from(der.as_ref()).unwrap();
    let key = rcgen::KeyPair::try_from(&private).unwrap();
    (STANDARD.encode(der.as_ref()), key.subject_public_key_info())
}

#[derive(Debug)]
struct Enrolled(Vec<u8>);

impl ClientCertVerifier for Enrolled {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (_, cert) = parse_x509_certificate(cert).unwrap();
        assert!(chain.is_empty());
        assert_eq!(cert.public_key().raw, self.0);
        assert!(cert.subject().iter().next().is_none());
        assert_eq!(cert.raw_serial(), [0]);
        assert_eq!(
            cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp(),
            86400
        );
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            msg,
            cert,
            sig,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            msg,
            cert,
            sig,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(super) struct Server {
    pub(super) addr: SocketAddr,
    pub(super) public: String,
    pub(super) private: String,
    pub(super) connections: Arc<AtomicUsize>,
    pub(super) requests: Arc<AtomicUsize>,
    endpoint: Option<quinn::Endpoint>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        }
    }
}

fn tls(enrolled: Vec<u8>, alpn: &str) -> (rustls::ServerConfig, String) {
    let pair = rcgen::generate_simple_self_signed(vec!["unrelated.example".into()]).unwrap();
    let public = STANDARD.encode(pair.signing_key.subject_public_key_info());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_client_cert_verifier(Arc::new(Enrolled(enrolled)))
    .with_single_cert(
        vec![pair.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(pair.signing_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    (tls, public)
}

#[derive(Clone, Default)]
pub(super) struct H3Options {
    pub(super) stream_window: Option<u32>,
    pub(super) body_gate: Option<Arc<tokio::sync::Notify>>,
    pub(super) fail_first: bool,
    pub(super) datagrams: Option<bool>,
    pub(super) disable_quic_datagrams: bool,
    pub(super) reject_port: Option<u16>,
    pub(super) body_error: bool,
}

pub(super) async fn h3_server(l4: bool, status: u16) -> Server {
    h3_server_options(l4, status, H3Options::default()).await
}

pub(super) async fn h3_server_options(l4: bool, status: u16, options: H3Options) -> Server {
    let (private, enrolled) = keys();
    let (tls, public) = tls(enrolled, "h3");
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    if let Some(window) = options.stream_window {
        transport.stream_receive_window(quinn::VarInt::from_u32(window));
    }
    if options.disable_quic_datagrams {
        transport.datagram_receive_buffer_size(None);
    }
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let accept = endpoint.clone();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    let request_count = Arc::new(AtomicUsize::new(0));
    let requests = request_count.clone();
    let task = tokio::spawn(async move {
        while let Some(connecting) = accept.accept().await {
            let count = count.clone();
            let requests = requests.clone();
            let options = options.clone();
            tokio::spawn(async move {
                let Ok(conn) = connecting.await else {
                    return;
                };
                count.fetch_add(1, Ordering::Relaxed);
                let mut builder = ::h3::server::builder();
                builder.enable_datagram(options.datagrams.unwrap_or(!l4));
                let mut h3 = builder
                    .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
                    .await
                    .unwrap();
                while let Ok(Some(resolver)) = h3.accept().await {
                    let conn = conn.clone();
                    let requests = requests.clone();
                    let options = options.clone();
                    tokio::spawn(async move {
                        let (request, mut stream) = resolver.resolve_request().await.unwrap();
                        let request_index = requests.fetch_add(1, Ordering::Relaxed);
                        if options.fail_first && request_index == 0 {
                            stream.stop_stream(::h3::error::Code::H3_REQUEST_REJECTED);
                            return;
                        }
                        assert_eq!(request.method(), http::Method::CONNECT);
                        if !l4 {
                            assert_eq!(
                                request
                                    .extensions()
                                    .get::<::h3::ext::Protocol>()
                                    .unwrap()
                                    .as_str(),
                                "cf-connect-ip"
                            );
                            assert_eq!(request.headers()["capsule-protocol"], "?1");
                            assert!(!request.headers().contains_key("user-agent"));
                        } else {
                            assert!(request.extensions().get::<::h3::ext::Protocol>().is_none());
                            assert_eq!(request.headers()["user-agent"], "quic-go HTTP/3");
                            assert_eq!(request.headers()["accept-encoding"], "gzip");
                            assert!(matches!(
                                request.uri().authority().unwrap().as_str(),
                                "10.8.0.1:7" | "10.8.0.1:8" | "10.8.0.1:53"
                            ));
                        }
                        let status = if options.reject_port.is_some()
                            && request.uri().authority().unwrap().port_u16() == options.reject_port
                        {
                            403
                        } else {
                            status
                        };
                        stream
                            .send_response(
                                http::Response::builder().status(status).body(()).unwrap(),
                            )
                            .await
                            .unwrap();
                        if status != 200 {
                            let _ = stream.finish().await;
                            return;
                        }
                        if l4 && request.uri().authority().unwrap().port_u16() == Some(53) {
                            let mut wire = Vec::new();
                            loop {
                                let Some(mut data) = stream.recv_data().await.unwrap() else {
                                    return;
                                };
                                wire.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                                if wire.len() >= 2
                                    && wire.len()
                                        >= usize::from(u16::from_be_bytes([wire[0], wire[1]])) + 2
                                {
                                    break;
                                }
                            }
                            let reply = super::dns_answer(&wire[2..]).unwrap();
                            let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                            framed.extend_from_slice(&reply);
                            stream.send_data(framed.into()).await.unwrap();
                            stream.finish().await.unwrap();
                            return;
                        }
                        if l4 {
                            if let Some(gate) = options.body_gate {
                                gate.notified().await;
                            }
                            if options.body_error {
                                stream.stop_sending(::h3::error::Code::H3_REQUEST_CANCELLED);
                                stream.stop_stream(::h3::error::Code::H3_REQUEST_CANCELLED);
                                return;
                            }
                            while let Some(mut data) = stream.recv_data().await.unwrap() {
                                let bytes = data.copy_to_bytes(data.remaining());
                                stream.send_data(bytes).await.unwrap();
                            }
                            stream
                                .send_data(Bytes::from_static(b"after-fin"))
                                .await
                                .unwrap();
                            stream.finish().await.unwrap();
                        } else {
                            ip_h3(conn, stream).await;
                        }
                    });
                }
            });
        }
    });
    Server {
        addr,
        public,
        private,
        connections,
        requests: request_count,
        endpoint: Some(endpoint),
        task,
    }
}

async fn ip_h3(
    conn: quinn::Connection,
    mut stream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) {
    assert_eq!(stream.id().into_inner(), 0);
    let wired = stack();
    let mut received = Vec::new();
    while received.len() < 46 {
        let Ok(Some(mut bytes)) = stream.recv_data().await else {
            wired.driver.abort();
            return;
        };
        received.extend_from_slice(&bytes.copy_to_bytes(bytes.remaining()));
    }
    // connect-ip-go 67ccdb0c capsule.go:201-220: type 3, length 44, two all-IP ranges.
    assert_eq!(received, hex::decode("032c0400000000ffffffff000600000000000000000000000000000000ffffffffffffffffffffffffffffffff00").unwrap());
    let mut incoming = wired.send;
    let mut outgoing = wired.recv;
    let receiving = async {
        loop {
            let raw = conn.read_datagram().await.map_err(io::Error::other)?;
            // RFC 9297/9484: first request quarter ID 0, context 0, then the IP packet.
            assert_eq!(raw.get(..2), Some(b"\0\0".as_slice()));
            let packet = gotatun::packet::Packet::from_bytes(bytes::BytesMut::from(&raw[2..]))
                .try_into_ip()
                .unwrap();
            incoming.send(packet).await?;
        }
        #[allow(unreachable_code, reason = "the receive loop exits on I/O error")]
        Ok::<(), io::Error>(())
    };
    let sending = async {
        let mut pool: PacketBufPool = PacketBufPool::new(0);
        loop {
            for packet in outgoing.recv(&mut pool).await? {
                let packet = packet.into_bytes();
                let mut wire = bytes::BytesMut::from(b"\0\0".as_slice());
                wire.extend_from_slice(&packet);
                conn.send_datagram(wire.freeze())
                    .map_err(io::Error::other)?;
            }
        }
        #[allow(unreachable_code, reason = "the send loop exits on I/O error")]
        Ok::<(), io::Error>(())
    };
    let draining = async {
        while stream
            .recv_data()
            .await
            .map_err(io::Error::other)?
            .is_some()
        {}
        Ok::<(), io::Error>(())
    };
    tokio::select! { _ = receiving => {}, _ = sending => {}, _ = draining => {} }
    wired.driver.abort();
}

pub(super) async fn h2_server(status: u16) -> Server {
    let (private, enrolled) = keys();
    let (tls, public) = tls(enrolled, "h2");
    let listen = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listen.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    let task = tokio::spawn(async move {
        let accept = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        loop {
            let (tcp, _) = listen.accept().await.unwrap();
            let accept = accept.clone();
            let count = count.clone();
            tokio::spawn(async move {
                let Ok(tls) = accept.accept(tcp).await else {
                    return;
                };
                count.fetch_add(1, Ordering::Relaxed);
                let mut connection = ::h2::server::handshake(tls).await.unwrap();
                while let Some(request) = connection.accept().await {
                    let (request, mut response) = request.unwrap();
                    assert_eq!(request.method(), http::Method::CONNECT);
                    assert_eq!(
                        request.uri().authority().unwrap().as_str(),
                        "cloudflareaccess.com:443"
                    );
                    assert_eq!(request.headers()["cf-connect-proto"], "cf-connect-ip");
                    assert_eq!(request.headers()["pq-enabled"], "false");
                    assert_eq!(request.headers()["accept-encoding"], "gzip");
                    assert!(!request.headers().contains_key("user-agent"));
                    let send = response
                        .send_response(
                            http::Response::builder().status(status).body(()).unwrap(),
                            status != 200,
                        )
                        .unwrap();
                    if status != 200 {
                        continue;
                    }
                    let body = concord_transport::h2io::H2Body::new(
                        send,
                        concord_transport::h2io::Incoming::Body(request.into_body()),
                    );
                    tokio::spawn(ip_h2(body));
                }
            });
        }
    });
    Server {
        addr,
        public,
        private,
        connections,
        requests: Arc::new(AtomicUsize::new(0)),
        endpoint: None,
        task,
    }
}

async fn ip_h2(body: concord_transport::h2io::H2Body) {
    let wired = stack();
    let (mut read, mut write) = tokio::io::split(body);
    let mut incoming = wired.send;
    let mut outgoing = wired.recv;
    let receiving = async {
        loop {
            assert_eq!(super::super::capsule::varint(&mut read).await?, 0);
            let len = super::super::capsule::varint(&mut read).await?;
            let mut raw = vec![0; len as usize];
            read.read_exact(&mut raw).await?;
            // H2 capsules carry the raw IP packet without an H3 context id.
            assert!(matches!(raw[0] >> 4, 4 | 6));
            incoming
                .send(
                    gotatun::packet::Packet::from_bytes(raw.as_slice().into())
                        .try_into_ip()
                        .unwrap(),
                )
                .await?;
        }
        #[allow(unreachable_code, reason = "the receive loop exits on I/O error")]
        Ok::<(), io::Error>(())
    };
    let sending = async {
        let mut pool: PacketBufPool = PacketBufPool::new(0);
        loop {
            for packet in outgoing.recv(&mut pool).await? {
                super::super::capsule::send(&mut write, 0, &packet.into_bytes()).await?;
            }
        }
        #[allow(unreachable_code, reason = "the send loop exits on I/O error")]
        Ok::<(), io::Error>(())
    };
    tokio::select! { _ = receiving => {}, _ = sending => {} }
    wired.driver.abort();
}

pub(super) async fn settings_server(
    gate: Arc<tokio::sync::Notify>,
    peer_settings: Vec<u8>,
) -> (Server, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let (private, enrolled) = keys();
    let (tls, public) = tls(enrolled, "h3");
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let accept = endpoint.clone();
    let (send, received) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let conn = accept.accept().await.unwrap().await.unwrap();
        let mut kept = Vec::new();
        let mut stream = loop {
            let mut stream = conn.accept_uni().await.unwrap();
            if stream.read_u8().await.unwrap() == 0 {
                break stream;
            }
            kept.push(stream);
        };
        assert_eq!(stream.read_u8().await.unwrap(), 4);
        let len = stream.read_u8().await.unwrap();
        assert!(len < 64);
        let mut wire = vec![0, 4, len];
        let mut payload = vec![0; len as usize];
        stream.read_exact(&mut payload).await.unwrap();
        wire.extend_from_slice(&payload);
        send.send(wire).unwrap();
        gate.notified().await;
        let Ok(mut control) = conn.open_uni().await else {
            return;
        };
        if control.write_all(&peer_settings).await.is_err() {
            return;
        }
        let _ = conn.closed().await;
        drop((control, stream, kept));
    });
    (
        Server {
            addr,
            public,
            private,
            connections: Arc::new(AtomicUsize::new(0)),
            requests: Arc::new(AtomicUsize::new(0)),
            endpoint: Some(endpoint),
            task,
        },
        received,
    )
}
