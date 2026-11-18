use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

pub fn endpoints_with_transport(
    server_transport: quinn::TransportConfig,
    client_transport: quinn::TransportConfig,
) -> (quinn::Endpoint, quinn::Endpoint) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(server_transport));
    let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    config.transport_config(Arc::new(client_transport));
    client.set_default_client_config(config);
    (server, client)
}
