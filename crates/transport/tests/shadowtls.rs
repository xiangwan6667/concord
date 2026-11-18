//! ShadowTLS servers written from `transport/shadowtls/server.go` and the
//! v2/v3 helpers, sharing no code with the client, in front of a real rustls
//! decoy server.

use std::io;
use std::sync::{Arc, Mutex};

use concord_common::BoxStream;
use concord_common::sync::lock;
use concord_tls::{TlsConnector, TlsOptions, TrustStore};
use concord_transport::{
    Layer, ShadowTlsClient, ShadowTlsOptions, TransportStack, WS_ALPN, tls_dial,
};
use hmac::{Hmac, Mac};
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf, duplex,
    split,
};

type HmacSha1 = Hmac<Sha1>;

struct Decoy {
    config: Arc<ServerConfig>,
    trust: Arc<TrustStore>,
}

fn decoy(tls13_only: bool, alpn: &[&str]) -> Decoy {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec!["decoy.test".to_owned()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().clone();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ServerConfig::builder_with_provider(provider);
    let builder = if tls13_only {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .unwrap();
    let mut config = builder
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    Decoy {
        config: Arc::new(config),
        trust: TrustStore::new(b"", vec![CertificateDer::from(der.to_vec())]),
    }
}

impl Decoy {
    fn connect(&self) -> DuplexStream {
        let (near, far) = duplex(1 << 20);
        let acceptor = tokio_rustls::TlsAcceptor::from(self.config.clone());
        tokio::spawn(async move {
            if let Ok(mut stream) = acceptor.accept(far).await {
                let mut sink = [0u8; 1024];
                while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
            }
        });
        near
    }
}

fn client_options(password: &str, version: u8, alpn: &[&str]) -> ShadowTlsOptions {
    ShadowTlsOptions {
        password: password.into(),
        version,
        tls: TlsOptions {
            server_name: Some("decoy.test".into()),
            alpn: alpn.iter().map(|a| (*a).to_owned()).collect(),
            ..TlsOptions::default()
        },
    }
}

async fn read_frame<R: AsyncRead + Unpin>(io: &mut R) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 5];
    io.read_exact(&mut head).await?;
    let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
    let mut frame = head.to_vec();
    frame.resize(5 + len, 0);
    io.read_exact(&mut frame[5..]).await?;
    Ok(frame)
}

fn app_record(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![23, 3, 3];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn mac(password: &str) -> HmacSha1 {
    HmacSha1::new_from_slice(password.as_bytes()).unwrap()
}

fn tag(mac: &HmacSha1) -> Vec<u8> {
    mac.clone().finalize().into_bytes()[..4].to_vec()
}

async fn echo_records<R, W>(mut from: R, mut to: W, first: Vec<u8>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut pending = Some(first);
    loop {
        let payload = match pending.take() {
            Some(p) => p,
            None => match read_frame(&mut from).await {
                Ok(frame) if frame[0] == 23 => frame[5..].to_vec(),
                _ => return,
            },
        };
        if to.write_all(&app_record(&payload)).await.is_err() {
            return;
        }
    }
}

async fn serve_v1(mut client: DuplexStream, decoy: &Decoy) {
    let upstream = decoy.connect();
    let (mut cr, mut cw) = split(&mut client);
    let (mut ur, mut uw) = split(upstream);
    let up = copy_until_finished(&mut cr, &mut uw);
    let down = copy_until_finished(&mut ur, &mut cw);
    let (a, b) = tokio::join!(up, down);
    a.unwrap();
    b.unwrap();
    let mut buf = [0u8; 4096];
    loop {
        let n = client.read(&mut buf).await.unwrap_or(0);
        if n == 0 || client.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

async fn copy_until_finished<R, W>(src: &mut R, dst: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut seen_ccs = false;
    loop {
        let frame = read_frame(src).await?;
        dst.write_all(&frame).await?;
        if frame[0] != 22 {
            if frame[0] != 20 {
                return Err(io::Error::other("unexpected record"));
            }
            if !seen_ccs {
                seen_ccs = true;
                continue;
            }
        }
        if seen_ccs {
            return Ok(());
        }
    }
}

#[derive(Default)]
struct WriteSums {
    mac: Option<HmacSha1>,
    current: Vec<u8>,
    previous: Vec<u8>,
    has_content: bool,
}

async fn serve_v2(client: DuplexStream, decoy: &Decoy, password: &str) {
    let (mut cr, cw) = split(client);
    let hello = read_frame(&mut cr).await.unwrap();
    let upstream = decoy.connect();
    let (mut ur, mut uw) = split(upstream);
    uw.write_all(&hello).await.unwrap();
    let sums = Arc::new(Mutex::new(WriteSums {
        mac: Some(mac(password)),
        ..WriteSums::default()
    }));
    let cw = Arc::new(tokio::sync::Mutex::new(cw));
    let down = {
        let (sums, cw) = (sums.clone(), cw.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let n = ur.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                cw.lock().await.write_all(&buf[..n]).await.unwrap();
                let mut sums = lock(&sums);
                if sums.has_content {
                    sums.previous = sums.current.clone();
                }
                let mac = sums.mac.as_mut().unwrap();
                mac.update(&buf[..n]);
                sums.current = mac.clone().finalize().into_bytes()[..8].to_vec();
                sums.has_content = true;
            }
        })
    };
    let request = loop {
        let frame = read_frame(&mut cr).await.unwrap();
        if frame[0] == 23 && frame.len() >= 13 {
            let sums = lock(&sums);
            let wire = &frame[5..13];
            if sums.has_content && (wire == sums.current || wire == sums.previous) {
                break frame[13..].to_vec();
            }
        }
        uw.write_all(&frame).await.unwrap();
    };
    down.abort();
    let _ = down.await;
    let writer = Arc::try_unwrap(cw).ok().unwrap().into_inner();
    echo_records(cr, writer, request).await;
}

fn verify_client_hello(frame: &[u8], password: &str) -> bool {
    const HMAC_AT: usize = 43 + 1 + 32 - 4;
    if frame.len() < HMAC_AT + 4 || frame[43] != 32 {
        return false;
    }
    let mut mac = mac(password);
    mac.update(&frame[5..HMAC_AT]);
    mac.update(&[0, 0, 0, 0]);
    mac.update(&frame[HMAC_AT + 4..]);
    tag(&mac) == frame[HMAC_AT..HMAC_AT + 4]
}

async fn serve_v3(client: DuplexStream, decoy: &Decoy, password: &str) {
    let (mut cr, cw) = split(client);
    let hello = read_frame(&mut cr).await.unwrap();
    if !verify_client_hello(&hello, password) {
        return;
    }
    let upstream = decoy.connect();
    let (mut ur, mut uw) = split(upstream);
    uw.write_all(&hello).await.unwrap();
    let server_hello = read_frame(&mut ur).await.unwrap();
    let cw = Arc::new(tokio::sync::Mutex::new(cw));
    cw.lock().await.write_all(&server_hello).await.unwrap();
    let random = server_hello[11..43].to_vec();
    let key: Vec<u8> = Sha256::new()
        .chain_update(password.as_bytes())
        .chain_update(&random)
        .finalize()
        .to_vec();
    let down = {
        let cw = cw.clone();
        let mut write_mac = mac(password);
        write_mac.update(&random);
        tokio::spawn(async move {
            while let Ok(mut frame) = read_frame(&mut ur).await {
                if frame[0] == 23 {
                    for (i, byte) in frame[5..].iter_mut().enumerate() {
                        *byte ^= key[i % key.len()];
                    }
                    write_mac.update(&frame[5..]);
                    let mut out = frame[..3].to_vec();
                    out.extend_from_slice(&((frame.len() - 5 + 4) as u16).to_be_bytes());
                    out.extend_from_slice(&tag(&write_mac));
                    out.extend_from_slice(&frame[5..]);
                    frame = out;
                }
                if cw.lock().await.write_all(&frame).await.is_err() {
                    return;
                }
            }
        })
    };
    let mut verify = mac(password);
    let reset = |verify: &mut HmacSha1| {
        *verify = mac(password);
        verify.update(&random);
        verify.update(b"C");
    };
    let first = loop {
        let frame = read_frame(&mut cr).await.unwrap();
        if frame[0] == 23 && frame.len() > 9 {
            reset(&mut verify);
            verify.update(&frame[9..]);
            if tag(&verify) == frame[5..9] {
                reset(&mut verify);
                verify.update(&frame[9..]);
                verify.update(&frame[5..9]);
                break frame[9..].to_vec();
            }
        }
        uw.write_all(&frame).await.unwrap();
    };
    down.abort();
    let _ = down.await;
    let mut add = mac(password);
    add.update(&random);
    add.update(b"S");
    let mut pending = Some(first);
    let writer = Arc::try_unwrap(cw).ok().unwrap().into_inner();
    let mut writer: WriteHalf<DuplexStream> = writer;
    let mut reader: ReadHalf<DuplexStream> = cr;
    loop {
        let payload = match pending.take() {
            Some(p) => p,
            None => {
                let Ok(frame) = read_frame(&mut reader).await else {
                    return;
                };
                assert_eq!(frame[0], 23);
                verify.update(&frame[9..]);
                assert_eq!(tag(&verify), frame[5..9]);
                verify.update(&frame[5..9]);
                frame[9..].to_vec()
            }
        };
        add.update(&payload);
        let digest = tag(&add);
        add.update(&digest);
        let mut out = vec![23, 3, 3];
        out.extend_from_slice(&((payload.len() + 4) as u16).to_be_bytes());
        out.extend_from_slice(&digest);
        out.extend_from_slice(&payload);
        if writer.write_all(&out).await.is_err() {
            return;
        }
    }
}

async fn roundtrip(stack: &TransportStack, client: DuplexStream) {
    let mut io = stack.apply(Box::new(client), "decoy.test").await.unwrap();
    io.write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    io.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello");
    let big: Vec<u8> = (0..120_000u32).map(|i| (i % 251) as u8).collect();
    let mut echoed = vec![0u8; big.len()];
    let (mut r, mut w) = split(io);
    let send = async {
        for chunk in big.chunks(7000) {
            w.write_all(chunk).await.unwrap();
        }
        w.flush().await.unwrap();
    };
    let recv = r.read_exact(&mut echoed);
    let (_, recv) = tokio::join!(send, recv);
    recv.unwrap();
    assert_eq!(echoed, big);
}

fn stack(client: ShadowTlsClient) -> TransportStack {
    TransportStack::new(vec![Layer::ShadowTls(Arc::new(client))], Default::default())
}

#[tokio::test]
async fn v1_relays_a_tls12_handshake_then_goes_raw() {
    let decoy = Arc::new(decoy(false, &["h2", "http/1.1"]));
    let client = ShadowTlsClient::new(client_options("pw", 1, &[]), decoy.trust.clone()).unwrap();
    let (near, far) = duplex(1 << 20);
    let server = {
        let decoy = decoy.clone();
        tokio::spawn(async move { serve_v1(far, &decoy).await })
    };
    let mut io = stack(client)
        .apply(Box::new(near), "decoy.test")
        .await
        .unwrap();
    io.write_all(b"raw bytes").await.unwrap();
    let mut got = [0u8; 9];
    io.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"raw bytes");
    drop(io);
    let _ = server.await;
}

#[tokio::test]
async fn v2_prefixes_the_first_write_and_frames_the_rest() {
    let decoy = Arc::new(decoy(true, &["h2", "http/1.1"]));
    let client = ShadowTlsClient::new(client_options("pw", 2, &[]), decoy.trust.clone()).unwrap();
    let (near, far) = duplex(1 << 20);
    let server = {
        let decoy = decoy.clone();
        tokio::spawn(async move { serve_v2(far, &decoy, "pw").await })
    };
    roundtrip(&stack(client), near).await;
    server.abort();
}

#[tokio::test]
async fn version_zero_means_version_two() {
    let decoy = decoy(true, &[]);
    let client = ShadowTlsClient::new(client_options("pw", 0, &[]), decoy.trust.clone()).unwrap();
    assert_eq!(client.version(), 2);
    assert!(ShadowTlsClient::new(client_options("pw", 4, &[]), decoy.trust.clone()).is_err());
}

#[tokio::test]
async fn v3_signs_the_hello_and_authenticates_every_record() {
    let decoy = Arc::new(decoy(true, &["http/1.1"]));
    let client =
        ShadowTlsClient::new(client_options("secret", 3, &WS_ALPN), decoy.trust.clone()).unwrap();
    let (near, far) = duplex(1 << 20);
    let server = {
        let decoy = decoy.clone();
        tokio::spawn(async move { serve_v3(far, &decoy, "secret").await })
    };
    roundtrip(&stack(client), near).await;
    server.abort();
}

#[tokio::test]
async fn v3_with_the_wrong_password_never_connects() {
    let decoy = Arc::new(decoy(true, &[]));
    let client =
        ShadowTlsClient::new(client_options("wrong", 3, &[]), decoy.trust.clone()).unwrap();
    let (near, far) = duplex(1 << 20);
    let server = {
        let decoy = decoy.clone();
        tokio::spawn(async move { serve_v3(far, &decoy, "secret").await })
    };
    let result = stack(client).apply(Box::new(near), "decoy.test").await;
    assert!(result.is_err());
    let _ = server.await;
}

#[tokio::test]
async fn v3_rejects_a_decoy_that_is_not_tls13() {
    let decoy = Arc::new(decoy(false, &[]));
    let tls12_only = Decoy {
        config: {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let key = KeyPair::generate().unwrap();
            let cert = CertificateParams::new(vec!["decoy.test".to_owned()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            Arc::new(
                ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS12])
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![cert.der().clone()],
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                    )
                    .unwrap(),
            )
        },
        trust: decoy.trust.clone(),
    };
    let client =
        ShadowTlsClient::new(client_options("secret", 3, &[]), decoy.trust.clone()).unwrap();
    let (near, far) = duplex(1 << 20);
    let server = tokio::spawn(async move { serve_v3(far, &tls12_only, "secret").await });
    let result = stack(client).apply(Box::new(near), "decoy.test").await;
    assert!(result.is_err());
    server.abort();
}

#[tokio::test]
async fn tls_layer_and_tls_dial_check_alpn() {
    let decoy = decoy(true, &["h2"]);
    let connector = |alpn: &[&str]| {
        Arc::new(
            TlsConnector::new(
                TlsOptions {
                    server_name: Some("decoy.test".into()),
                    alpn: alpn.iter().map(|a| (*a).to_owned()).collect(),
                    ..TlsOptions::default()
                },
                decoy.trust.clone(),
            )
            .unwrap(),
        )
    };
    let dial_inner: concord_transport::DialFn = {
        let config = decoy.config.clone();
        Arc::new(move || {
            let config = config.clone();
            Box::pin(async move {
                let (near, far) = duplex(1 << 16);
                let acceptor = tokio_rustls::TlsAcceptor::from(config);
                tokio::spawn(async move {
                    if let Ok(mut stream) = acceptor.accept(far).await {
                        let mut buf = [0u8; 16];
                        if let Ok(n) = stream.read(&mut buf).await {
                            let _ = stream.write_all(&buf[..n]).await;
                        }
                    }
                });
                Ok(Box::new(near) as BoxStream)
            })
        })
    };

    let ok = tls_dial(
        dial_inner.clone(),
        connector(&["h2"]),
        "decoy.test".into(),
        Some("h2"),
    );
    let mut io = ok().await.unwrap();
    io.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    io.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");

    let mismatch = tls_dial(
        dial_inner.clone(),
        connector(&["http/1.1"]),
        "decoy.test".into(),
        Some("h2"),
    );
    assert!(mismatch().await.is_err());

    let stack = TransportStack::new(vec![Layer::Tls(connector(&["h2"]))], Default::default());
    let (near, far) = duplex(1 << 16);
    let acceptor = tokio_rustls::TlsAcceptor::from(decoy.config.clone());
    tokio::spawn(async move {
        if let Ok(mut stream) = acceptor.accept(far).await {
            let _ = stream.write_all(b"hi").await;
            let _ = stream.flush().await;
            let mut sink = [0u8; 8];
            let _ = stream.read(&mut sink).await;
        }
    });
    let mut io = stack.apply(Box::new(near), "decoy.test").await.unwrap();
    let mut got = [0u8; 2];
    io.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hi");
}
