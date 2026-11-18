use std::io;
use std::sync::Arc;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, UnparsedPublicKey, X25519};
use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_768};
use aws_lc_rs::signature::{self, ED25519};
use concord_common::{BoxStream, Tasks};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod verify;
use verify::certificate_verify_message;

use super::cert::{hmac_matches, parse_ed25519_cert, verify_mldsa};
use super::hello::{HelloParams, SESSION_ID_LEN, SESSION_ID_OFFSET, build_client_hello};
use super::schedule::{
    CT_ALERT, CT_HANDSHAKE, Hash, RecordKey, Suite, application_secrets, expand, extract,
    finished_verify_data, handshake_secrets,
};
use super::spider;
use super::stream::RealityStream;
use super::wire::{Cursor, put_u24};
use crate::error::invalid_data;
use crate::fingerprints::{
    ClientFingerprint, FingerprintSpec, GROUP_X25519, GROUP_X25519_MLKEM768,
};
use crate::policy::CertPolicy;
use crate::record::RecordStream;
use crate::record_io::RecordIo;
use crate::{RealityOptions, TlsError, TlsOptions, TrustStore};

const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_COMPRESSED_CERTIFICATE: u8 = 25;
const SCHEME_ED25519: u16 = 0x0807;
const MAX_HANDSHAKE: usize = 65_536;
const MAX_CERTIFICATE_MESSAGE: usize = 262_144;
const MAX_DECOMPRESSED: usize = (1 << 24) - 1;
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

pub type SessionIdSealer<'a> =
    &'a (dyn Fn(&[u8]) -> io::Result<[u8; SESSION_ID_LEN]> + Send + Sync);

enum Established {
    Reality(Box<RealityStream>),
    Raw {
        io: BoxStream,
        alpn: Option<Vec<u8>>,
    },
}

pub(crate) struct RealityClient {
    options: Option<RealityOptions>,
    jls: Option<crate::JlsAuth>,
    /// A decoy hello offers X25519MLKEM768 only when its protocol survives the larger hello.
    decoy_hybrid: bool,
    spec: &'static FingerprintSpec,
    browser: spider::Browser,
    alpn: Vec<String>,
    policy: Arc<CertPolicy>,
}

struct Record {
    header: [u8; 5],
    body: Vec<u8>,
}

async fn read_record(io: &mut RecordIo<BoxStream>) -> io::Result<Record> {
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await?;
    let [_, _, _, hi, lo] = header;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes([hi, lo]))];
    io.read_exact(&mut body).await?;
    Ok(Record { header, body })
}

async fn read_server_hello(io: &mut RecordIo<BoxStream>) -> io::Result<Vec<u8>> {
    let mut hello = Vec::new();
    loop {
        let record = read_record(io).await?;
        match record.header.first().copied() {
            Some(20) if record.body == [1] => continue,
            Some(21) => return Err(alert_error(&record.body)),
            Some(22) => {
                if hello.is_empty()
                    && let Some(&[_, a, b, c]) = record.body.first_chunk::<4>()
                {
                    let len = (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c);
                    if record.body.len() == 4 + len {
                        return Ok(record.body);
                    }
                }
                hello.extend_from_slice(&record.body);
            }
            _ => return Err(invalid_data("TLS: expected a handshake record")),
        }
        if let Some(&[_, a, b, c]) = hello.first_chunk::<4>() {
            let len = (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c);
            if len > MAX_HANDSHAKE || hello.len() > 4 + len {
                return Err(invalid_data("TLS: invalid ServerHello length"));
            }
            if hello.len() == 4 + len {
                return Ok(hello);
            }
        }
    }
}

fn alert_error(body: &[u8]) -> io::Error {
    let description = body.get(1).copied().unwrap_or(0);
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!("REALITY: server sent tls alert {description}"),
    )
}

struct ServerHello {
    cipher: u16,
    session_id: Vec<u8>,
    group: u16,
    key_share: Vec<u8>,
}

fn parse_server_hello(message: &[u8]) -> io::Result<ServerHello> {
    let mut outer = Cursor::new(message);
    if outer.u8()? != HS_SERVER_HELLO {
        return Err(invalid_data("REALITY: expected ServerHello"));
    }
    let body = outer.vec24()?;
    if !outer.is_empty() {
        return Err(invalid_data("REALITY: trailing bytes after ServerHello"));
    }
    let mut cursor = Cursor::new(body);
    if cursor.u16()? != 0x0303 {
        return Err(invalid_data("REALITY: unexpected ServerHello version"));
    }
    if cursor.take(32)? == HELLO_RETRY_RANDOM {
        return Err(invalid_data("REALITY: HelloRetryRequest is not supported"));
    }
    let session_id = cursor.vec8()?.to_vec();
    let cipher = cursor.u16()?;
    if cursor.u8()? != 0 {
        return Err(invalid_data("REALITY: invalid ServerHello compression"));
    }
    let mut extensions = Cursor::new(cursor.vec16()?);
    let mut tls13 = false;
    let mut share = None;
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        match kind {
            43 => tls13 = data == [0x03, 0x04],
            51 => {
                let mut share_cursor = Cursor::new(data);
                let group = share_cursor.u16()?;
                share = Some((group, share_cursor.vec16()?.to_vec()));
            }
            _ => {}
        }
    }
    let (group, key_share) =
        share.ok_or_else(|| invalid_data("REALITY: ServerHello has no key share"))?;
    if !tls13 {
        return Err(invalid_data("REALITY: server did not negotiate TLS 1.3"));
    }
    Ok(ServerHello {
        cipher,
        session_id,
        group,
        key_share,
    })
}

struct Message {
    kind: u8,
    body: Vec<u8>,
    raw: Vec<u8>,
}

fn next_message(buf: &mut Vec<u8>) -> io::Result<Option<Message>> {
    let Some(header) = buf.get(..4) else {
        return Ok(None);
    };
    let kind = header.first().copied().unwrap_or(0);
    let len = Cursor::new(header.get(1..).unwrap_or_default()).u24()?;
    let max = match kind {
        HS_CERTIFICATE | HS_COMPRESSED_CERTIFICATE => MAX_CERTIFICATE_MESSAGE,
        _ => MAX_HANDSHAKE,
    };
    if len > max {
        return Err(invalid_data("REALITY: handshake message too large"));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let rest = buf.split_off(4 + len);
    let raw = std::mem::replace(buf, rest);
    let body = raw.get(4..).unwrap_or_default().to_vec();
    Ok(Some(Message { kind, body, raw }))
}

async fn fill_handshake(
    io: &mut RecordIo<BoxStream>,
    key: &mut RecordKey,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    loop {
        let mut record = read_record(io).await?;
        match record.header.first().copied() {
            Some(20) => continue,
            Some(21) => return Err(alert_error(&record.body)),
            Some(23) => {}
            _ => return Err(invalid_data("REALITY: expected an encrypted record")),
        }
        let (inner, len) = key.open_in_place(&record.header, &mut record.body)?;
        match inner {
            CT_HANDSHAKE => {
                buf.extend_from_slice(record.body.get(..len).unwrap_or_default());
                return Ok(());
            }
            CT_ALERT => return Err(alert_error(record.body.get(..len).unwrap_or_default())),
            _ => return Err(invalid_data("REALITY: unexpected record in handshake")),
        }
    }
}

fn parse_alpn(extensions: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let mut cursor = Cursor::new(extensions);
    while !cursor.is_empty() {
        let kind = cursor.u16()?;
        let data = cursor.vec16()?;
        if kind == 16 {
            let mut list = Cursor::new(Cursor::new(data).vec16()?);
            return Ok(Some(list.vec8()?.to_vec()));
        }
    }
    Ok(None)
}

fn parse_certificates(body: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut cursor = Cursor::new(body);
    cursor.vec8()?;
    let mut list = Cursor::new(cursor.vec24()?);
    let mut chain = Vec::new();
    while !list.is_empty() {
        chain.push(list.vec24()?.to_vec());
        list.vec16()?;
    }
    Ok(chain)
}

fn decompress_certificate(spec: &FingerprintSpec, body: &[u8]) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut cursor = Cursor::new(body);
    let algorithm = cursor.u16()?;
    let expected = cursor.u24()?;
    let compressed = cursor.vec24()?;
    if !spec.cert_compression.contains(&algorithm) || expected > MAX_DECOMPRESSED {
        return Err(invalid_data("REALITY: unsolicited certificate compression"));
    }
    let mut out = Vec::with_capacity(expected);
    let limit = u64::try_from(expected).unwrap_or(0) + 1;
    match algorithm {
        1 => flate2::read::ZlibDecoder::new(compressed)
            .take(limit)
            .read_to_end(&mut out)?,
        2 => brotli_decompressor::Decompressor::new(compressed, 4096)
            .take(limit)
            .read_to_end(&mut out)?,
        _ => return Err(invalid_data("REALITY: unknown certificate compression")),
    };
    if out.len() != expected {
        return Err(invalid_data("REALITY: certificate length mismatch"));
    }
    Ok(out)
}

fn weak_secret(secret: &[u8]) -> bool {
    secret.iter().all(|byte| *byte == 0)
}

impl RealityClient {
    pub(crate) fn new(
        options: RealityOptions,
        fingerprint: Option<ClientFingerprint>,
        alpn: Vec<String>,
        trust: Arc<TrustStore>,
        tasks: &Tasks,
    ) -> Result<Self, TlsError> {
        let policy = Arc::new(CertPolicy::new(&TlsOptions::default(), trust)?);
        Self::build(Some(options), fingerprint, alpn, policy, tasks)
    }

    pub(crate) fn jls(options: &TlsOptions, trust: Arc<TrustStore>) -> Result<Self, TlsError> {
        let auth = options
            .jls
            .clone()
            .ok_or_else(|| TlsError::Config("jls: missing credentials".into()))?;
        if auth.username.is_empty() || auth.password.is_empty() {
            return Err(TlsError::Config(
                "jls: username and password are required".into(),
            ));
        }
        let fingerprint = options
            .client_fingerprint
            .map(ClientFingerprint::resolve_random);
        if fingerprint
            .and_then(|fp| fp.spec())
            .is_some_and(|spec| !spec.tls13)
        {
            return Err(TlsError::Config(
                "jls: fingerprint does not support TLS 1.3".into(),
            ));
        }
        let policy = Arc::new(CertPolicy::new(&TlsOptions::default(), trust)?);
        let alpn = options.alpn.clone();
        let mut client = Self::build(None, fingerprint, alpn, policy, &options.tasks)?;
        if fingerprint.is_none_or(|fp| fp == ClientFingerprint::None) {
            client.spec = &crate::jls::NATIVE;
        }
        client.jls = Some(auth);
        client.decoy_hybrid = true;
        Ok(client)
    }

    pub(crate) fn decoy(
        options: &TlsOptions,
        trust: Arc<TrustStore>,
        hybrid: bool,
    ) -> Result<Self, TlsError> {
        let policy = Arc::new(CertPolicy::new(options, trust)?);
        let mut client = Self::build(
            None,
            options.client_fingerprint,
            options.alpn.clone(),
            policy,
            &options.tasks,
        )?;
        client.decoy_hybrid = hybrid;
        Ok(client)
    }

    fn build(
        options: Option<RealityOptions>,
        fingerprint: Option<ClientFingerprint>,
        alpn: Vec<String>,
        policy: Arc<CertPolicy>,
        tasks: &Tasks,
    ) -> Result<Self, TlsError> {
        let requested = fingerprint.unwrap_or(ClientFingerprint::Chrome);
        let resolved = match requested {
            ClientFingerprint::None => ClientFingerprint::Chrome,
            other => other.resolve_random(),
        };
        let spec = match resolved.spec().filter(|spec| spec.tls13) {
            Some(spec) => spec,
            None => {
                tracing::warn!(
                    "client-fingerprint {resolved} has no TLS 1.3 hello for REALITY; using chrome"
                );
                ClientFingerprint::Chrome
                    .spec()
                    .ok_or_else(|| TlsError::Config("chrome fingerprint missing".into()))?
            }
        };
        let user_agent = match spec.name {
            "firefox" => "Firefox",
            "safari" => "Safari",
            "ios" => "iOS",
            "edge" => "Edge",
            "qq" => "QQBrowser",
            _ => "Chrome",
        };
        Ok(Self {
            options,
            jls: None,
            decoy_hybrid: false,
            spec,
            browser: spider::Browser {
                user_agent,
                tasks: tasks.clone(),
            },
            alpn,
            policy,
        })
    }

    pub(crate) async fn connect(
        &self,
        io: BoxStream,
        name: &ServerName<'static>,
    ) -> io::Result<RealityStream> {
        let run = self.run(io, name, None);
        let established = if self.jls.is_some() {
            tokio::time::timeout(crate::jls::HANDSHAKE_TIMEOUT, run)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "JLS: handshake timed out"))?
                .map_err(|err| {
                    let text = err.to_string();
                    match text.strip_prefix("REALITY:") {
                        Some(message) => io::Error::new(err.kind(), format!("JLS:{message}")),
                        None => err,
                    }
                })?
        } else {
            run.await?
        };
        match established {
            Established::Reality(stream) => Ok(*stream),
            Established::Raw { .. } => Err(invalid_data("REALITY: unexpected handshake outcome")),
        }
    }

    pub(crate) async fn connect_decoy(
        &self,
        io: BoxStream,
        name: &ServerName<'static>,
        sealer: SessionIdSealer<'_>,
    ) -> io::Result<(BoxStream, Option<Vec<u8>>)> {
        match self.run(io, name, Some(sealer)).await? {
            Established::Raw { io, alpn } => Ok((io, alpn)),
            Established::Reality(_) => Err(invalid_data("TLS: unexpected handshake outcome")),
        }
    }

    async fn run(
        &self,
        io: BoxStream,
        name: &ServerName<'static>,
        sealer: Option<SessionIdSealer<'_>>,
    ) -> io::Result<Established> {
        let mut io = RecordIo::new(io);
        let sni = match name {
            ServerName::DnsName(dns) => Some(dns.as_ref().to_owned()),
            _ => None,
        };

        let x25519 = agreement::PrivateKey::generate(&X25519)
            .map_err(|_| invalid_data("REALITY: x25519 keygen"))?;
        let x25519_public: [u8; 32] = x25519
            .compute_public_key()
            .map_err(|_| invalid_data("REALITY: x25519 public key"))?
            .as_ref()
            .try_into()
            .map_err(|_| invalid_data("REALITY: x25519 public key length"))?;
        let mlkem = if (self.decoy_hybrid
            || self
                .options
                .as_ref()
                .is_some_and(|o| o.support_x25519mlkem768))
            && self.spec.offers_mlkem()
        {
            Some(
                DecapsulationKey::generate(&ML_KEM_768)
                    .map_err(|_| invalid_data("REALITY: ml-kem keygen"))?,
            )
        } else {
            None
        };
        let mlkem_public = match &mlkem {
            Some(key) => Some(
                key.encapsulation_key()
                    .and_then(|ek| ek.key_bytes())
                    .map_err(|_| invalid_data("REALITY: ml-kem public key"))?,
            ),
            None => None,
        };
        let mut random = [0u8; 32];
        aws_lc_rs::rand::fill(&mut random).map_err(|_| invalid_data("REALITY: random"))?;

        let mut hello = build_client_hello(
            self.spec,
            &HelloParams {
                jls: self.jls.is_some(),
                server_name: sni.as_deref(),
                alpn: (self.jls.is_some() || !self.alpn.is_empty()).then_some(self.alpn.as_slice()),
                random: &random,
                x25519_public: &x25519_public,
                mlkem_encapsulation_key: mlkem_public.as_ref().map(|key| key.as_ref()),
            },
        )?;

        let (session_id, auth_key) = match (&self.options, sealer) {
            (Some(options), None) => {
                let (session_id, auth_key) = seal_reality(
                    options,
                    &x25519,
                    &random,
                    &hello,
                    self.policy.now().as_secs(),
                )?;
                (session_id, Some(auth_key))
            }
            (None, Some(sealer)) => (sealer(&hello)?, None),
            (None, None) if self.jls.is_some() => (rand::random(), None),
            _ => return Err(invalid_data("TLS: handshake mode mismatch")),
        };
        hello
            .get_mut(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
            .ok_or_else(|| invalid_data("REALITY: hello layout"))?
            .copy_from_slice(&session_id);
        if let Some(auth) = &self.jls {
            auth.seal(&mut hello)?;
        }

        let mut record = vec![22, 3, 1];
        record.extend_from_slice(
            &u16::try_from(hello.len())
                .map_err(|_| invalid_data("REALITY: hello too large"))?
                .to_be_bytes(),
        );
        record.extend_from_slice(&hello);
        io.write_all(&record).await?;
        io.flush().await?;

        let server_hello_raw = read_server_hello(&mut io).await?;
        let server_hello = parse_server_hello(&server_hello_raw)?;
        if server_hello.session_id != session_id {
            return Err(invalid_data("REALITY: server did not echo the session id"));
        }
        let suite = Suite::from_id(server_hello.cipher)
            .ok_or_else(|| invalid_data("REALITY: unsupported cipher suite"))?;
        let hash = suite.hash();

        let shared = match (server_hello.group, &mlkem) {
            (GROUP_X25519, _) => x25519_agree(&x25519, &server_hello.key_share)?,
            (GROUP_X25519_MLKEM768, Some(key)) => {
                let (ciphertext, x_share) = server_hello
                    .key_share
                    .split_at_checked(MLKEM768_CIPHERTEXT_LEN)
                    .filter(|(_, x)| x.len() == 32)
                    .ok_or_else(|| invalid_data("REALITY: bad hybrid key share"))?;
                let mut shared = key
                    .decapsulate(ciphertext.into())
                    .map_err(|_| invalid_data("REALITY: ml-kem decapsulation failed"))?
                    .as_ref()
                    .to_vec();
                shared.extend_from_slice(&x25519_agree(&x25519, x_share)?);
                shared
            }
            _ => {
                return Err(invalid_data(
                    "REALITY: server selected an unoffered key share",
                ));
            }
        };

        let mut transcript = hello;
        transcript.extend_from_slice(&server_hello_raw);
        let mldsa = self
            .options
            .as_ref()
            .and_then(|options| options.mldsa65_verify.as_deref())
            .map(|key| (key, transcript.clone()));
        let secrets = handshake_secrets(hash, &shared, &transcript);
        let mut server_key = RecordKey::new(suite, &secrets.server)?;
        let mut client_key = RecordKey::new(suite, &secrets.client)?;

        let flight = self
            .read_flight(
                &mut io,
                &mut server_key,
                &mut transcript,
                hash,
                &secrets.server,
            )
            .await?;

        let authenticated =
            self.authenticate(&flight, &server_hello_raw, auth_key.as_deref(), mldsa, name)?;

        let mut finished = vec![HS_FINISHED];
        let verify_data = finished_verify_data(hash, &secrets.client, &transcript);
        put_u24(&mut finished, verify_data.len());
        finished.extend_from_slice(&verify_data);
        io.write_all(&client_key.seal(CT_HANDSHAKE, &finished)?)
            .await?;
        io.flush().await?;

        if sealer.is_some() {
            return Ok(Established::Raw {
                io: io.into_inner(),
                alpn: flight.alpn,
            });
        }
        let (client_secret, server_secret) =
            application_secrets(hash, &secrets.master, &transcript);
        let keys = crate::ciphers::tls13_keys(suite, client_secret, server_secret, 0, 0)?;
        let stream = RealityStream::new(
            RecordStream::new(io, keys, flight.alpn, Vec::new(), Vec::new()),
            server_hello.group,
        );
        if authenticated {
            return Ok(Established::Reality(Box::new(stream)));
        }
        if self.jls.is_some() {
            if !std::ptr::eq(self.spec, &crate::jls::NATIVE) {
                self.browser.jls_fallback(stream, name).await;
            }
            Err(invalid_data("jls authentication failed"))
        } else {
            self.browser.spawn(stream, sni.unwrap_or_default());
            Err(invalid_data("REALITY authentication failed"))
        }
    }

    fn authenticate(
        &self,
        flight: &Flight,
        server_hello_raw: &[u8],
        auth_key: Option<&[u8]>,
        mldsa: Option<(&[u8], Vec<u8>)>,
        name: &ServerName<'static>,
    ) -> io::Result<bool> {
        if self.jls.is_some()
            && flight
                .alpn
                .as_ref()
                .is_some_and(|alpn| !self.alpn.iter().any(|offered| offered.as_bytes() == alpn))
        {
            return Err(invalid_data("jls: server selected an unoffered ALPN"));
        }
        let cv_hash = flight.certificate_verify_hash.clone();
        if let Some(auth) = &self.jls {
            let authenticated = auth.verify(server_hello_raw)?;
            if authenticated {
                self.verify_signature(flight, &cv_hash)?;
            } else {
                self.verify_fallback_chain(flight, &cv_hash, name)?;
            }
            Ok(authenticated)
        } else {
            match flight
                .chain
                .first()
                .and_then(|leaf| parse_ed25519_cert(leaf))
            {
                Some(cert) if auth_key.is_some_and(|key| hmac_matches(key, &cert)) => {
                    if flight.signature_scheme != SCHEME_ED25519 {
                        return Err(invalid_data("REALITY: unexpected signature scheme"));
                    }
                    signature::UnparsedPublicKey::new(&ED25519, &cert.public_key)
                        .verify(&certificate_verify_message(&cv_hash), &flight.signature)
                        .map_err(|_| {
                            invalid_data("REALITY: CertificateVerify signature mismatch")
                        })?;
                    if let Some((key, hellos)) = mldsa {
                        verify_mldsa(auth_key.unwrap_or_default(), &cert, key, &hellos)?;
                    }
                    Ok(true)
                }
                _ => {
                    self.verify_fallback_chain(flight, &cv_hash, name)?;
                    Ok(false)
                }
            }
        }
    }

    async fn read_flight(
        &self,
        io: &mut RecordIo<BoxStream>,
        key: &mut RecordKey,
        transcript: &mut Vec<u8>,
        hash: Hash,
        server_secret: &[u8],
    ) -> io::Result<Flight> {
        #[derive(PartialEq, PartialOrd, Clone, Copy)]
        enum Stage {
            Start,
            EncryptedExtensions,
            Certificate,
            CertificateVerify,
        }
        let mut stage = Stage::Start;
        let mut buf = Vec::new();
        let mut flight = Flight::default();
        loop {
            let Some(message) = next_message(&mut buf)? else {
                fill_handshake(io, key, &mut buf).await?;
                continue;
            };
            match (message.kind, stage) {
                (HS_ENCRYPTED_EXTENSIONS, Stage::Start) => {
                    let mut cursor = Cursor::new(&message.body);
                    flight.alpn = parse_alpn(cursor.vec16()?)?;
                    stage = Stage::EncryptedExtensions;
                }
                (HS_CERTIFICATE, Stage::EncryptedExtensions) => {
                    flight.chain = parse_certificates(&message.body)?;
                    stage = Stage::Certificate;
                }
                (HS_COMPRESSED_CERTIFICATE, Stage::EncryptedExtensions) => {
                    let body = decompress_certificate(self.spec, &message.body)?;
                    flight.chain = parse_certificates(&body)?;
                    stage = Stage::Certificate;
                }
                (HS_CERTIFICATE_VERIFY, Stage::Certificate) => {
                    let mut cursor = Cursor::new(&message.body);
                    flight.signature_scheme = cursor.u16()?;
                    flight.signature = cursor.vec16()?.to_vec();
                    flight.certificate_verify_hash = hash.digest(transcript);
                    stage = Stage::CertificateVerify;
                }
                (HS_FINISHED, Stage::CertificateVerify) => {
                    let expected = finished_verify_data(hash, server_secret, transcript);
                    if message.body != expected || !buf.is_empty() {
                        return Err(invalid_data("REALITY: server Finished mismatch"));
                    }
                    transcript.extend_from_slice(&message.raw);
                    if flight.chain.is_empty() {
                        return Err(invalid_data("REALITY: server sent no certificate"));
                    }
                    return Ok(flight);
                }
                _ => return Err(invalid_data("REALITY: unexpected handshake message")),
            }
            transcript.extend_from_slice(&message.raw);
        }
    }
}

#[derive(Default)]
struct Flight {
    alpn: Option<Vec<u8>>,
    chain: Vec<Vec<u8>>,
    signature_scheme: u16,
    signature: Vec<u8>,
    certificate_verify_hash: Vec<u8>,
}

fn x25519_agree(private: &agreement::PrivateKey, peer: &[u8]) -> io::Result<Vec<u8>> {
    let secret = agreement::agree(
        private,
        UnparsedPublicKey::new(&X25519, peer),
        (),
        |secret| Ok(secret.to_vec()),
    )
    .map_err(|()| invalid_data("REALITY: x25519 agreement failed"))?;
    if weak_secret(&secret) {
        return Err(invalid_data("REALITY: x25519 agreement failed"));
    }
    Ok(secret)
}

fn seal_reality(
    options: &RealityOptions,
    x25519: &agreement::PrivateKey,
    random: &[u8; 32],
    hello: &[u8],
    unix: u64,
) -> io::Result<([u8; SESSION_ID_LEN], Vec<u8>)> {
    let ecdh = agreement::agree(
        x25519,
        UnparsedPublicKey::new(&X25519, &options.public_key),
        (),
        |secret| Ok(secret.to_vec()),
    )
    .map_err(|()| invalid_data("REALITY: auth key agreement failed"))?;
    if weak_secret(&ecdh) {
        return Err(invalid_data("REALITY: auth key agreement failed"));
    }
    let (salt, nonce_bytes) = random.split_at(20);
    let auth_key = expand(&extract(Hash::Sha256, salt, &ecdh), b"REALITY", 32);

    let [_, _, _, _, t4, t5, t6, t7] = unix.to_be_bytes();
    let [s0, s1, s2, s3, s4, s5, s6, s7] = options.short_id;
    let [v0, v1, v2] = options.client_version;
    let mut sealed = [
        v0, v1, v2, 0, t4, t5, t6, t7, s0, s1, s2, s3, s4, s5, s6, s7,
    ];
    let aead = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &auth_key)
            .map_err(|_| invalid_data("REALITY: auth key rejected"))?,
    );
    let nonce_bytes: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| invalid_data("REALITY: nonce"))?;
    let tag = aead
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(hello),
            &mut sealed,
        )
        .map_err(|_| invalid_data("REALITY: session id seal"))?;
    let mut session_id = [0u8; SESSION_ID_LEN];
    let (sealed_part, tag_part) = session_id.split_at_mut(sealed.len());
    sealed_part.copy_from_slice(&sealed);
    tag_part.copy_from_slice(tag.as_ref());
    Ok((session_id, auth_key))
}
