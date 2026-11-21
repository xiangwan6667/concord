use std::error::Error as _;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use boring::pkey::PKey;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, Ssl, SslAlert, SslContext,
    SslContextBuilder, SslMethod, SslMode, SslOptions, SslRef, SslSessionCacheMode, SslVerifyError,
    SslVerifyMode, SslVersion,
};
use boring::x509::X509;
use concord_common::BoxStream;
use concord_common::sync::lock;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

use crate::TlsError;
use crate::ciphers;
use crate::client_auth::ClientAuth;
use crate::conn::TlsConn;
use crate::ech::BoringRejection;
use crate::fingerprints::{Ext, FingerprintSpec, GREASE};
use crate::policy::CertPolicy;
use crate::reality::schedule::Suite;
use crate::record::{Keys, RecordStream};
use crate::record_io::RecordIo;

pub(crate) type BoringStream = tokio_boring::SslStream<RecordIo<BoxStream>>;

/// The application traffic secrets BoringSSL logged for one connection.
#[derive(Default)]
pub(crate) struct Logged {
    client: Option<Vec<u8>>,
    server: Option<Vec<u8>>,
}

pub(crate) type LogSlot = Arc<Mutex<Logged>>;

struct VerifyCx {
    name: ServerName<'static>,
    failure: Mutex<Option<String>>,
}

pub(crate) struct BoringConnector {
    ctx: SslContext,
    index: boring::ex_data::Index<Ssl, Arc<VerifyCx>>,
    log: boring::ex_data::Index<Ssl, LogSlot>,
    ech_grease: bool,
    ech_config_list: Option<Vec<u8>>,
}

struct Brotli;

impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let reader = brotli_decompressor::Decompressor::new(input, 4096);
        copy_capped(reader, output)
    }
}

struct Zlib;

impl CertificateCompressor for Zlib {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        copy_capped(flate2::read::ZlibDecoder::new(input), output)
    }
}

const MAX_DECOMPRESSED_CERTS: u64 = (1 << 24) - 1;

fn copy_capped<R: Read, W: Write>(reader: R, output: &mut W) -> io::Result<()> {
    io::copy(&mut reader.take(MAX_DECOMPRESSED_CERTS), output).map(|_| ())
}

fn cipher_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0xc02b => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xc02f => "ECDHE-RSA-AES128-GCM-SHA256",
        0xc02c => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xc030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xcca9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        0xcca8 => "ECDHE-RSA-CHACHA20-POLY1305",
        0xc009 => "ECDHE-ECDSA-AES128-SHA",
        0xc00a => "ECDHE-ECDSA-AES256-SHA",
        0xc013 => "ECDHE-RSA-AES128-SHA",
        0xc014 => "ECDHE-RSA-AES256-SHA",
        0x009c => "AES128-GCM-SHA256",
        0x009d => "AES256-GCM-SHA384",
        0x002f => "AES128-SHA",
        0x0035 => "AES256-SHA",
        0x000a => "DES-CBC3-SHA",
        _ => return None,
    })
}

fn curve_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x11ec => "X25519MLKEM768",
        0x001d => "X25519",
        0x0017 => "P-256",
        0x0018 => "P-384",
        0x0019 => "P-521",
        _ => return None,
    })
}

fn sigalg_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0403 => "ECDSA+SHA256",
        0x0503 => "ECDSA+SHA384",
        0x0603 => "ECDSA+SHA512",
        0x0804 => "RSA-PSS+SHA256",
        0x0805 => "RSA-PSS+SHA384",
        0x0806 => "RSA-PSS+SHA512",
        0x0401 => "RSA+SHA256",
        0x0501 => "RSA+SHA384",
        0x0601 => "RSA+SHA512",
        0x0201 => "RSA+SHA1",
        _ => return None,
    })
}

fn joined(names: impl Iterator<Item = Option<&'static str>>) -> String {
    let mut seen: Vec<&'static str> = Vec::new();
    for name in names.flatten() {
        if !seen.contains(&name) {
            seen.push(name);
        }
    }
    seen.join(":")
}

fn boring_err(what: &str, err: boring::error::ErrorStack) -> TlsError {
    TlsError::Config(format!("boringssl {what}: {err}"))
}

fn alpn_wire(protocols: &[String]) -> Result<Vec<u8>, TlsError> {
    let mut wire = Vec::new();
    for proto in protocols {
        let len = u8::try_from(proto.len())
            .ok()
            .filter(|len| *len > 0)
            .ok_or_else(|| TlsError::Config(format!("invalid ALPN protocol {proto:?}")))?;
        wire.push(len);
        wire.extend_from_slice(proto.as_bytes());
    }
    Ok(wire)
}

impl BoringConnector {
    pub(crate) fn new(
        spec: &'static FingerprintSpec,
        policy: Arc<CertPolicy>,
        alpn: &[String],
        client_auth: Option<ClientAuth>,
        ech_config_list: Option<Vec<u8>>,
    ) -> Result<Self, TlsError> {
        let mut builder =
            SslContextBuilder::new(SslMethod::tls()).map_err(|e| boring_err("context", e))?;
        builder.set_mode(SslMode::ENABLE_PARTIAL_WRITE | SslMode::ACCEPT_MOVING_WRITE_BUFFER);
        let mut options = SslOptions::NO_COMPRESSION;
        if !spec.extensions.contains(&Ext::SessionTicket) {
            options |= SslOptions::NO_TICKET;
        }
        builder.set_options(options);
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| boring_err("min version", e))?;
        let max = if spec.tls13 {
            SslVersion::TLS1_3
        } else {
            SslVersion::TLS1_2
        };
        builder
            .set_max_proto_version(Some(max))
            .map_err(|e| boring_err("max version", e))?;
        builder.set_grease_enabled(spec.grease);
        builder.set_permute_extensions(spec.permute_extensions);

        let ciphers = joined(
            spec.cipher_suites
                .iter()
                .filter(|id| **id != GREASE)
                .map(|id| cipher_name(*id)),
        );
        builder
            .set_cipher_list(&ciphers)
            .map_err(|e| boring_err("cipher list", e))?;
        let curves = joined(spec.groups.iter().map(|id| curve_name(*id)));
        builder
            .set_curves_list(&curves)
            .map_err(|e| boring_err("curves", e))?;
        let sigalgs = joined(spec.signature_algorithms.iter().map(|id| sigalg_name(*id)));
        builder
            .set_sigalgs_list(&sigalgs)
            .map_err(|e| boring_err("signature algorithms", e))?;
        if spec.extensions.contains(&Ext::Sct) {
            builder.enable_signed_cert_timestamps();
        }
        if spec.extensions.contains(&Ext::StatusRequest) {
            builder.enable_ocsp_stapling();
        }
        for algo in spec.cert_compression {
            let added = match algo {
                1 => builder.add_certificate_compression_algorithm(Zlib),
                2 => builder.add_certificate_compression_algorithm(Brotli),
                _ => Ok(()),
            };
            added.map_err(|e| boring_err("certificate compression", e))?;
        }

        let protocols: Vec<String> = if alpn.is_empty() {
            spec.alpn.iter().map(|p| (*p).to_owned()).collect()
        } else {
            alpn.to_vec()
        };
        if !protocols.is_empty() && spec.extensions.contains(&Ext::Alpn) {
            builder
                .set_alpn_protos(&alpn_wire(&protocols)?)
                .map_err(|e| boring_err("alpn", e))?;
        }

        if let Some(auth) = client_auth {
            let mut certs = auth.chain.iter();
            let leaf = certs
                .next()
                .ok_or_else(|| TlsError::Config("client certificate chain is empty".into()))?;
            let leaf = X509::from_der(leaf.as_ref()).map_err(|e| boring_err("client cert", e))?;
            builder
                .set_certificate(&leaf)
                .map_err(|e| boring_err("client cert", e))?;
            for extra in certs {
                let extra =
                    X509::from_der(extra.as_ref()).map_err(|e| boring_err("client cert", e))?;
                builder
                    .add_extra_chain_cert(extra)
                    .map_err(|e| boring_err("client cert", e))?;
            }
            let key = PKey::private_key_from_der(auth.key.secret_der())
                .map_err(|e| boring_err("client key", e))?;
            builder
                .set_private_key(&key)
                .map_err(|e| boring_err("client key", e))?;
        }

        let index = Ssl::new_ex_index::<Arc<VerifyCx>>().map_err(|e| boring_err("ex index", e))?;
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            verify(&policy, index, ssl)
        });
        // The callback belongs to the context, so it also sees connections that carry no slot.
        let log = Ssl::new_ex_index::<LogSlot>().map_err(|e| boring_err("ex index", e))?;
        builder.set_keylog_callback(move |ssl, line| {
            if let Some(slot) = ssl.ex_data(log) {
                record_secret(slot, line);
            }
        });
        Ok(Self {
            ctx: builder.build(),
            index,
            log,
            ech_grease: spec.ech_grease.is_some(),
            ech_config_list,
        })
    }

    /// AEAD suites leave BoringSSL's record layer once the handshake is done; a CBC suite
    /// keeps BoringSSL's stream.
    pub(crate) async fn connect(
        &self,
        name: ServerName<'static>,
        io: BoxStream,
    ) -> io::Result<TlsConn> {
        let slot = LogSlot::default();
        let mut stream = self
            .handshake(name, RecordIo::new(io), Some(slot.clone()))
            .await?;
        stream.flush().await?;
        let Some((keys, alpn)) = handoff(stream.ssl(), &slot)? else {
            return Ok(TlsConn::Boring(Box::new(stream)));
        };
        let placeholder: BoxStream = Box::new(tokio::io::duplex(1).0);
        let io = std::mem::replace(stream.get_mut(), RecordIo::new(placeholder));
        Ok(TlsConn::Record(Box::new(RecordStream::new(
            io,
            keys,
            alpn,
            Vec::new(),
            Vec::new(),
        ))))
    }

    pub(crate) async fn connect_buffered(
        &self,
        name: ServerName<'static>,
        io: BoxStream,
    ) -> io::Result<TlsConn> {
        let slot = LogSlot::default();
        let mut stream = self
            .handshake(name, RecordIo::new(io), Some(slot.clone()))
            .await?;
        stream.flush().await?;
        Ok(TlsConn::Buffered(crate::buffered::BufferedTls::boring(
            stream, slot,
        )))
    }

    #[cfg(test)]
    pub(crate) async fn connect_over<S>(
        &self,
        name: ServerName<'static>,
        io: S,
    ) -> io::Result<tokio_boring::SslStream<S>>
    where
        S: AsyncRead + tokio::io::AsyncWrite + Unpin + Debug,
    {
        self.handshake(name, io, None).await
    }

    async fn handshake<S>(
        &self,
        name: ServerName<'static>,
        io: S,
        log: Option<LogSlot>,
    ) -> io::Result<tokio_boring::SslStream<S>>
    where
        S: AsyncRead + tokio::io::AsyncWrite + Unpin + Debug,
    {
        let mut ssl = Ssl::new(&self.ctx).map_err(io::Error::other)?;
        let cx = Arc::new(VerifyCx {
            name: name.clone(),
            failure: Mutex::new(None),
        });
        ssl.set_ex_data(self.index, cx.clone());
        if let Some(slot) = log {
            ssl.set_ex_data(self.log, slot);
        }
        if let ServerName::DnsName(dns) = &name {
            ssl.set_hostname(dns.as_ref()).map_err(io::Error::other)?;
        }
        if let Some(list) = &self.ech_config_list {
            ssl.set_ech_config_list(list).map_err(io::Error::other)?;
        } else if self.ech_grease {
            ssl.set_enable_ech_grease(true);
        }
        match tokio_boring::SslStreamBuilder::new(ssl, io).connect().await {
            Ok(stream) => Ok(stream),
            Err(err) => {
                let failure = lock(&cx.failure).take();
                if failure.is_none()
                    && err
                        .source()
                        .and_then(|source| source.downcast_ref::<boring::ssl::Error>())
                        .is_some_and(boring::ssl::Error::is_ech_rejected)
                    && let Some(retry) = err
                        .ssl()
                        .and_then(SslRef::get_ech_retry_configs)
                        .filter(|list| !list.is_empty())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        BoringRejection {
                            text: err.to_string(),
                            retry: retry.to_vec(),
                        },
                    ));
                }
                Err(match failure {
                    Some(text) => io::Error::new(io::ErrorKind::InvalidData, text),
                    None => io::Error::other(err.to_string()),
                })
            }
        }
    }
}

fn record_secret(slot: &LogSlot, line: &str) {
    let mut fields = line.split(' ');
    let (Some(label), Some(_), Some(secret)) = (fields.next(), fields.next(), fields.next()) else {
        return;
    };
    let Ok(secret) = hex::decode(secret) else {
        return;
    };
    let mut logged = lock(slot);
    match label {
        "CLIENT_TRAFFIC_SECRET_0" => logged.client = Some(secret),
        "SERVER_TRAFFIC_SECRET_0" => logged.server = Some(secret),
        _ => {}
    }
}

/// What BoringSSL holds when the handshake returns: its record sequence numbers, whether it
/// still has input it has not handed out, and for TLS 1.2 the key block.
struct RecordState {
    read_seq: u64,
    write_seq: u64,
    buffered: bool,
    closed: bool,
    key_block: Option<Vec<u8>>,
}

fn record_state(ssl: &SslRef, key_block: bool) -> RecordState {
    RecordState {
        read_seq: ssl.read_sequence(),
        write_seq: ssl.write_sequence(),
        buffered: ssl.has_pending(),
        closed: !ssl.shutdown_state().is_empty(),
        key_block: key_block.then(|| ssl.key_block().ok()).flatten(),
    }
}

/// The record keys to carry on without BoringSSL; None keeps BoringSSL's stream.
pub(crate) fn handoff(ssl: &SslRef, slot: &LogSlot) -> io::Result<Option<(Keys, Option<Vec<u8>>)>> {
    let Some(suite) = ssl.current_cipher().map(|cipher| cipher.protocol_id()) else {
        return Ok(None);
    };
    let version = ssl.version2();
    let tls12 = version == Some(SslVersion::TLS1_2) && ciphers::tls12_is_aead(suite);
    let state = record_state(ssl, tls12);
    if ssl.pending() > 0 || state.buffered || state.closed {
        return Ok(None);
    }
    let keys = if version == Some(SslVersion::TLS1_3) {
        let Some(suite) = Suite::from_id(suite) else {
            return Ok(None);
        };
        let (client, server) = {
            let mut logged = lock(slot);
            (logged.client.take(), logged.server.take())
        };
        let (Some(client), Some(server)) = (client, server) else {
            return Ok(None);
        };
        ciphers::tls13_keys(suite, client, server, state.write_seq, state.read_seq)?
    } else if tls12 {
        let Some(block) = state.key_block else {
            return Ok(None);
        };
        ciphers::tls12_keys(suite, &block, state.write_seq, state.read_seq)?
    } else {
        return Ok(None);
    };
    let alpn = ssl.selected_alpn_protocol().map(<[u8]>::to_vec);
    Ok(Some((keys, alpn)))
}

fn verify(
    policy: &CertPolicy,
    index: boring::ex_data::Index<Ssl, Arc<VerifyCx>>,
    ssl: &mut boring::ssl::SslRef,
) -> Result<(), SslVerifyError> {
    let Some(cx) = ssl.ex_data(index).cloned() else {
        return Err(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR));
    };
    let mut ders: Vec<Vec<u8>> = Vec::new();
    if let Some(leaf) = ssl.peer_certificate().and_then(|cert| cert.to_der().ok()) {
        ders.push(leaf);
    }
    if let Some(chain) = ssl.peer_cert_chain() {
        for cert in chain {
            let Ok(der) = cert.to_der() else { continue };
            if ders.first() != Some(&der) {
                ders.push(der);
            }
        }
    }
    let chain: Vec<CertificateDer<'_>> = ders
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let public_name = match ssl.get_ech_name_override() {
        None => None,
        Some(bytes) => match std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| ServerName::try_from(text.to_owned()).ok())
        {
            Some(name) => Some(name),
            None => return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE)),
        },
    };
    let name = public_name.as_ref().unwrap_or(&cx.name);
    match policy.verify(&chain, name, policy.now()) {
        Ok(()) => Ok(()),
        Err(err) => {
            {
                let mut slot = lock(&cx.failure);
                *slot = Some(err.to_string());
            }
            Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))
        }
    }
}

pub(crate) fn pending_plaintext<S>(stream: &tokio_boring::SslStream<S>) -> usize {
    stream.ssl().pending()
}

pub(crate) fn drain_plaintext<S>(stream: &mut tokio_boring::SslStream<S>, out: &mut Vec<u8>)
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        let pending = stream.ssl().pending();
        if pending == 0 {
            break;
        }
        let mut chunk = vec![0u8; pending];
        let mut buf = ReadBuf::new(&mut chunk);
        match Pin::new(&mut *stream).poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(())) if !buf.filled().is_empty() => out.extend_from_slice(buf.filled()),
            _ => break,
        }
    }
}
