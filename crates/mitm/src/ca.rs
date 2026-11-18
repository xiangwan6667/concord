use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use concord_common::PRODUCT_NAME;
use concord_common::sync::lock;
use concord_platform::HomeDir;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, RsaKeySize, SanType,
    SerialNumber,
};
use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;

pub const CERT_FILE_NAME: &str = "ca.crt";
pub const KEY_FILE_NAME: &str = "ca.key";
pub const AUTHORITY_DIR: &str = "mitm";

const CA_VALIDITY: Duration = Duration::days(10 * 365);
const LEAF_VALIDITY: Duration = Duration::hours(1);
const LEAF_RENEWAL: Duration = Duration::minutes(20);
const BACKDATE: Duration = Duration::hours(1);
const MAX_COMMON_NAME: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("no CA has been generated")]
    Missing,
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Io(#[from] io::Error),
}

impl CaError {
    fn invalid(message: impl Into<String>) -> CaError {
        CaError::Invalid(message.into())
    }
}

fn read_error(err: io::Error) -> CaError {
    if err.kind() == io::ErrorKind::NotFound {
        CaError::Missing
    } else {
        CaError::Io(err)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificateInfo {
    pub pem: String,
    pub fingerprint: String,
    pub subject: String,
    #[serde(rename = "not-before", with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(rename = "not-after", with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
}

struct Leaf {
    certified: Arc<CertifiedKey>,
    der: CertificateDer<'static>,
    expires: OffsetDateTime,
}

#[derive(Default)]
struct LeafCache {
    leaves: HashMap<String, (Arc<Leaf>, u64)>,
    tick: u64,
}

impl LeafCache {
    fn get(&mut self, host: &str, now: OffsetDateTime) -> Option<Arc<Leaf>> {
        self.tick += 1;
        let tick = self.tick;
        let (leaf, used) = self.leaves.get_mut(host)?;
        if now + LEAF_RENEWAL > leaf.expires {
            return None;
        }
        *used = tick;
        Some(leaf.clone())
    }

    fn insert(&mut self, host: String, leaf: Arc<Leaf>, size: usize) {
        self.tick += 1;
        self.leaves.insert(host, (leaf, self.tick));
        while self.leaves.len() > size.max(1) {
            let oldest = self
                .leaves
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(host, _)| host.clone());
            match oldest {
                Some(host) => self.leaves.remove(&host),
                None => break,
            };
        }
    }
}

struct LeafKey {
    pair: KeyPair,
    signing: Arc<dyn rustls::sign::SigningKey>,
}

/// One key serves every leaf, so issuing a leaf costs a signature only.
pub struct Ca {
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    fingerprint: String,
    subject: String,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    leaf_key: LeafKey,
    leaves: Mutex<LeafCache>,
    cache_size: AtomicUsize,
    retired: CancellationToken,
}

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl Ca {
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn info(&self) -> CertificateInfo {
        CertificateInfo {
            pem: encode_certificate(&self.cert_der),
            fingerprint: self.fingerprint.clone(),
            subject: self.subject.clone(),
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }

    pub fn set_cache_size(&self, size: usize) {
        self.cache_size.store(size, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn cached_leaves(&self) -> usize {
        lock(&self.leaves).leaves.len()
    }

    /// Cancelled once the CA is replaced, so that the clients of its decrypted
    /// connections reconnect and are handed a certificate of the new one.
    pub fn retired(&self) -> &CancellationToken {
        &self.retired
    }

    pub fn retire(&self) {
        self.retired.cancel();
    }

    /// Signs a leaf for `host` as the engine would for a client, so that the
    /// host can check whether its trust store accepts the CA's leaves.
    pub fn issue_pem(&self, host: &str) -> Result<String, CaError> {
        Ok(encode_certificate(&self.leaf(host)?.der))
    }

    pub fn server_config(&self, host: &str, alpn: &[&str]) -> Result<Arc<ServerConfig>, CaError> {
        let leaf = self.leaf(host)?;
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|err| CaError::invalid(err.to_string()))?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedCert(leaf.certified.clone())));
        config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
        Ok(Arc::new(config))
    }

    pub fn leaf_der(&self, host: &str) -> Result<CertificateDer<'static>, CaError> {
        Ok(self.leaf(host)?.der.clone())
    }

    fn leaf(&self, host: &str) -> Result<Arc<Leaf>, CaError> {
        let host = host.to_ascii_lowercase();
        let mut cache = lock(&self.leaves);
        let now = OffsetDateTime::now_utc();
        if let Some(leaf) = cache.get(&host, now) {
            return Ok(leaf);
        }
        let leaf = Arc::new(self.issue(&host, now)?);
        let size = match self.cache_size.load(Ordering::Relaxed) {
            0 => crate::limits::DEFAULT_CERTIFICATE_CACHE as usize,
            size => size,
        };
        cache.insert(host, leaf.clone(), size);
        Ok(leaf)
    }

    fn issue(&self, host: &str, now: OffsetDateTime) -> Result<Leaf, CaError> {
        let mut params = CertificateParams::default();
        params.serial_number = Some(random_serial());
        params.not_before = (now - BACKDATE).max(self.not_before);
        params.not_after = (now + LEAF_VALIDITY).min(self.not_after);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        params.distinguished_name = DistinguishedName::new();
        if host.len() <= MAX_COMMON_NAME {
            params.distinguished_name.push(DnType::CommonName, host);
        }
        params.subject_alt_names =
            vec![match host.parse::<IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName(host.try_into().map_err(|_| {
                    CaError::invalid(format!("{host} cannot be a certificate name"))
                })?),
            }];
        let certificate = params
            .signed_by(&self.leaf_key.pair, &self.issuer)
            .map_err(|err| CaError::invalid(err.to_string()))?;
        let der = certificate.der().clone();
        Ok(Leaf {
            certified: Arc::new(CertifiedKey::new(
                vec![der.clone()],
                self.leaf_key.signing.clone(),
            )),
            der,
            expires: params.not_after,
        })
    }
}

fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    if let Some(first) = bytes.first_mut() {
        *first &= 0x7f;
        *first |= 0x01;
    }
    SerialNumber::from_slice(&bytes)
}

fn encode_certificate(der: &CertificateDer<'_>) -> String {
    pem_encode("CERTIFICATE", der.as_ref())
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub fn fingerprint_of(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_ca(cert_pem: &str, key_pem: &str) -> Result<Ca, CaError> {
    let cert_der = rustls_pki_types::pem::PemObject::pem_slice_iter(cert_pem.as_bytes())
        .filter_map(Result::ok)
        .next()
        .map(|der: CertificateDer<'static>| der)
        .ok_or_else(|| CaError::invalid("no certificate in the CA file"))?;
    let (subject, not_before, not_after, spki_key) = {
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref())
            .map_err(|err| CaError::invalid(err.to_string()))?;
        if !cert.is_ca() {
            return Err(CaError::invalid("the certificate is not a CA"));
        }
        let subject = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|name| name.as_str().ok())
            .unwrap_or_default()
            .to_string();
        (
            subject,
            cert.validity().not_before.to_datetime(),
            cert.validity().not_after.to_datetime(),
            cert.public_key().subject_public_key.data.to_vec(),
        )
    };
    let key = KeyPair::from_pkcs8_pem_and_sign_algo(key_pem, &PKCS_RSA_SHA256)
        .or_else(|_| KeyPair::from_pem(key_pem))
        .map_err(|err| CaError::invalid(format!("the CA key: {err}")))?;
    if rcgen::PublicKeyData::der_bytes(&key) != spki_key.as_slice() {
        return Err(CaError::invalid(
            "the CA key does not belong to its certificate",
        ));
    }
    let issuer = Issuer::from_ca_cert_der(&cert_der, key)
        .map_err(|err| CaError::invalid(err.to_string()))?;
    let leaf_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|err| CaError::invalid(err.to_string()))?;
    let leaf_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_pair.serialize_der()));
    let signing = aws_lc_rs::sign::any_supported_type(&leaf_der)
        .map_err(|err| CaError::invalid(err.to_string()))?;
    Ok(Ca {
        fingerprint: fingerprint_of(cert_der.as_ref()),
        cert_der,
        issuer,
        subject,
        not_before,
        not_after,
        leaf_key: LeafKey {
            pair: leaf_pair,
            signing,
        },
        leaves: Mutex::default(),
        cache_size: AtomicUsize::new(crate::limits::DEFAULT_CERTIFICATE_CACHE as usize),
        retired: CancellationToken::new(),
    })
}

fn authority_path(name: &str) -> String {
    format!("{AUTHORITY_DIR}/{name}")
}

pub fn load_ca(home: &HomeDir) -> Result<Ca, CaError> {
    let cert = home
        .read(authority_path(CERT_FILE_NAME))
        .map_err(read_error)?;
    let key = home
        .read(authority_path(KEY_FILE_NAME))
        .map_err(read_error)?;
    parse_ca(
        &String::from_utf8_lossy(&cert),
        &String::from_utf8_lossy(&key),
    )
}

/// Replaces any CA in the directory, so clients that trusted the old one have
/// to install the new one.
pub fn generate_ca(home: &HomeDir) -> Result<Ca, CaError> {
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
        .map_err(|err| CaError::invalid(err.to_string()))?;
    let serial = random_serial();
    let tail = serial.to_bytes();
    let low = tail
        .iter()
        .rev()
        .take(4)
        .rev()
        .fold(0u32, |acc, byte| acc << 8 | u32::from(*byte));
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.serial_number = Some(serial);
    params.not_before = now - BACKDATE;
    params.not_after = now + CA_VALIDITY;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("{PRODUCT_NAME} CA {low:08X}"));
    params
        .distinguished_name
        .push(DnType::OrganizationName, PRODUCT_NAME);
    let certificate = params
        .self_signed(&key)
        .map_err(|err| CaError::invalid(err.to_string()))?;
    let cert_pem = certificate.pem();
    let key_pem = key.serialize_pem();
    home.create_dir_all(AUTHORITY_DIR)?;
    home.write_private(authority_path(KEY_FILE_NAME), key_pem.as_bytes())?;
    home.write_atomic(authority_path(CERT_FILE_NAME), cert_pem.as_bytes())?;
    parse_ca(&cert_pem, &key_pem)
}

struct AuthorityState {
    ca: Option<Arc<Ca>>,
    error: Option<Arc<str>>,
}

/// The CA of a home directory. A missing CA is remembered too, because the
/// engine asks for it on every connection.
pub struct Authority {
    home: Arc<HomeDir>,
    state: ArcSwap<AuthorityState>,
    loaded: std::sync::atomic::AtomicBool,
    load_lock: Mutex<()>,
    cache_size: AtomicUsize,
}

impl Authority {
    pub fn new(home: Arc<HomeDir>) -> Authority {
        Authority {
            home,
            state: ArcSwap::from_pointee(AuthorityState {
                ca: None,
                error: None,
            }),
            loaded: std::sync::atomic::AtomicBool::new(false),
            load_lock: Mutex::new(()),
            cache_size: AtomicUsize::new(crate::limits::DEFAULT_CERTIFICATE_CACHE as usize),
        }
    }

    /// Sizes the leaf cache of the CA in use and of every one read or made after it.
    pub fn set_cache_size(&self, size: usize) {
        self.cache_size.store(size, Ordering::Relaxed);
        if let Some(ca) = &self.state.load().ca {
            ca.set_cache_size(size);
        }
    }

    pub fn dir(&self) -> std::path::PathBuf {
        self.home.join(AUTHORITY_DIR)
    }

    pub fn resources_dir(&self) -> std::path::PathBuf {
        self.dir().join("resources")
    }

    pub fn store_path(&self) -> std::path::PathBuf {
        self.dir().join("store.json")
    }

    pub fn home(&self) -> &Arc<HomeDir> {
        &self.home
    }

    /// `Err(CaError::Missing)` while none has been generated.
    pub fn current(&self) -> Result<Arc<Ca>, CaError> {
        if !self.loaded.load(Ordering::Acquire) {
            let _guard = lock(&self.load_lock);
            if !self.loaded.load(Ordering::Acquire) {
                self.replace(load_ca(&self.home));
            }
        }
        let state = self.state.load();
        match (&state.ca, &state.error) {
            (Some(ca), _) => Ok(ca.clone()),
            (None, Some(message)) if message.as_ref() == "missing" => Err(CaError::Missing),
            (None, Some(message)) => Err(CaError::invalid(message.to_string())),
            (None, None) => Err(CaError::Missing),
        }
    }

    pub fn available(&self) -> Option<Arc<Ca>> {
        self.current().ok()
    }

    pub fn renew(&self) -> Result<Arc<Ca>, CaError> {
        let ca = generate_ca(&self.home)?;
        self.replace(Ok(ca));
        self.current()
    }

    /// Reads the CA from disk again, for one another process wrote.
    pub fn reload(&self) -> Result<Arc<Ca>, CaError> {
        self.replace(load_ca(&self.home));
        self.current()
    }

    /// Ends the decrypted connections of a CA that is no longer the one in use;
    /// the same CA read again keeps serving them.
    fn replace(&self, next: Result<Ca, CaError>) {
        let previous = self.state.load_full();
        let state = match next {
            Ok(ca) => match &previous.ca {
                Some(current) if current.fingerprint == ca.fingerprint => AuthorityState {
                    ca: Some(current.clone()),
                    error: None,
                },
                _ => AuthorityState {
                    ca: Some(Arc::new(ca)),
                    error: None,
                },
            },
            Err(CaError::Missing) => AuthorityState {
                ca: None,
                error: Some(Arc::from("missing")),
            },
            Err(err) => AuthorityState {
                ca: None,
                error: Some(Arc::from(err.to_string())),
            },
        };
        if let Some(ca) = &state.ca {
            ca.set_cache_size(self.cache_size.load(Ordering::Relaxed));
        }
        let kept = matches!((&previous.ca, &state.ca), (Some(a), Some(b)) if Arc::ptr_eq(a, b));
        self.state.store(Arc::new(state));
        self.loaded.store(true, Ordering::Release);
        if let (Some(old), false) = (&previous.ca, kept) {
            old.retire();
        }
    }
}

#[cfg(test)]
mod tests {
    use rustls::RootCertStore;
    use rustls::pki_types::ServerName;
    use x509_parser::prelude::FromDer;

    use super::*;

    fn home() -> (tempfile::TempDir, Arc<HomeDir>) {
        let dir = tempfile::tempdir().unwrap();
        let home = Arc::new(HomeDir::new(dir.path()));
        (dir, home)
    }

    #[test]
    fn a_generated_ca_reloads_and_keeps_its_key_private() {
        #[cfg_attr(not(unix), allow(unused_variables, reason = "Unix mode check"))]
        let (dir, home) = home();
        let ca = generate_ca(&home).unwrap();
        let loaded = load_ca(&home).unwrap();
        assert_eq!(loaded.info().fingerprint, ca.info().fingerprint);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("mitm/ca.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let info = ca.info();
        assert!(info.not_after > OffsetDateTime::now_utc() + Duration::days(9 * 365));
        assert!(
            info.subject.starts_with(&format!("{PRODUCT_NAME} CA "))
                && info.fingerprint.len() == 95
        );
        assert!(info.pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn regenerating_replaces_the_ca() {
        let (_dir, home) = home();
        let first = generate_ca(&home).unwrap();
        let second = generate_ca(&home).unwrap();
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn load_refuses_a_key_of_another_certificate() {
        let (dir, home) = home();
        generate_ca(&home).unwrap();
        let (other_dir, other_home) = self::home();
        generate_ca(&other_home).unwrap();
        let key = std::fs::read(other_dir.path().join("mitm/ca.key")).unwrap();
        std::fs::write(dir.path().join("mitm/ca.key"), key).unwrap();
        assert!(matches!(load_ca(&home), Err(CaError::Invalid(_))));
    }

    #[test]
    fn a_missing_ca_is_reported_as_missing() {
        let (_dir, home) = home();
        assert!(matches!(load_ca(&home), Err(CaError::Missing)));
    }

    fn verifies(ca: &Ca, host: &str) {
        verifies_leaf(ca, host, &ca.leaf_der(host).unwrap());
    }

    fn verifies_leaf(ca: &Ca, host: &str, leaf: &CertificateDer<'_>) {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der.clone()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap();
        let name = ServerName::try_from(host.to_string()).unwrap();
        rustls::client::danger::ServerCertVerifier::verify_server_cert(
            verifier.as_ref(),
            leaf,
            &[],
            &name,
            &[],
            rustls_pki_types::UnixTime::now(),
        )
        .unwrap_or_else(|err| panic!("{host}: {err}"));
    }

    #[test]
    fn a_leaf_verifies_against_the_ca() {
        let (_dir, home) = home();
        let ca = generate_ca(&home).unwrap();
        for host in ["www.example.com", "10.1.2.3", "2001:db8::1"] {
            verifies(&ca, host);
            assert!(
                Arc::ptr_eq(&ca.leaf(host).unwrap(), &ca.leaf(host).unwrap()),
                "{host} was issued twice"
            );
        }
    }

    #[test]
    fn a_leaf_names_the_ca_subject_byte_for_byte_as_its_issuer() {
        let (_dir, home) = home();
        let ca = generate_ca(&home).unwrap();
        let leaf = ca.leaf_der("a.example.com").unwrap();
        let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref()).unwrap();
        let (_, root) =
            x509_parser::certificate::X509Certificate::from_der(ca.cert_der.as_ref()).unwrap();
        assert_eq!(leaf.issuer().as_raw(), root.subject().as_raw());
        assert!(!leaf.is_ca());
    }

    #[test]
    fn a_ca_with_printable_string_names_keeps_its_issuer_bytes() {
        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(
            DnType::CommonName,
            rcgen::DnValue::PrintableString("Concord CA 0A1B2C3D".try_into().unwrap()),
        );
        params.distinguished_name.push(
            DnType::OrganizationName,
            rcgen::DnValue::PrintableString("Concord".try_into().unwrap()),
        );
        let cert = params.self_signed(&key).unwrap();
        let ca = parse_ca(&cert.pem(), &key.serialize_pem()).unwrap();
        let leaf = ca.leaf_der("a.example.com").unwrap();
        let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref()).unwrap();
        let (_, root) =
            x509_parser::certificate::X509Certificate::from_der(ca.cert_der.as_ref()).unwrap();
        assert_eq!(leaf.issuer().as_raw(), root.subject().as_raw());
        verifies(&ca, "a.example.com");
    }

    #[test]
    fn the_leaf_cache_evicts_the_least_recently_used() {
        let (_dir, home) = home();
        let ca = generate_ca(&home).unwrap();
        ca.set_cache_size(2);
        let a = ca.leaf("a.test").unwrap();
        ca.leaf("b.test").unwrap();
        ca.leaf("a.test").unwrap();
        ca.leaf("c.test").unwrap();
        assert!(Arc::ptr_eq(&a, &ca.leaf("a.test").unwrap()));
        let cache = lock(&ca.leaves);
        assert_eq!(cache.leaves.len(), 2);
        assert!(!cache.leaves.contains_key("b.test"));
    }

    #[test]
    fn a_panicked_holder_leaves_the_leaf_cache_and_the_ca_load_working() {
        let (_dir, home) = home();
        let ca = generate_ca(&home).unwrap();
        concord_test_support::poison(&ca.leaves);
        let leaf = ca.leaf("a.test").unwrap();
        assert!(Arc::ptr_eq(&leaf, &ca.leaf("a.test").unwrap()));
        assert_eq!(ca.cached_leaves(), 1);

        let authority = Authority::new(home);
        concord_test_support::poison(&authority.load_lock);
        assert_eq!(
            authority.current().unwrap().info().fingerprint,
            ca.info().fingerprint
        );
    }

    #[test]
    fn the_authority_keeps_the_ca_it_reads_again_and_retires_a_replaced_one() {
        let (_dir, home) = home();
        let authority = Authority::new(home);
        assert!(matches!(authority.current(), Err(CaError::Missing)));
        let first = authority.renew().unwrap();
        let again = authority.reload().unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        assert!(!first.retired().is_cancelled());
        let second = authority.renew().unwrap();
        assert!(first.retired().is_cancelled());
        assert!(!second.retired().is_cancelled());
        assert!(Arc::ptr_eq(&authority.current().unwrap(), &second));
    }

    #[test]
    fn a_server_config_serves_the_leaf_over_the_wire() {
        let (_dir, home) = home();
        let ca = generate_ca(&home).unwrap();
        let config = ca
            .server_config("a.example.com", &["h2", "http/1.1"])
            .unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn an_issued_pem_verifies_as_a_server_certificate() {
        let (_dir, home) = home();
        let ca = generate_ca(&home).unwrap();
        let pem = ca.issue_pem("check.example.test").unwrap();
        let (rest, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        assert!(rest.iter().all(u8::is_ascii_whitespace), "one certificate");
        assert_eq!(parsed.label, "CERTIFICATE");
        verifies_leaf(
            &ca,
            "check.example.test",
            &CertificateDer::from(parsed.contents),
        );
    }

    #[test]
    fn the_authority_sizes_the_leaf_cache_of_every_ca() {
        let (_dir, home) = home();
        let authority = Authority::new(home);
        let first = authority.renew().unwrap();
        authority.set_cache_size(2);
        let second = authority.renew().unwrap();
        for ca in [&first, &second] {
            for host in ["a.test", "b.test", "c.test"] {
                ca.leaf(host).unwrap();
            }
            assert_eq!(ca.cached_leaves(), 2);
        }
    }
}
