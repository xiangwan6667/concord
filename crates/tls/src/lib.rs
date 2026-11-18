#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod boring_backend;
mod buffered;
mod ciphers;
mod client_auth;
mod conn;
mod connector;
mod ech;
mod error;
pub mod fingerprints;
mod jls;
mod options;
mod policy;
mod reality;
mod record;
mod record_io;
mod rustls_backend;
mod trust;

#[cfg(test)]
mod tests;

use std::io;
use std::sync::Arc;

pub use conn::TlsConn;
pub use connector::{Backend, DecoyHandshake, TlsConnector};
pub use ech::EchLookup;
pub use error::TlsError;
pub use fingerprints::{ClientFingerprint, FingerprintSpec};
pub use jls::JlsAuth;
pub use options::{REALITY_SHORT_ID_LEN, RealityOptions, TlsOptions};
pub use policy::CertPolicy;
pub use reality::{RealityStream, SessionIdSealer};
pub use record::{TlsRead, TlsWrite};
pub use record_io::RecordIo;
pub use trust::{SystemRoots, TrustStore, parse_certificates};

pub use rustls::ClientConfig;

/// Connects a caller-configured rustls client through the native record engine.
/// The config must enable secret extraction for the record-layer handoff.
pub async fn connect_config(
    config: &Arc<ClientConfig>,
    server_name: &str,
    io: concord_common::BoxStream,
) -> io::Result<TlsConn> {
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    Ok(TlsConn::Record(Box::new(
        rustls_backend::connect(config, name, io, false).await?,
    )))
}

pub fn quic_client_config(
    options: &TlsOptions,
    trust: Arc<TrustStore>,
    alpn: &[&str],
) -> Result<Arc<ClientConfig>, TlsError> {
    let policy = Arc::new(CertPolicy::new(options, trust)?);
    let auth = client_auth::load_client_auth(options)?;
    rustls_backend::client_config(
        policy,
        alpn_bytes(alpn),
        auth,
        true,
        options.ech_config_list.as_deref(),
    )
}

/// The QUIC client config of a node; with an ECH lookup the config is built per answer.
pub struct QuicTls {
    plain: Arc<ClientConfig>,
    lazy: Option<LazyQuic>,
}

struct LazyQuic {
    lookup: Arc<dyn EchLookup>,
    options: TlsOptions,
    trust: Arc<TrustStore>,
    alpn: Vec<String>,
    built: ech::ByList<ClientConfig>,
}

impl QuicTls {
    pub fn new(
        options: &TlsOptions,
        trust: Arc<TrustStore>,
        alpn: &[&str],
    ) -> Result<Self, TlsError> {
        let lookup = options
            .ech_lookup
            .clone()
            .filter(|_| options.ech_config_list.is_none());
        let options = TlsOptions {
            ech_lookup: None,
            ..options.clone()
        };
        let plain = quic_client_config(&options, trust.clone(), alpn)?;
        let lazy = lookup.map(|lookup| LazyQuic {
            lookup,
            options,
            trust,
            alpn: alpn.iter().map(|proto| (*proto).to_string()).collect(),
            built: ech::ByList::new(),
        });
        Ok(QuicTls { plain, lazy })
    }

    /// `server_name` is the name the handshake sends, which the ECH lookup is asked for.
    pub async fn config(&self, server_name: &str) -> io::Result<Arc<ClientConfig>> {
        let Some(lazy) = &self.lazy else {
            return Ok(self.plain.clone());
        };
        lazy.built
            .get(&*lazy.lookup, server_name, |list| {
                let options = TlsOptions {
                    ech_config_list: Some(list.to_vec()),
                    ..lazy.options.clone()
                };
                let alpn: Vec<&str> = lazy.alpn.iter().map(String::as_str).collect();
                quic_client_config(&options, lazy.trust.clone(), &alpn)
            })
            .await
    }
}

/// The global `skip-cert-verify` is passed here by the caller and nowhere else.
pub fn http_client_config(
    trust: Arc<TrustStore>,
    skip_cert_verify: bool,
    alpn: &[&str],
) -> Result<Arc<ClientConfig>, TlsError> {
    let options = TlsOptions {
        skip_cert_verify,
        ..TlsOptions::default()
    };
    http_client_config_for(&options, trust, alpn)
}

pub fn http_client_config_for(
    options: &TlsOptions,
    trust: Arc<TrustStore>,
    alpn: &[&str],
) -> Result<Arc<ClientConfig>, TlsError> {
    let policy = Arc::new(CertPolicy::new(options, trust)?);
    let auth = client_auth::load_client_auth(options)?;
    rustls_backend::client_config(
        policy,
        alpn_bytes(alpn),
        auth,
        false,
        options.ech_config_list.as_deref(),
    )
}

fn alpn_bytes(alpn: &[&str]) -> Vec<Vec<u8>> {
    alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect()
}

#[cfg(feature = "fuzzing")]
pub mod fuzzing;
