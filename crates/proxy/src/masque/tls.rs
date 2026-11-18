use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use concord_config::proxy::MasqueOpts;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, parse_x509_certificate};

use crate::ctx::{BuildCtx, BuildError};

#[derive(Debug)]
struct Pinned {
    peer: Vec<u8>,
    skip: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !self.skip {
            for der in std::iter::once(end_entity).chain(intermediates) {
                let (_, cert) = parse_x509_certificate(der.as_ref()).map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                })?;
                if cert.public_key().raw != self.peer {
                    return Err(rustls::Error::General(
                        "MASQUE endpoint public key does not match".into(),
                    ));
                }
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(super) fn config(
    opts: &MasqueOpts,
    ctx: &BuildCtx,
) -> Result<Arc<rustls::ClientConfig>, BuildError> {
    let invalid = |err: &dyn std::fmt::Display| BuildError::invalid(format!("masque TLS: {err}"));
    let private = STANDARD
        .decode(&opts.private_key)
        .map_err(|e| invalid(&e))?;
    let private = PrivateKeyDer::try_from(private).map_err(|e| invalid(&e))?;
    if !matches!(private, PrivateKeyDer::Sec1(_)) {
        return Err(BuildError::invalid("masque private key must be SEC1 ECDSA"));
    }
    let key = rcgen::KeyPair::try_from(&private).map_err(|e| invalid(&e))?;
    if ![
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ECDSA_P521_SHA512,
    ]
    .contains(&key.algorithm())
    {
        return Err(BuildError::invalid("masque private key must be SEC1 ECDSA"));
    }
    let peer = STANDARD.decode(&opts.public_key).map_err(|e| invalid(&e))?;
    let (rest, spki) = SubjectPublicKeyInfo::from_der(&peer).map_err(|e| invalid(&e))?;
    if !rest.is_empty()
        || spki.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || spki.parsed().is_err()
    {
        return Err(BuildError::invalid(
            "masque public key must be ECDSA SubjectPublicKeyInfo",
        ));
    }
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(0u64.into());
    params.not_before = time::OffsetDateTime::from((ctx.clock)());
    params.not_after = params.not_before + time::Duration::days(1);
    let cert = params.self_signed(&key).map_err(|e| invalid(&e))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| invalid(&e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            peer,
            skip: opts.skip_cert_verify,
            provider,
        }))
        .with_client_auth_cert(vec![cert.der().clone()], private)
        .map_err(|e| invalid(&e))?;
    config.alpn_protocols = vec![if opts.network == "h2" {
        b"h2".to_vec()
    } else {
        b"h3".to_vec()
    }];
    config.enable_secret_extraction = true;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}
