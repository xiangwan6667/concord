use super::{Flight, RealityClient};
use crate::error::invalid_data;
use rustls_pki_types::{CertificateDer, ServerName};
use std::io;

pub(super) fn certificate_verify_message(transcript_hash: &[u8]) -> Vec<u8> {
    let mut message = vec![0x20u8; 64];
    message.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    message.extend_from_slice(transcript_hash);
    message
}

impl RealityClient {
    pub(super) fn verify_fallback_chain(
        &self,
        flight: &Flight,
        transcript_hash: &[u8],
        name: &ServerName<'static>,
    ) -> io::Result<()> {
        let chain: Vec<CertificateDer<'_>> = flight
            .chain
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        self.policy.verify(&chain, name, self.policy.now())?;
        self.verify_signature(flight, transcript_hash)
    }

    pub(super) fn verify_signature(
        &self,
        flight: &Flight,
        transcript_hash: &[u8],
    ) -> io::Result<()> {
        let leaf = flight
            .chain
            .first()
            .ok_or_else(|| invalid_data("REALITY: server sent no certificate"))?;
        let der = CertificateDer::from(leaf.as_slice());
        let end_entity = webpki::EndEntityCert::try_from(&der)
            .map_err(|_| invalid_data("REALITY: unparsable certificate"))?;
        let message = certificate_verify_message(transcript_hash);
        let verified = self
            .policy
            .algorithms()
            .mapping
            .iter()
            .filter(|(scheme, _)| u16::from(*scheme) == flight.signature_scheme)
            .flat_map(|(_, algs)| algs.iter())
            .any(|alg| {
                end_entity
                    .verify_signature(*alg, &message, &flight.signature)
                    .is_ok()
            });
        if verified {
            Ok(())
        } else {
            Err(invalid_data(
                "REALITY: CertificateVerify signature mismatch",
            ))
        }
    }
}
