use aws_lc_rs::{hmac, signature};

use crate::error::invalid_data;

#[derive(Clone, Copy)]
struct Der<'a> {
    tag: u8,
    value: &'a [u8],
}

fn read_der<'a>(input: &'a [u8], pos: &mut usize) -> Option<Der<'a>> {
    let tag = *input.get(*pos)?;
    let first = *input.get(pos.checked_add(1)?)?;
    *pos = pos.checked_add(2)?;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | usize::from(*input.get(*pos)?);
            *pos = pos.checked_add(1)?;
        }
        len
    };
    let end = pos.checked_add(len)?;
    let value = input.get(*pos..end)?;
    *pos = end;
    Some(Der { tag, value })
}

pub(crate) struct Ed25519Cert {
    pub public_key: [u8; 32],
    pub signature: Vec<u8>,
    pub extension: Option<Vec<u8>>,
}

/// The temporary certificate a REALITY server presents: an Ed25519 key whose
/// certificate "signature" is HMAC-SHA512(auth_key, public_key).
pub(crate) fn parse_ed25519_cert(cert: &[u8]) -> Option<Ed25519Cert> {
    let mut pos = 0;
    let outer = read_der(cert, &mut pos)?;
    if outer.tag != 0x30 {
        return None;
    }
    let mut inner = 0;
    let tbs = read_der(outer.value, &mut inner)?;
    let _algorithm = read_der(outer.value, &mut inner)?;
    let signature = read_der(outer.value, &mut inner)?;
    if tbs.tag != 0x30 || signature.tag != 0x03 || *signature.value.first()? != 0 {
        return None;
    }
    let mut children = Vec::new();
    let mut at = 0;
    while at < tbs.value.len() {
        children.push(read_der(tbs.value, &mut at)?);
    }
    let base = usize::from(children.first().is_some_and(|node| node.tag == 0xa0));
    let spki = children.get(base + 5)?;
    let mut spki_pos = 0;
    let algorithm = read_der(spki.value, &mut spki_pos)?;
    let key = read_der(spki.value, &mut spki_pos)?;
    let mut alg_pos = 0;
    let oid = read_der(algorithm.value, &mut alg_pos)?;
    if algorithm.tag != 0x30
        || key.tag != 0x03
        || oid.tag != 0x06
        || oid.value != [0x2b, 0x65, 0x70]
    {
        return None;
    }
    let (unused, bits) = key.value.split_first()?;
    if *unused != 0 {
        return None;
    }
    Some(Ed25519Cert {
        public_key: bits.try_into().ok()?,
        signature: signature.value.get(1..)?.to_vec(),
        extension: children
            .iter()
            .find(|child| child.tag == 0xa3)
            .and_then(|child| first_extension(child.value)),
    })
}

fn first_extension(input: &[u8]) -> Option<Vec<u8>> {
    let extensions = read_der(input, &mut 0)?;
    let first = read_der(extensions.value, &mut 0)?;
    let mut at = 0;
    let _oid = read_der(first.value, &mut at)?;
    let mut value = read_der(first.value, &mut at)?;
    if value.tag == 0x01 {
        value = read_der(first.value, &mut at)?;
    }
    (value.tag == 0x04).then(|| value.value.to_vec())
}

pub(crate) fn hmac_matches(auth_key: &[u8], cert: &Ed25519Cert) -> bool {
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA512, auth_key),
        &cert.public_key,
        &cert.signature,
    )
    .is_ok()
}

pub(crate) fn verify_mldsa(
    auth_key: &[u8],
    cert: &Ed25519Cert,
    verify_key: &[u8],
    hellos: &[u8],
) -> std::io::Result<()> {
    let signature = cert
        .extension
        .as_deref()
        .ok_or_else(|| invalid_data("REALITY: ML-DSA-65 signature is missing"))?;
    let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let mut context = hmac::Context::with_key(&key);
    context.update(&cert.public_key);
    context.update(hellos);
    signature::UnparsedPublicKey::new(&signature::ML_DSA_65, verify_key)
        .verify(context.sign().as_ref(), signature)
        .map_err(|_| invalid_data("REALITY: ML-DSA-65 authentication failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::schedule::hmac_sign;

    fn cert_with(key_pair: &rcgen::KeyPair) -> Vec<u8> {
        let params = rcgen::CertificateParams::new(vec!["reality.test".into()]).unwrap();
        params.self_signed(key_pair).unwrap().der().to_vec()
    }

    #[test]
    fn extracts_the_ed25519_key_and_signature() {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let der = cert_with(&pair);
        let parsed = parse_ed25519_cert(&der).unwrap();
        assert_eq!(parsed.public_key.as_slice(), pair.public_key_raw());
        assert_eq!(parsed.signature.len(), 64);
    }

    #[test]
    fn other_key_types_and_garbage_are_not_reality_certs() {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        assert!(parse_ed25519_cert(&cert_with(&pair)).is_none());
        assert!(parse_ed25519_cert(&[]).is_none());
        assert!(parse_ed25519_cert(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let der = cert_with(&pair);
        for cut in 0..der.len() {
            let _ = parse_ed25519_cert(&der[..cut]);
        }
    }

    #[test]
    fn hmac_check_is_keyed() {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut parsed = parse_ed25519_cert(&cert_with(&pair)).unwrap();
        let key = [3u8; 32];
        parsed.signature = hmac_sign(hmac::HMAC_SHA512, &key, &parsed.public_key);
        assert!(hmac_matches(&key, &parsed));
        assert!(!hmac_matches(&[4u8; 32], &parsed));
    }
}
