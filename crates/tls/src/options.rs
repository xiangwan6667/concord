use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::{ClientFingerprint, EchLookup, TlsError};

pub const REALITY_SHORT_ID_LEN: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityOptions {
    pub public_key: [u8; 32],
    pub short_id: [u8; REALITY_SHORT_ID_LEN],
    pub support_x25519mlkem768: bool,
    pub client_version: [u8; 3],
    pub mldsa65_verify: Option<Vec<u8>>,
}

impl RealityOptions {
    /// `public_key` is unpadded base64url and `short_id` is up to eight bytes
    /// of hex, left-aligned and zero padded, as in `reality-opts`.
    pub fn parse(
        public_key: &str,
        short_id: &str,
        support_x25519mlkem768: bool,
    ) -> Result<Self, TlsError> {
        let key = URL_SAFE_NO_PAD
            .decode(public_key.trim())
            .map_err(|_| TlsError::Config("reality public-key is not base64url".into()))?;
        let public_key: [u8; 32] = key
            .try_into()
            .map_err(|_| TlsError::Config("reality public-key must be 32 bytes".into()))?;
        let short = hex::decode(short_id.trim())
            .map_err(|_| TlsError::Config("reality short-id is not hex".into()))?;
        if short.len() > REALITY_SHORT_ID_LEN {
            return Err(TlsError::Config(
                "reality short-id is longer than 8 bytes".into(),
            ));
        }
        let mut short_id = [0u8; REALITY_SHORT_ID_LEN];
        short_id
            .get_mut(..short.len())
            .ok_or_else(|| TlsError::Config("reality short-id is longer than 8 bytes".into()))?
            .copy_from_slice(&short);
        Ok(Self {
            public_key,
            short_id,
            support_x25519mlkem768,
            client_version: [1, 8, 2],
            mldsa65_verify: None,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct TlsOptions {
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub skip_cert_verify: bool,
    pub name_cert_verify: Option<String>,
    /// SHA-256 certificate pin, hex with optional colons.
    pub fingerprint: Option<String>,
    /// Client certificate and key: PEM text or file paths.
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub client_fingerprint: Option<ClientFingerprint>,
    pub reality: Option<RealityOptions>,
    /// An `ECHConfigList`: the hello is encrypted to the first config this build can use.
    pub ech_config_list: Option<Vec<u8>>,
    /// Asked at each handshake when `ech_config_list` is `None`.
    pub ech_lookup: Option<Arc<dyn EchLookup>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_options_parse_like_the_yaml_fields() {
        let key = "A".repeat(43);
        let opts = RealityOptions::parse(&key, "abcd", true).unwrap();
        assert_eq!(opts.public_key, [0u8; 32]);
        assert_eq!(opts.short_id, [0xab, 0xcd, 0, 0, 0, 0, 0, 0]);
        assert!(opts.support_x25519mlkem768);
        let empty = RealityOptions::parse(&key, "", false).unwrap();
        assert_eq!(empty.short_id, [0u8; 8]);
    }

    #[test]
    fn reality_options_reject_bad_input() {
        let key = "A".repeat(43);
        assert!(RealityOptions::parse("short", "", false).is_err());
        assert!(RealityOptions::parse(&key, "zz", false).is_err());
        assert!(RealityOptions::parse(&key, "0011223344556677ff", false).is_err());
        assert!(RealityOptions::parse("!!!", "", false).is_err());
    }
}
