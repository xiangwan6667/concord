use aes_gcm::aead::generic_array::{GenericArray, typenum::U32};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, aes::Aes256};
use sha2::{Digest, Sha256};

use crate::error::invalid_data;

use crate::fingerprints::{Ext, FingerprintSpec, KeyShareKind};

pub(crate) const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) static NATIVE: FingerprintSpec = FingerprintSpec {
    name: "native",
    grease: false,
    permute_extensions: false,
    tls13: true,
    cipher_suites: &[
        0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x1301,
        0x1302, 0x1303,
    ],
    extensions: &[
        Ext::ServerName,
        Ext::PointFormats,
        Ext::RenegotiationInfo,
        Ext::ExtendedMasterSecret,
        Ext::Sct,
        Ext::StatusRequest,
        Ext::SupportedGroups,
        Ext::SignatureAlgorithms,
        Ext::SignatureAlgorithmsCert(&[
            0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201,
            0x0203,
        ]),
        Ext::Alpn,
        Ext::SupportedVersions,
        Ext::KeyShare,
    ],
    groups: &[0x11ec, 0x11eb, 0x11ed, 0x001d, 0x0017, 0x0018, 0x0019],
    key_shares: &[KeyShareKind::X25519MlKem768, KeyShareKind::X25519],
    signature_algorithms: &[
        0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603,
    ],
    delegated_credentials: &[],
    versions: &[0x0304, 0x0303],
    alpn: &["h2", "http/1.1"],
    alps_protocols: &[],
    cert_compression: &[],
    record_size_limit: 0,
    ech_grease: None,
};

#[derive(Clone, Debug)]
pub struct JlsAuth {
    pub username: String,
    pub password: String,
}

impl JlsAuth {
    fn digest(value: &str, hello: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(value.as_bytes());
        hash.update(hello);
        hash.finalize().into()
    }

    fn cipher(&self, hello: &[u8]) -> AesGcm<Aes256, U32> {
        AesGcm::new(GenericArray::from_slice(&Self::digest(
            &self.password,
            hello,
        )))
    }

    fn auth_data(hello: &[u8], kind: u8) -> std::io::Result<Vec<u8>> {
        let Some(&[ty, a, b, c]) = hello.first_chunk::<4>() else {
            return Err(invalid_data("jls: invalid hello"));
        };
        let len = (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c);
        if ty != kind || len + 4 != hello.len() {
            return Err(invalid_data("jls: invalid hello"));
        }
        let mut auth = hello.to_vec();
        auth.get_mut(6..38)
            .ok_or_else(|| invalid_data("jls: short hello"))?
            .fill(0);
        Ok(auth)
    }

    pub(crate) fn seal(&self, hello: &mut [u8]) -> std::io::Result<()> {
        let auth = Self::auth_data(hello, 1)?;
        let nonce = Self::digest(&self.username, &auth);
        let cipher = self.cipher(&auth);
        loop {
            let seed: [u8; 16] = rand::random();
            let sealed = cipher
                .encrypt(GenericArray::from_slice(&nonce), seed.as_slice())
                .map_err(|_| invalid_data("jls: random seal failed"))?;
            if forbidden(&sealed) {
                continue;
            }
            hello
                .get_mut(6..38)
                .ok_or_else(|| invalid_data("jls: short hello"))?
                .copy_from_slice(&sealed);
            return Ok(());
        }
    }

    pub(crate) fn verify(&self, hello: &[u8]) -> std::io::Result<bool> {
        let auth = Self::auth_data(hello, 2)?;
        let nonce = Self::digest(&self.username, &auth);
        Ok(self
            .cipher(&auth)
            .decrypt(
                GenericArray::from_slice(&nonce),
                hello.get(6..38).unwrap_or_default(),
            )
            .is_ok_and(|seed| seed.len() == 16))
    }
}

fn forbidden(random: &[u8]) -> bool {
    [
        b"DOWNGRD\x00",
        b"DOWNGRD\x01",
        b"\x07\x9e\x09\xe2\xc8\xa8\x33\x9c",
    ]
    .iter()
    .any(|tail| random.ends_with(tail.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jls_authentication_binds_the_complete_wire_hello() {
        let auth = JlsAuth {
            username: "name".into(),
            password: "secret".into(),
        };
        let mut hello = vec![1, 0, 0, 38, 3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[1, 2, 3, 4]);
        let plain = hello.clone();
        auth.seal(&mut hello).unwrap();
        let nonce = JlsAuth::digest("name", &plain);
        assert_eq!(
            auth.cipher(&plain)
                .decrypt(GenericArray::from_slice(&nonce), &hello[6..38])
                .unwrap()
                .len(),
            16
        );
        assert!(!forbidden(&hello[6..38]));
        hello[0] = 2;
        let server_auth = JlsAuth::auth_data(&hello, 2).unwrap();
        let nonce = JlsAuth::digest("name", &server_auth);
        let sealed = auth
            .cipher(&server_auth)
            .encrypt(GenericArray::from_slice(&nonce), [7; 16].as_slice())
            .unwrap();
        // Go 1.27.3, mihomo 3c0d10a5 transport/jls: AES-256-GCM with a 32-byte nonce, key
        // SHA-256("secret" || hello), nonce SHA-256("name" || hello), sealing sixteen 7s.
        assert_eq!(
            hex::encode(&sealed),
            "ccb6b2b0df1c6c5accadfa86c2200989274ebd9d5f4da8fbde8e78dc2f4b9576"
        );
        hello[6..38].copy_from_slice(&sealed);
        assert!(auth.verify(&hello).unwrap());
        hello[41] ^= 1;
        assert!(!auth.verify(&hello).unwrap());
        assert!(auth.verify(&hello[..20]).is_err());
    }
}
