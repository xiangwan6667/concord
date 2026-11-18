use std::borrow::Cow;
use std::io::{BufReader, Read};

use age::armor::ArmoredReader;
use age::{Decryptor, Identity, IdentityFile};

use crate::error::{ConfigError, Result};

pub const ARMOR_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

pub fn is_armored(data: &[u8]) -> bool {
    data.starts_with(ARMOR_HEADER.as_bytes())
}

fn identities(secret_keys: &[&str]) -> Result<Vec<Box<dyn Identity>>> {
    let mut out: Vec<Box<dyn Identity>> = Vec::new();
    for key in secret_keys {
        if key.lines().any(|line| {
            line.trim()
                .to_ascii_uppercase()
                .starts_with("AGE-SECRET-KEY-PQ-")
        }) {
            return Err(ConfigError::new(
                "post-quantum (AGE-SECRET-KEY-PQ-1) keys are not supported by this core",
            ));
        }
        let file = IdentityFile::from_buffer(BufReader::new(key.as_bytes()))
            .map_err(|err| ConfigError::new(err.to_string()))?;
        let parsed = file
            .into_identities()
            .map_err(|err| ConfigError::new(err.to_string()))?;
        out.extend(parsed);
    }
    Ok(out)
}

pub fn verify_secret_key(secret_key: &str) -> Result<()> {
    identities(&[secret_key]).map(|_| ())
}

pub fn decrypt_bytes<'a>(data: &'a [u8], secret_keys: &[&str]) -> Result<Cow<'a, [u8]>> {
    if !is_armored(data) {
        return Ok(Cow::Borrowed(data));
    }
    let identities = identities(secret_keys)?;
    let decryptor = Decryptor::new_buffered(ArmoredReader::new(data))
        .map_err(|err| ConfigError::new(err.to_string()))?;
    let mut reader = decryptor
        .decrypt(
            identities
                .iter()
                .map(|identity| identity.as_ref() as &dyn Identity),
        )
        .map_err(|err| ConfigError::new(err.to_string()))?;
    let mut plain = Vec::new();
    reader
        .read_to_end(&mut plain)
        .map_err(|err| ConfigError::new(err.to_string()))?;
    Ok(Cow::Owned(plain))
}

pub fn decrypt_config<'a>(data: &'a [u8], secret_keys: &[&str]) -> Result<Cow<'a, [u8]>> {
    decrypt_bytes(data, secret_keys)
        .map_err(|err| ConfigError::new(format!("decrypt config error: {}", err.message)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use age::x25519;

    #[test]
    fn a_post_quantum_key_is_named_as_unsupported() {
        let err = verify_secret_key("AGE-SECRET-KEY-PQ-1QQQQ").unwrap_err();
        assert_eq!(
            err.message,
            "post-quantum (AGE-SECRET-KEY-PQ-1) keys are not supported by this core"
        );
    }

    #[test]
    fn armored_input_round_trips_and_plain_input_passes_through() {
        let identity = x25519::Identity::generate();
        let secret = identity.to_string();
        let armored = age::encrypt_and_armor(&identity.to_public(), b"proxies: []\n").unwrap();
        assert!(is_armored(armored.as_bytes()));
        let plain = decrypt_bytes(armored.as_bytes(), &[secret.expose_secret()]).unwrap();
        assert_eq!(&*plain, b"proxies: []\n");
        let untouched = decrypt_bytes(b"mode: rule\n", &[]).unwrap();
        assert!(matches!(untouched, Cow::Borrowed(_)));
        assert!(decrypt_bytes(armored.as_bytes(), &[]).is_err());
        assert!(verify_secret_key("not a key").is_err());
    }
}
