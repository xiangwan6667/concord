use std::io;

use aes::cipher::{KeyIvInit, StreamCipher};
use aws_lc_rs::aead::{AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use blake3::hazmat::HasherExt;

pub(super) type Ctr = Box<ctr::Ctr128BE<aes::Aes256>>;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "VLESS Encryption authentication failed",
    )
}

pub(super) fn derive(context: &[u8], material: &[u8]) -> [u8; 32] {
    let context = blake3::hazmat::hash_derive_key_context_bytes(context);
    *blake3::Hasher::new_from_context_key(&context)
        .update(material)
        .finalize()
        .as_bytes()
}

pub(super) fn ctr(key: &[u8], iv: &[u8; 16]) -> Ctr {
    Box::new(ctr::Ctr128BE::new(&derive(b"VLESS", key).into(), iv.into()))
}

pub(super) fn xor(ctr: &mut Ctr, bytes: &mut [u8]) {
    ctr.apply_keystream(bytes);
}

pub(super) struct Aead {
    key: LessSafeKey,
    nonce: [u8; 12],
}

impl Aead {
    pub(super) fn new(context: &[u8], material: &[u8], aes: bool) -> io::Result<Self> {
        let algorithm = if aes {
            &AES_256_GCM
        } else {
            &CHACHA20_POLY1305
        };
        let key = UnboundKey::new(algorithm, &derive(context, material)).map_err(|_| invalid())?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce: [0; 12],
        })
    }

    fn next(&mut self) -> Nonce {
        for byte in self.nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        Nonce::assume_unique_for_key(self.nonce)
    }

    pub(super) fn at_max(&self) -> bool {
        self.nonce == [255; 12]
    }

    pub(super) fn seal(&mut self, plain: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next();
        let mut out = plain.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut out)
            .map_err(|_| invalid())?;
        Ok(out)
    }

    pub(super) fn open(&mut self, body: &mut [u8], aad: &[u8]) -> io::Result<usize> {
        let nonce = self.next();
        self.open_nonce(body, aad, nonce)
    }

    pub(super) fn open_max(&self, body: &mut [u8]) -> io::Result<usize> {
        self.open_nonce(body, &[], Nonce::assume_unique_for_key([255; 12]))
    }

    fn open_nonce(&self, body: &mut [u8], aad: &[u8], nonce: Nonce) -> io::Result<usize> {
        self.key
            .open_in_place(nonce, Aad::from(aad), body)
            .map(|plain| plain.len())
            .map_err(|_| invalid())
    }
}

pub(super) fn use_aes() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    return std::is_x86_feature_detected!("aes")
        && std::is_x86_feature_detected!("pclmulqdq")
        && std::is_x86_feature_detected!("sse4.1")
        && std::is_x86_feature_detected!("ssse3");
    #[cfg(target_arch = "aarch64")]
    return std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull");
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    false
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests assert fixed-size cipher and nonce vectors"
    )]

    use super::*;

    #[test]
    fn both_ciphers_advance_the_nonce_before_sealing_and_wrap_at_maximum() {
        for aes in [true, false] {
            let mut sender = Aead::new(b"context", b"key", aes).unwrap();
            let mut receiver = Aead::new(b"context", b"key", aes).unwrap();
            for nonce in [[0; 12], [255; 12]] {
                sender.nonce = nonce;
                receiver.nonce = nonce;
                assert_eq!(sender.at_max(), nonce == [255; 12]);
                let mut body = sender.seal(b"payload", b"header").unwrap();
                assert_eq!(receiver.open(&mut body, b"header").unwrap(), 7);
                assert_eq!(&body[..7], b"payload");
                assert_eq!(sender.nonce, receiver.nonce);
                if nonce == [255; 12] {
                    assert_eq!(sender.nonce, [0; 12]);
                } else {
                    assert_eq!(sender.nonce[11], 1);
                }
            }
        }
    }
}
