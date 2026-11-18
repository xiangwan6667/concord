use std::io;

use super::chacha::ChaCha64;
use bytes::BytesMut;
use shadowsocks::crypto::CipherKind;
use shadowsocks::crypto::v1::{Cipher, openssl_bytes_to_key};

use super::stream::{BoxLayer, Layer};
use crate::ctx::BuildError;

const KDF_LEN_DUMMY: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamKind {
    Crate(CipherKind),
    Chacha20,
    Xchacha20,
}

impl StreamKind {
    pub(crate) fn chacha(upper: &str) -> Option<StreamKind> {
        match upper {
            "CHACHA20" => Some(StreamKind::Chacha20),
            "XCHACHA20" => Some(StreamKind::Xchacha20),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        match self {
            StreamKind::Crate(kind) => kind.key_len(),
            StreamKind::Chacha20 | StreamKind::Xchacha20 => 32,
        }
    }

    fn iv_len(self) -> usize {
        match self {
            StreamKind::Crate(kind) => kind.iv_len(),
            StreamKind::Chacha20 => 8,
            StreamKind::Xchacha20 => 24,
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "one per connection; boxing the existing cipher would add an allocation to existing protocols"
)]
enum KeyStream {
    Crate(Cipher),
    Chacha(ChaCha64),
}

impl KeyStream {
    fn new(kind: StreamKind, key: &[u8], iv: &[u8]) -> io::Result<Self> {
        Ok(match kind {
            StreamKind::Crate(kind) => KeyStream::Crate(Cipher::new(kind, key, iv)),
            StreamKind::Chacha20 | StreamKind::Xchacha20 => {
                KeyStream::Chacha(ChaCha64::new(key, iv)?)
            }
        })
    }

    fn apply(&mut self, data: &mut [u8], encrypt: bool) -> io::Result<()> {
        let ok = match self {
            KeyStream::Crate(cipher) if encrypt => {
                cipher.encrypt_packet(data);
                true
            }
            KeyStream::Crate(cipher) => cipher.decrypt_packet(data),
            KeyStream::Chacha(cipher) => return cipher.apply(data),
        };
        if ok {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "bad stream"))
        }
    }
}

#[derive(Clone)]
pub(crate) struct SsrCipher {
    kind: Option<StreamKind>,
    pub(super) key: Vec<u8>,
}

/// EVP_BytesToKey over MD5, which is what Go's `core.Kdf` is.
pub(super) fn kdf(password: &[u8], len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    openssl_bytes_to_key(password, &mut key);
    key
}

impl SsrCipher {
    pub(crate) fn chacha(name: &str, password: &str) -> Option<Self> {
        let kind = StreamKind::chacha(&name.to_ascii_uppercase())?;
        Some(SsrCipher {
            kind: Some(kind),
            key: kdf(password.as_bytes(), kind.key_len()),
        })
    }

    pub(super) fn pick(name: &str, password: &str) -> Result<Self, BuildError> {
        if let Some(cipher) = SsrCipher::chacha(name, password) {
            return Ok(cipher);
        }
        let upper = name.to_ascii_uppercase();
        let kind = match upper.as_str() {
            "NONE" | "DUMMY" => {
                return Ok(SsrCipher {
                    kind: None,
                    key: kdf(password.as_bytes(), KDF_LEN_DUMMY),
                });
            }
            "RC4-MD5" => CipherKind::SS_RC4_MD5,
            "AES-128-CTR" => CipherKind::AES_128_CTR,
            "AES-192-CTR" => CipherKind::AES_192_CTR,
            "AES-256-CTR" => CipherKind::AES_256_CTR,
            "AES-128-CFB" => CipherKind::AES_128_CFB128,
            "AES-192-CFB" => CipherKind::AES_192_CFB128,
            "AES-256-CFB" => CipherKind::AES_256_CFB128,
            "CHACHA20-IETF" => CipherKind::CHACHA20,
            other if is_aead(other) => {
                return Err(BuildError::invalid(format!(
                    "{name} is not none or a supported stream cipher in ssr"
                )));
            }
            _ => {
                return Err(BuildError::invalid(format!(
                    "ssr cipher: {name} initialize error: cipher not supported"
                )));
            }
        };
        let kind = StreamKind::Crate(kind);
        Ok(SsrCipher {
            kind: Some(kind),
            key: kdf(password.as_bytes(), kind.key_len()),
        })
    }

    pub(super) fn iv_len(&self) -> usize {
        self.kind.map_or(0, StreamKind::iv_len)
    }

    pub(crate) fn layer(&self) -> io::Result<CipherLayer> {
        let mut iv = vec![0u8; self.iv_len()];
        rand::fill(&mut iv[..]);
        Ok(CipherLayer {
            kind: self.kind,
            key: self.key.clone(),
            enc: self
                .kind
                .map(|kind| KeyStream::new(kind, &self.key, &iv))
                .transpose()?,
            iv,
            wrote_iv: false,
            dec: None,
        })
    }

    /// A UDP packet is a fresh IV followed by the stream-encrypted payload.
    pub(crate) fn seal_packet(&self, packet: &mut concord_common::PacketBuf) -> io::Result<()> {
        let Some(kind) = self.kind else {
            return Ok(());
        };
        let mut iv = vec![0u8; kind.iv_len()];
        rand::fill(&mut iv[..]);
        KeyStream::new(kind, &self.key, &iv)?.apply(packet.as_mut_slice(), true)?;
        packet.prepend(iv.len()).copy_from_slice(&iv);
        Ok(())
    }

    pub(crate) fn open_packet(&self, packet: &mut concord_common::PacketBuf) -> io::Result<()> {
        let Some(kind) = self.kind else {
            return Ok(());
        };
        let iv_len = kind.iv_len();
        let iv = packet
            .as_slice()
            .get(..iv_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short packet"))?
            .to_vec();
        packet.consume(iv_len);
        KeyStream::new(kind, &self.key, &iv)?
            .apply(packet.as_mut_slice(), false)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad packet"))
    }

    pub(crate) fn headroom(&self) -> usize {
        self.iv_len()
    }
}

fn is_aead(upper: &str) -> bool {
    upper.contains("GCM")
        || upper.contains("POLY1305")
        || upper.contains("CCM")
        || upper.starts_with("AEAD_")
}

pub(crate) struct CipherLayer {
    kind: Option<StreamKind>,
    key: Vec<u8>,
    pub(super) iv: Vec<u8>,
    enc: Option<KeyStream>,
    wrote_iv: bool,
    dec: Option<KeyStream>,
}

impl Layer for CipherLayer {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        if !self.wrote_iv {
            out.extend_from_slice(&self.iv);
            self.wrote_iv = true;
        }
        let start = out.len();
        out.extend_from_slice(data);
        if let (Some(enc), Some(tail)) = (self.enc.as_mut(), out.get_mut(start..)) {
            enc.apply(tail, true)?;
        }
        Ok(())
    }

    fn decode(
        &mut self,
        input: &mut BytesMut,
        decoded: &mut BytesMut,
        _reply: &mut Vec<u8>,
    ) -> io::Result<()> {
        if let (None, Some(kind)) = (&self.dec, self.kind) {
            let iv_len = kind.iv_len();
            if input.len() < iv_len {
                return Ok(());
            }
            let iv = input.split_to(iv_len);
            self.dec = Some(KeyStream::new(kind, &self.key, &iv)?);
        }
        let mut chunk = input.split();
        if let Some(dec) = self.dec.as_mut() {
            dec.apply(&mut chunk, false)?;
        }
        decoded.unsplit(chunk);
        Ok(())
    }

    fn split(self) -> (BoxLayer, BoxLayer) {
        let decode = CipherLayer {
            kind: self.kind,
            key: self.key.clone(),
            iv: Vec::new(),
            enc: None,
            wrote_iv: true,
            dec: self.dec,
        };
        let encode = CipherLayer { dec: None, ..self };
        (Box::new(decode), Box::new(encode))
    }
}

#[cfg(test)]
mod tests;
