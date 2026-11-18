mod crypto;
mod handshake;
mod kdf;
mod mask;
mod padding;
mod record;

use std::fmt::Display;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
use base64::Engine;
#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use concord_common::BoxStream;

use crate::ctx::BuildError;
use padding::Padding;
pub(super) use record::{Encrypted, EncryptedRead, EncryptedWrite};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Native,
    XorPub,
    Random,
}

enum PublicKey {
    X25519(x25519_dalek::PublicKey),
    MlKem(EncapsulationKey),
}

struct Relay {
    key: PublicKey,
    bytes: Vec<u8>,
    hash: [u8; 32],
}

#[derive(Clone)]
struct Ticket {
    expires: Instant,
    pfs: [u8; 64],
    bytes: [u8; 16],
}

pub(super) struct Client {
    relays: Vec<Relay>,
    mode: Mode,
    resume: bool,
    padding: Padding,
    ticket: Mutex<Option<Ticket>>,
}

fn invalid(error: impl Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("VLESS encryption: {error}"),
    )
}

impl Client {
    pub(super) fn parse(value: &str) -> Result<Option<Arc<Self>>, BuildError> {
        if matches!(value, "" | "none") {
            return Ok(None);
        }
        Self::parse_enabled(value)
            .map(|client| Some(Arc::new(client)))
            .map_err(|error| BuildError::invalid(error.to_string()))
    }

    fn parse_enabled(value: &str) -> io::Result<Self> {
        let parts: Vec<_> = value.split('.').collect();
        let ["mlkem768x25519plus", mode, rtt, segments @ ..] = parts.as_slice() else {
            return Err(invalid("invalid encryption value"));
        };
        if segments.is_empty() {
            return Err(invalid("invalid encryption value"));
        }
        let mode = match *mode {
            "native" => Mode::Native,
            "xorpub" => Mode::XorPub,
            "random" => Mode::Random,
            _ => return Err(invalid("invalid appearance mode")),
        };
        let resume = match *rtt {
            "1rtt" => false,
            "0rtt" => true,
            _ => return Err(invalid("invalid RTT mode")),
        };
        let mut relays = Vec::new();
        let mut padding = Vec::new();
        for part in segments {
            if part.len() < 20 {
                padding.push(*part);
                continue;
            }
            let decoder = GeneralPurpose::new(
                &base64::alphabet::URL_SAFE,
                GeneralPurposeConfig::new()
                    .with_decode_padding_mode(DecodePaddingMode::RequireNone)
                    .with_decode_allow_trailing_bits(true),
            );
            let encoded: Vec<_> = part
                .bytes()
                .filter(|byte| !matches!(byte, b'\r' | b'\n'))
                .collect();
            let bytes = decoder.decode(encoded).map_err(invalid)?;
            let key = match bytes.len() {
                32 => PublicKey::X25519(x25519_dalek::PublicKey::from(
                    <[u8; 32]>::try_from(bytes.as_slice()).map_err(invalid)?,
                )),
                1184 => {
                    let encoded: &[u8; 1184] = bytes.as_slice().try_into().map_err(invalid)?;
                    let (coefficients, _) = encoded.split_at(1152);
                    if coefficients
                        .as_chunks::<3>()
                        .0
                        .iter()
                        .any(|&[low, middle, high]| {
                            let first = u16::from(low) | (u16::from(middle & 15) << 8);
                            let second = u16::from(middle >> 4) | (u16::from(high) << 4);
                            first >= 3329 || second >= 3329
                        })
                    {
                        return Err(invalid("non-canonical ML-KEM-768 public key"));
                    }
                    PublicKey::MlKem(EncapsulationKey::new(&ML_KEM_768, &bytes).map_err(invalid)?)
                }
                _ => return Err(invalid("invalid public key length")),
            };
            relays.push(Relay {
                key,
                hash: *blake3::hash(&bytes).as_bytes(),
                bytes,
            });
        }
        if relays.is_empty() {
            return Err(invalid("empty public keys"));
        }
        Ok(Self {
            relays,
            mode,
            resume,
            padding: Padding::parse(&padding)?,
            ticket: Mutex::new(None),
        })
    }

    pub(super) async fn handshake(self: &Arc<Self>, io: BoxStream) -> io::Result<Encrypted> {
        self.handshake_with_cipher(io, aes_gcm_hardware()).await
    }

    pub(super) fn reset(&self) {
        *concord_common::sync::lock(&self.ticket) = None;
    }

    fn invalidate(&self, pfs: &[u8; 64]) {
        let mut cache = concord_common::sync::lock(&self.ticket);
        if cache.as_ref().is_some_and(|ticket| &ticket.pfs == pfs) {
            *cache = None;
        }
    }
}

fn aes_gcm_hardware() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("sse4.1")
            && std::is_x86_feature_detected!("ssse3")
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod interop_tests;
