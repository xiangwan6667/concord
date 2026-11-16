mod crypto;
mod mask;
mod padding;
mod record;
#[cfg(test)]
mod tests;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aws_lc_rs::agreement::{self, UnparsedPublicKey, X25519};
use aws_lc_rs::kem::{DecapsulationKey, EncapsulationKey, ML_KEM_768};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use concord_common::BoxStream;
use concord_common::sync::lock;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crypto::{Aead, Ctr, ctr, xor};
use padding::Padding;
pub(crate) use record::{EncryptionRead, EncryptionStream, EncryptionWrite};

#[derive(Clone)]
struct Session {
    expires: Instant,
    pfs: Vec<u8>,
    ticket: [u8; 16],
}

pub(crate) struct Client {
    keys: Vec<Vec<u8>>,
    mode: u8,
    resume: bool,
    padding: Padding,
    session: Mutex<Option<Session>>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn x_key() -> io::Result<(agreement::PrivateKey, Vec<u8>)> {
    let key = agreement::PrivateKey::generate(&X25519)
        .map_err(|_| invalid("VLESS X25519 key generation failed"))?;
    let public = key
        .compute_public_key()
        .map_err(|_| invalid("VLESS X25519 public key failed"))?
        .as_ref()
        .to_vec();
    Ok((key, public))
}

fn agree(key: &agreement::PrivateKey, public: &[u8]) -> io::Result<Vec<u8>> {
    agreement::agree(key, UnparsedPublicKey::new(&X25519, public), (), |key| {
        Ok(key.to_vec())
    })
    .map_err(|_| invalid("VLESS X25519 agreement failed"))
}

impl Client {
    pub(crate) fn parse(text: &str) -> io::Result<Option<Arc<Self>>> {
        if matches!(text, "" | "none") {
            return Ok(None);
        }
        let parts: Vec<_> = text.split('.').collect();
        let ["mlkem768x25519plus", mode, rtt, rest @ ..] = parts.as_slice() else {
            return Err(invalid("invalid VLESS Encryption value"));
        };
        let mode = match *mode {
            "native" => 0,
            "xorpub" => 1,
            "random" => 2,
            _ => return Err(invalid("invalid VLESS Encryption mode")),
        };
        let resume = match *rtt {
            "1rtt" => false,
            "0rtt" => true,
            _ => return Err(invalid("invalid VLESS Encryption RTT mode")),
        };
        let mut keys = Vec::new();
        let mut padding = Vec::new();
        for part in rest {
            if part.len() < 20 {
                padding.push(*part);
                continue;
            }
            let key = URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|_| invalid("invalid VLESS Encryption public key"))?;
            match key.len() {
                32 => {}
                1184 => {
                    EncapsulationKey::new(&ML_KEM_768, &key)
                        .map_err(|_| invalid("invalid VLESS ML-KEM-768 public key"))?;
                }
                _ => return Err(invalid("invalid VLESS Encryption public key size")),
            }
            keys.push(key);
        }
        if keys.is_empty() {
            return Err(invalid("VLESS Encryption requires a public key"));
        }
        Ok(Some(Arc::new(Self {
            keys,
            mode,
            resume,
            padding: Padding::parse(&padding.join("."))?,
            session: Mutex::new(None),
        })))
    }

    pub(crate) fn reset(&self) {
        *lock(&self.session) = None;
    }

    fn expire(&self, pfs: &[u8]) {
        let mut session = lock(&self.session);
        if session.as_ref().is_some_and(|session| session.pfs == pfs) {
            *session = None;
        }
    }

    fn relays(&self, iv: &[u8; 16]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut bytes = Vec::new();
        let mut previous: Option<Ctr> = None;
        let mut final_key = Vec::new();
        for (index, public) in self.keys.iter().enumerate() {
            let (mut exchange, key) = if public.len() == 32 {
                let (private, exchange) = x_key()?;
                (exchange, agree(&private, public)?)
            } else {
                let (ciphertext, key) = EncapsulationKey::new(&ML_KEM_768, public)
                    .map_err(|_| invalid("invalid VLESS ML-KEM-768 key"))?
                    .encapsulate()
                    .map_err(|_| invalid("VLESS ML-KEM-768 encapsulation failed"))?;
                (ciphertext.as_ref().to_vec(), key.as_ref().to_vec())
            };
            if self.mode > 0 {
                xor(&mut ctr(public, iv), &mut exchange);
            }
            if let Some(previous) = &mut previous {
                xor(previous, exchange.get_mut(..32).unwrap_or_default());
            }
            bytes.extend_from_slice(&exchange);
            if let Some(next) = self.keys.get(index + 1) {
                let mut next_hash = *blake3::hash(next).as_bytes();
                let mut cipher = ctr(&key, iv);
                xor(&mut cipher, &mut next_hash);
                bytes.extend_from_slice(&next_hash);
                previous = Some(cipher);
            }
            final_key = key;
        }
        Ok((bytes, final_key))
    }

    pub(crate) async fn handshake(self: &Arc<Self>, io: BoxStream) -> io::Result<EncryptionStream> {
        self.handshake_as(io, crypto::use_aes()).await
    }

    async fn send_hello(
        &self,
        io: &mut BoxStream,
        mut prefix: Vec<u8>,
        nfs: &mut Aead,
    ) -> io::Result<()> {
        let (length, mut lengths, gaps) = self.padding.create();
        let head_length = prefix.len();
        prefix.extend_from_slice(&nfs.seal(&((length - 18) as u16).to_be_bytes(), &[])?);
        prefix.extend_from_slice(&nfs.seal(&vec![0; length - 34], &[])?);
        if let Some(first) = lengths.first_mut() {
            *first += head_length;
        }
        let mut offset = 0;
        for (index, length) in lengths.into_iter().enumerate() {
            io.write_all(
                prefix
                    .get(offset..offset + length)
                    .ok_or_else(|| invalid("invalid VLESS padding length"))?,
            )
            .await?;
            offset += length;
            if let Some(gap) = gaps.get(index)
                && !gap.is_zero()
            {
                tokio::time::sleep(*gap).await;
            }
        }
        io.flush().await
    }

    async fn handshake_as(
        self: &Arc<Self>,
        mut io: BoxStream,
        aes: bool,
    ) -> io::Result<EncryptionStream> {
        let mut iv = [0; 16];
        rand::rng().fill(&mut iv);
        let (relays, nfs_key) = self.relays(&iv)?;
        let mut prefix = iv.to_vec();
        prefix.extend_from_slice(&relays);
        let mut nfs = Aead::new(&iv, &nfs_key, aes)?;
        let session = lock(&self.session)
            .clone()
            .filter(|session| session.expires > Instant::now());
        if let Some(session) = session.filter(|_| self.resume) {
            prefix.extend_from_slice(&nfs.seal(&32_u16.to_be_bytes(), &[])?);
            let encrypted_ticket = nfs.seal(&session.ticket, &[])?;
            prefix.extend_from_slice(&encrypted_ticket);
            let mut united = session.pfs.clone();
            united.extend_from_slice(&nfs_key);
            let state = record::State {
                write: Aead::new(&encrypted_ticket, &united, aes)?,
                read: None,
                write_xor: (self.mode == 2).then(|| ctr(&united, &iv)),
                read_xor: None,
                united,
                aes,
                prefix,
                padding: 0,
                random: self.mode == 2,
                resumption: Some((Arc::downgrade(self), session.pfs)),
            };
            return Ok(EncryptionStream::new(io, state));
        }
        let pfs = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| invalid("VLESS ML-KEM-768 generation failed"))?;
        let (x_private, x_public) = x_key()?;
        let mut public = pfs
            .encapsulation_key()
            .and_then(|key| key.key_bytes())
            .map_err(|_| invalid("VLESS ML-KEM-768 public key failed"))?
            .as_ref()
            .to_vec();
        public.extend_from_slice(&x_public);
        prefix.extend_from_slice(&nfs.seal(&(public.len() as u16 + 16).to_be_bytes(), &[])?);
        prefix.extend_from_slice(&nfs.seal(&public, &[])?);
        self.send_hello(&mut io, prefix, &mut nfs).await?;
        let mut exchange = vec![0; 1088 + 32 + 16];
        io.read_exact(&mut exchange).await?;
        nfs.open_max(&mut exchange)?;
        let peer_context = exchange.get(..1120).unwrap_or_default().to_vec();
        let (ciphertext, peer_x) = exchange
            .get(..1120)
            .and_then(|bytes| bytes.split_at_checked(1088))
            .ok_or_else(|| invalid("bad VLESS PFS exchange"))?;
        let mut pfs_key = pfs
            .decapsulate(ciphertext.into())
            .map_err(|_| invalid("VLESS ML-KEM-768 decapsulation failed"))?
            .as_ref()
            .to_vec();
        pfs_key.extend_from_slice(&agree(&x_private, peer_x)?);
        let mut united = pfs_key.clone();
        united.extend_from_slice(&nfs_key);
        let write = Aead::new(&public, &united, aes)?;
        let mut read = Aead::new(&peer_context, &united, aes)?;
        let mut ticket = [0; 32];
        io.read_exact(&mut ticket).await?;
        read.open(&mut ticket, &[])?;
        let mut random_iv = [0; 16];
        random_iv.copy_from_slice(
            ticket
                .get(..16)
                .ok_or_else(|| invalid("bad VLESS ticket"))?,
        );
        let seconds = u16::from_be_bytes([random_iv[0], random_iv[1]]);
        if self.resume && seconds > 0 {
            *lock(&self.session) = Some(Session {
                expires: Instant::now() + Duration::from_secs(u64::from(seconds)),
                pfs: pfs_key,
                ticket: random_iv,
            });
        }
        let mut length = [0; 18];
        io.read_exact(&mut length).await?;
        read.open(&mut length, &[])?;
        let padding = usize::from(u16::from_be_bytes([length[0], length[1]]));
        if padding < 16 {
            return Err(invalid("bad VLESS server padding length"));
        }
        let state = record::State {
            write,
            read: Some(read),
            write_xor: (self.mode == 2).then(|| ctr(&united, &iv)),
            read_xor: (self.mode == 2).then(|| ctr(&united, &random_iv)),
            united,
            aes,
            prefix: Vec::new(),
            padding,
            random: self.mode == 2,
            resumption: None,
        };
        Ok(EncryptionStream::new(io, state))
    }
}
