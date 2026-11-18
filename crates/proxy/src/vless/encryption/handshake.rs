use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_768};
use concord_common::BoxStream;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use super::crypto::{Aead, Ctr};
use super::record::Session;
use super::{Client, Encrypted, Mode, PublicKey, Ticket, invalid};

impl Client {
    pub(super) fn relay_hello(&self, iv: [u8; 16]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        self.relay_hello_with_x25519(iv, || rand::rng().random())
    }

    pub(super) fn relay_hello_with_x25519(
        &self,
        iv: [u8; 16],
        mut ephemeral: impl FnMut() -> [u8; 32],
    ) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut hello = iv.to_vec();
        let mut previous: Option<Ctr> = None;
        let mut secret = Vec::new();
        for (index, relay) in self.relays.iter().enumerate() {
            let mut exchange = match &relay.key {
                PublicKey::X25519(public) => {
                    let private = StaticSecret::from(ephemeral());
                    let shared = private.diffie_hellman(public);
                    if !shared.was_contributory() {
                        return Err(invalid("invalid X25519 public key"));
                    }
                    secret = shared.as_bytes().to_vec();
                    XPublic::from(&private).as_bytes().to_vec()
                }
                PublicKey::MlKem(key) => {
                    let (ciphertext, shared) = key.encapsulate().map_err(invalid)?;
                    secret = shared.as_ref().to_vec();
                    ciphertext.as_ref().to_vec()
                }
            };
            if self.mode != Mode::Native {
                Ctr::new(&relay.bytes, iv).apply(&mut exchange);
            }
            if let Some(previous) = &mut previous {
                previous.apply(exchange.split_at_mut(32).0);
            }
            hello.extend_from_slice(&exchange);
            if let Some(next) = self.relays.get(index + 1) {
                let mut ctr = Ctr::new(&secret, iv);
                let mut hash = next.hash;
                ctr.apply(&mut hash);
                hello.extend_from_slice(&hash);
                previous = Some(ctr);
            }
        }
        Ok((hello, secret))
    }

    pub(super) async fn handshake_with_cipher(
        self: &Arc<Self>,
        mut io: BoxStream,
        aes: bool,
    ) -> io::Result<Encrypted> {
        let iv: [u8; 16] = rand::rng().random();
        let (hello, nfs) = self.relay_hello(iv)?;
        let ticket = if self.resume {
            concord_common::sync::lock(&self.ticket)
                .as_ref()
                .filter(|t| Instant::now() < t.expires)
                .cloned()
        } else {
            None
        };
        if let Some(ticket) = ticket {
            let session = self.resumed_session(hello, nfs, iv, aes, ticket)?;
            return Ok(Encrypted::new(io, session));
        }
        let nfs_aead = Aead::new(&iv, &nfs, aes)?;
        self.full_handshake(&mut io, hello, nfs_aead, nfs, iv, aes)
            .await
            .map(|session| Encrypted::new(io, session))
    }

    pub(super) fn resumed_session(
        self: &Arc<Self>,
        mut hello: Vec<u8>,
        nfs: Vec<u8>,
        iv: [u8; 16],
        aes: bool,
        ticket: Ticket,
    ) -> io::Result<Session> {
        let mut nfs_aead = Aead::new(&iv, &nfs, aes)?;
        append_sealed(&mut hello, &mut nfs_aead, &32u16.to_be_bytes())?;
        let sealed = append_sealed(&mut hello, &mut nfs_aead, &ticket.bytes)?;
        let mut united = ticket.pfs.to_vec();
        united.extend_from_slice(&nfs);
        let send = Aead::new(&sealed, &united, aes)?;
        Ok(Session {
            united: Arc::from(united),
            send,
            recv: None,
            aes,
            iv,
            recv_iv: None,
            padding: 0,
            prewrite: hello,
            resume: Some((self.clone(), ticket.pfs)),
            random: self.mode == Mode::Random,
        })
    }

    async fn full_handshake(
        &self,
        io: &mut BoxStream,
        mut hello: Vec<u8>,
        mut nfs_aead: Aead,
        nfs: Vec<u8>,
        iv: [u8; 16],
        aes: bool,
    ) -> io::Result<Session> {
        let mlkem = DecapsulationKey::generate(&ML_KEM_768).map_err(invalid)?;
        let xsecret = StaticSecret::from(rand::rng().random::<[u8; 32]>());
        let mut public = mlkem
            .encapsulation_key()
            .map_err(invalid)?
            .key_bytes()
            .map_err(invalid)?
            .as_ref()
            .to_vec();
        public.extend_from_slice(XPublic::from(&xsecret).as_bytes());
        append_sealed(&mut hello, &mut nfs_aead, &1232u16.to_be_bytes())?;
        append_sealed(&mut hello, &mut nfs_aead, &public)?;
        let prefix = hello.len();
        let (lens, gaps) = self.padding.sample();
        let padding_len: usize = lens.iter().sum();
        let body_len = u16::try_from(padding_len - 18).map_err(invalid)?;
        append_sealed(&mut hello, &mut nfs_aead, &body_len.to_be_bytes())?;
        append_sealed(&mut hello, &mut nfs_aead, &vec![0; padding_len - 34])?;
        let mut remaining = hello.as_slice();
        for (i, &len) in lens.iter().enumerate() {
            let len = len + if i == 0 { prefix } else { 0 };
            if len > 0 {
                let (part, rest) = remaining.split_at(len);
                io.write_all(part).await?;
                remaining = rest;
            }
            if let Some(gap) = gaps.get(i).filter(|g| !g.is_zero()) {
                tokio::time::sleep(*gap).await;
            }
        }
        io.flush().await?;
        let mut reply = vec![0; 1136];
        io.read_exact(&mut reply).await?;
        // Go discards this error, but its cleared X25519 output then fails ECDH; reject explicitly.
        nfs_aead.open_nonce(&mut reply, &[], [255; 12])?;
        let (ciphertext, xpublic) = reply
            .split_at_checked(1088)
            .ok_or_else(|| invalid("short PFS reply"))?;
        let shared = mlkem.decapsulate(ciphertext.into()).map_err(invalid)?;
        let xpublic = XPublic::from(<[u8; 32]>::try_from(xpublic).map_err(invalid)?);
        let xshared = xsecret.diffie_hellman(&xpublic);
        if !xshared.was_contributory() {
            return Err(invalid("invalid server X25519 key"));
        }
        let mut pfs = [0; 64];
        pfs[..32].copy_from_slice(shared.as_ref());
        pfs[32..].copy_from_slice(xshared.as_bytes());
        let mut united = pfs.to_vec();
        united.extend_from_slice(&nfs);
        let send = Aead::new(&public, &united, aes)?;
        let mut recv = Aead::new(&reply, &united, aes)?;
        let mut ticket = vec![0; 32];
        io.read_exact(&mut ticket).await?;
        recv.open(&mut ticket, &[])?;
        let bytes: [u8; 16] = ticket.as_slice().try_into().map_err(invalid)?;
        let seconds = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut length = vec![0; 18];
        io.read_exact(&mut length).await?;
        recv.open(&mut length, &[])?;
        if self.resume && seconds > 0 {
            *concord_common::sync::lock(&self.ticket) = Some(Ticket {
                expires: Instant::now() + Duration::from_secs(u64::from(seconds)),
                pfs,
                bytes,
            });
        }
        let length: [u8; 2] = length.as_slice().try_into().map_err(invalid)?;
        let padding = usize::from(u16::from_be_bytes(length));
        Ok(Session {
            united: Arc::from(united),
            send,
            recv: Some(recv),
            aes,
            iv,
            recv_iv: Some(bytes),
            padding,
            prewrite: Vec::new(),
            resume: None,
            random: self.mode == Mode::Random,
        })
    }
}

fn append_sealed(hello: &mut Vec<u8>, aead: &mut Aead, data: &[u8]) -> io::Result<Vec<u8>> {
    let mut sealed = data.to_vec();
    aead.seal(&mut sealed, &[])?;
    hello.extend_from_slice(&sealed);
    Ok(sealed)
}
