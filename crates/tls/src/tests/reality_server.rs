//! A small REALITY server for tests: authenticates the session id like
//! `utls.RealityServer`, then speaks just enough TLS 1.3 to echo.

use std::io;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, UnparsedPublicKey, X25519};
use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
use aws_lc_rs::signature::{Ed25519KeyPair, ML_DSA_65_SIGNING, PqdsaKeyPair};
use aws_lc_rs::{hmac, rand::fill};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::reality::{
    CT_APPLICATION_DATA, CT_HANDSHAKE, Cursor, Hash, RecordKey, Suite, application_secrets, expand,
    extract, finished_verify_data, handshake_secrets, put_u24,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    None,
    BadFinished,
    NoSessionIdEcho,
    HelloRetry,
    BadHmac,
    BadCertificateVerify,
    UnsupportedCipher,
    HugeRecord,
    Garbage,
}

pub struct MockReality {
    private: agreement::PrivateKey,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub hybrid: bool,
    pub fault: Fault,
    pub alpn: Option<&'static [u8]>,
    pub suite: u16,
    pub client_version: [u8; 3],
    pub mldsa: Option<PqdsaKeyPair>,
    pub jls: bool,
    pub fragmented: bool,
}

impl MockReality {
    pub fn new() -> Self {
        let private = agreement::PrivateKey::generate(&X25519).unwrap();
        let public_key = private
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        Self {
            private,
            public_key,
            short_id: [0xab, 0xcd, 0, 0, 0, 0, 0, 0],
            hybrid: false,
            fault: Fault::None,
            alpn: Some(b"h2"),
            suite: 0x1301,
            client_version: [1, 8, 2],
            mldsa: None,
            jls: false,
            fragmented: false,
        }
    }
}

async fn read_record<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<([u8; 5], Vec<u8>)> {
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    io.read_exact(&mut body).await?;
    Ok((header, body))
}

fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 3, 3];
    out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    put_u24(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

fn bad(text: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, text.to_owned())
}

struct ClientHello {
    random: [u8; 32],
    session_id: Vec<u8>,
    x25519: Option<Vec<u8>>,
    mlkem_ek: Option<Vec<u8>>,
}

fn parse_client_hello(msg: &[u8]) -> io::Result<ClientHello> {
    let mut outer = Cursor::new(msg);
    if outer.u8()? != 1 {
        return Err(bad("not a client hello"));
    }
    let mut c = Cursor::new(outer.vec24()?);
    c.u16()?;
    let random: [u8; 32] = c.take(32)?.try_into().unwrap();
    let session_id = c.vec8()?.to_vec();
    c.vec16()?;
    c.vec8()?;
    let mut exts = Cursor::new(c.vec16()?);
    let (mut x25519, mut mlkem_ek) = (None, None);
    while !exts.is_empty() {
        let kind = exts.u16()?;
        let data = exts.vec16()?;
        if kind == 51 {
            let mut shares = Cursor::new(Cursor::new(data).vec16()?);
            while !shares.is_empty() {
                let group = shares.u16()?;
                let share = shares.vec16()?;
                match group {
                    0x001d if share.len() == 32 => x25519 = Some(share.to_vec()),
                    0x11ec if share.len() == 1184 + 32 => {
                        mlkem_ek = Some(share[..1184].to_vec());
                        x25519.get_or_insert_with(|| share[1184..].to_vec());
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(ClientHello {
        random,
        session_id,
        x25519,
        mlkem_ek,
    })
}

impl MockReality {
    fn reality_cert(
        &self,
        auth_key: &[u8],
        tamper: bool,
        hellos: &[u8],
    ) -> (Vec<u8>, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        if let Some(signer) = &self.mldsa {
            let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
            let mut context = hmac::Context::with_key(&hmac_key);
            context.update(key.public_key_raw());
            context.update(hellos);
            let mut signature = vec![0; ML_DSA_65_SIGNING.signature_len()];
            let length = signer
                .sign(context.sign().as_ref(), &mut signature)
                .unwrap();
            signature.truncate(length);
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 2, 3, 4],
                    signature,
                ));
        }
        let mut der = params.self_signed(&key).unwrap().der().to_vec();
        let mut mac = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA512, auth_key),
            key.public_key_raw(),
        )
        .as_ref()
        .to_vec();
        if tamper {
            mac[0] ^= 1;
        }
        let at = der.len() - 64;
        der[at..].copy_from_slice(&mac);
        (der, key)
    }

    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(&self, mut io: S) -> io::Result<()> {
        let (_, hello) = read_record(&mut io).await?;
        let parsed = parse_client_hello(&hello)?;
        let client_x = parsed
            .x25519
            .clone()
            .ok_or_else(|| bad("no x25519 share"))?;

        if self.fault == Fault::Garbage {
            io.write_all(&[0x99; 600]).await?;
            return Ok(());
        }
        if self.fault == Fault::HugeRecord {
            io.write_all(&[22, 3, 3, 0xff, 0xff]).await?;
            io.write_all(&vec![0u8; 70_000]).await?;
            return Ok(());
        }

        let auth_key = if self.jls {
            use aes_gcm::aead::{
                Aead, KeyInit, generic_array::GenericArray, generic_array::typenum::U32,
            };
            use sha2::{Digest, Sha256};
            let mut zeroed = hello.clone();
            zeroed[6..38].fill(0);
            let key = Sha256::digest([b"secret".as_slice(), &zeroed].concat());
            let nonce = Sha256::digest([b"name".as_slice(), &zeroed].concat());
            let cipher =
                aes_gcm::AesGcm::<aes_gcm::aes::Aes256, U32>::new(GenericArray::from_slice(&key));
            if cipher
                .decrypt(GenericArray::from_slice(&nonce), &hello[6..38])
                .is_err()
            {
                return Err(bad("jls client random does not authenticate"));
            }
            vec![0; 32]
        } else {
            let ecdh = agreement::agree(
                &self.private,
                UnparsedPublicKey::new(&X25519, &client_x),
                (),
                |s| Ok(s.to_vec()),
            )
            .map_err(|()| bad("agree"))?;
            let auth_key = expand(
                &extract(Hash::Sha256, &parsed.random[..20], &ecdh),
                b"REALITY",
                32,
            );
            let mut zeroed = hello.clone();
            zeroed[39..71].fill(0);
            let aead = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &auth_key).unwrap());
            let mut sealed = parsed.session_id.clone();
            let plain = aead
                .open_in_place(
                    Nonce::assume_unique_for_key(parsed.random[20..32].try_into().unwrap()),
                    Aad::from(zeroed.as_slice()),
                    &mut sealed,
                )
                .map_err(|_| bad("session id does not open"))?;
            if plain[..3] != self.client_version || plain[8..16] != self.short_id {
                return Err(bad("unknown client"));
            }

            auth_key
        };

        let xs = agreement::PrivateKey::generate(&X25519).unwrap();
        let xpub = xs.compute_public_key().unwrap();
        let x_ss = agreement::agree(&xs, UnparsedPublicKey::new(&X25519, &client_x), (), |s| {
            Ok(s.to_vec())
        })
        .unwrap();
        let (group, share, shared) = match (&parsed.mlkem_ek, self.hybrid) {
            (Some(ek), true) => {
                let (ct, ss) = EncapsulationKey::new(&ML_KEM_768, ek)
                    .unwrap()
                    .encapsulate()
                    .unwrap();
                let mut share = ct.as_ref().to_vec();
                share.extend_from_slice(xpub.as_ref());
                let mut shared = ss.as_ref().to_vec();
                shared.extend_from_slice(&x_ss);
                (0x11ecu16, share, shared)
            }
            _ => (0x001d, xpub.as_ref().to_vec(), x_ss),
        };

        let mut random = [0u8; 32];
        fill(&mut random).unwrap();
        if self.fault == Fault::HelloRetry {
            random = [
                0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
                0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
                0xc8, 0xa8, 0x33, 0x9c,
            ];
        }
        let cipher = if self.fault == Fault::UnsupportedCipher {
            0x00ff
        } else {
            self.suite
        };
        let mut sh = vec![3, 3];
        sh.extend_from_slice(&random);
        sh.push(32);
        if self.fault == Fault::NoSessionIdEcho {
            sh.extend_from_slice(&[0u8; 32]);
        } else {
            sh.extend_from_slice(&parsed.session_id);
        }
        sh.extend_from_slice(&cipher.to_be_bytes());
        sh.push(0);
        let mut exts = vec![0, 43, 0, 2, 3, 4, 0, 51];
        exts.extend_from_slice(&u16::try_from(4 + share.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&group.to_be_bytes());
        exts.extend_from_slice(&u16::try_from(share.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&share);
        sh.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        sh.extend_from_slice(&exts);
        let mut server_hello = message(2, &sh);
        if self.jls && self.fault != Fault::HelloRetry {
            use aes_gcm::aead::{
                Aead, KeyInit, generic_array::GenericArray, generic_array::typenum::U32,
            };
            use sha2::{Digest, Sha256};
            server_hello[6..38].fill(0);
            let key = Sha256::digest([b"secret".as_slice(), &server_hello].concat());
            let nonce = Sha256::digest([b"name".as_slice(), &server_hello].concat());
            let cipher =
                aes_gcm::AesGcm::<aes_gcm::aes::Aes256, U32>::new(GenericArray::from_slice(&key));
            let random = cipher
                .encrypt(GenericArray::from_slice(&nonce), [7; 16].as_slice())
                .unwrap();
            server_hello[6..38].copy_from_slice(&random);
        }
        for chunk in server_hello.chunks(if self.fragmented {
            1
        } else {
            server_hello.len()
        }) {
            io.write_all(&record(CT_HANDSHAKE, chunk)).await?;
        }
        io.write_all(&[20, 3, 3, 0, 1, 1]).await?;
        let Some(suite) = Suite::from_id(cipher) else {
            return Ok(());
        };
        if self.fault == Fault::HelloRetry {
            return Ok(());
        }

        let hash = suite.hash();
        let mut transcript = hello.clone();
        transcript.extend_from_slice(&server_hello);
        let secrets = handshake_secrets(hash, &shared, &transcript);
        let mut server_key = RecordKey::new(suite, &secrets.server)?;
        let mut client_key = RecordKey::new(suite, &secrets.client)?;

        let mut ee_body = vec![0, 0];
        if let Some(alpn) = self.alpn {
            let mut list = vec![u8::try_from(alpn.len()).unwrap()];
            list.extend_from_slice(alpn);
            let mut ext = vec![0, 16];
            ext.extend_from_slice(&u16::try_from(list.len() + 2).unwrap().to_be_bytes());
            ext.extend_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
            ext.extend_from_slice(&list);
            ee_body = u16::try_from(ext.len()).unwrap().to_be_bytes().to_vec();
            ee_body.extend_from_slice(&ext);
        }
        let ee = message(8, &ee_body);
        let (cert_der, cert_key) =
            self.reality_cert(&auth_key, self.fault == Fault::BadHmac, &transcript);
        let mut cert_body = vec![0];
        put_u24(&mut cert_body, cert_der.len() + 5);
        put_u24(&mut cert_body, cert_der.len());
        cert_body.extend_from_slice(&cert_der);
        cert_body.extend_from_slice(&[0, 0]);
        let cert = message(11, &cert_body);

        let mut so_far = transcript.clone();
        so_far.extend_from_slice(&ee);
        so_far.extend_from_slice(&cert);
        let mut to_sign = vec![0x20u8; 64];
        to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        to_sign.extend_from_slice(&hash.digest(&so_far));
        if self.fault == Fault::BadCertificateVerify {
            to_sign.push(1);
        }
        let signer = Ed25519KeyPair::from_pkcs8(&cert_key.serialize_der()).unwrap();
        let signature = signer.sign(&to_sign);
        let mut cv_body = vec![0x08, 0x07];
        cv_body.extend_from_slice(
            &u16::try_from(signature.as_ref().len())
                .unwrap()
                .to_be_bytes(),
        );
        cv_body.extend_from_slice(signature.as_ref());
        let cv = message(15, &cv_body);
        so_far.extend_from_slice(&cv);
        let mut verify_data = finished_verify_data(hash, &secrets.server, &so_far);
        if self.fault == Fault::BadFinished {
            verify_data[0] ^= 1;
        }
        let finished = message(20, &verify_data);
        so_far.extend_from_slice(&finished);

        for msg in [&ee, &cert, &cv, &finished] {
            io.write_all(&server_key.seal(CT_HANDSHAKE, msg)?).await?;
        }
        io.flush().await?;

        let (client_secret, server_secret) = application_secrets(hash, &secrets.master, &so_far);
        let (header, mut body) = loop {
            let (header, body) = read_record(&mut io).await?;
            if header[0] != 20 {
                break (header, body);
            }
        };
        let (kind, len) = client_key.open_in_place(&header, &mut body)?;
        let expected = finished_verify_data(hash, &secrets.client, &so_far);
        if kind != CT_HANDSHAKE || body[4..len] != expected {
            return Err(bad("client finished mismatch"));
        }

        let mut read_key = RecordKey::new(suite, &client_secret)?;
        let mut write_key = RecordKey::new(suite, &server_secret)?;
        loop {
            let (header, mut body) = match read_record(&mut io).await {
                Ok(record) => record,
                Err(_) => return Ok(()),
            };
            let (kind, len) = read_key.open_in_place(&header, &mut body)?;
            if kind == CT_APPLICATION_DATA {
                io.write_all(&write_key.seal(CT_APPLICATION_DATA, &body[..len])?)
                    .await?;
                io.flush().await?;
            } else if kind == 21 {
                io.write_all(&write_key.seal(21, &[1, 0])?).await?;
                return Ok(());
            }
        }
    }
}
