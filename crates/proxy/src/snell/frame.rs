use std::io;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::aead::{AES_128_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use bytes::BytesMut;
use concord_common::stream_buffer::BufferRequirements;

use crate::util::invalid_data;

pub(super) const MAX_CHUNK: usize = 0x3FFF;
const SALT: usize = 16;
const TAG: usize = 16;
const NONCE: usize = 12;
const V4_HEADER: usize = 7;
const V4_FRAME: usize = 1460;
const V4_PADDING_MIN: usize = 0x100;
const V4_PADDING_SPAN: usize = 0x100;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Scheme {
    Chacha,
    Aes,
    V4,
}

pub(super) fn derive(psk: &[u8], salt: &[u8], len: usize) -> io::Result<Vec<u8>> {
    let params = Params::new(8, 3, 1, Some(32)).map_err(|err| io::Error::other(err.to_string()))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(psk, salt, &mut key)
        .map_err(|err| io::Error::other(err.to_string()))?;
    Ok(key.get(..len).unwrap_or_default().to_vec())
}

struct Aead {
    key: LessSafeKey,
    nonce: [u8; NONCE],
}

impl Aead {
    fn new(scheme: Scheme, psk: &[u8], salt: &[u8]) -> io::Result<Self> {
        let (algorithm, len) = match scheme {
            Scheme::Chacha => (&CHACHA20_POLY1305, 32),
            Scheme::Aes | Scheme::V4 => (&AES_128_GCM, 16),
        };
        let raw = derive(psk, salt, len)?;
        let unbound =
            UnboundKey::new(algorithm, &raw).map_err(|_| io::Error::other("snell key"))?;
        Ok(Aead {
            key: LessSafeKey::new(unbound),
            nonce: [0; NONCE],
        })
    }

    fn step(&mut self) -> Nonce {
        let current = Nonce::assume_unique_for_key(self.nonce);
        for byte in &mut self.nonce {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        current
    }

    fn seal(&mut self, out: &mut Vec<u8>, plain: &[u8]) -> io::Result<()> {
        let start = out.len();
        out.extend_from_slice(plain);
        let mut tail = out.split_off(start);
        let nonce = self.step();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut tail)
            .map_err(|_| io::Error::other("snell seal"))?;
        out.append(&mut tail);
        Ok(())
    }

    fn open<'a>(&mut self, sealed: &'a mut [u8]) -> io::Result<&'a mut [u8]> {
        let nonce = self.step();
        self.key
            .open_in_place(nonce, Aad::empty(), sealed)
            .map_err(|_| invalid_data("snell authentication failed"))
    }
}

pub(super) enum Chunk {
    Data,
    Zero,
}

pub(super) struct Sealer {
    scheme: Scheme,
    psk: Vec<u8>,
    state: Option<Aead>,
    salt: [u8; SALT],
    salt_sent: bool,
    initial_padding: usize,
    payload_limit: usize,
    last_write: Option<Instant>,
}

impl Sealer {
    pub(super) fn write_requirements(&self) -> BufferRequirements {
        let header = if self.scheme == Scheme::V4 {
            V4_HEADER
        } else {
            2
        };
        let initial = if self.salt_sent {
            0
        } else {
            SALT + if self.scheme == Scheme::V4 {
                self.initial_padding
            } else {
                0
            }
        };
        BufferRequirements {
            mtu: MAX_CHUNK,
            front: header + TAG + initial,
            rear: TAG,
        }
    }

    pub(super) fn new(scheme: Scheme, psk: &[u8]) -> Self {
        let mut salt = [0u8; SALT];
        rand::fill(&mut salt[..]);
        Sealer {
            scheme,
            psk: psk.to_vec(),
            state: None,
            salt,
            salt_sent: false,
            initial_padding: V4_PADDING_MIN + rand::random_range(0..V4_PADDING_SPAN),
            payload_limit: 0,
            last_write: None,
        }
    }

    fn aead(&mut self) -> io::Result<&mut Aead> {
        if self.state.is_none() {
            self.state = Some(Aead::new(self.scheme, &self.psk, &self.salt)?);
        }
        self.state
            .as_mut()
            .ok_or_else(|| io::Error::other("snell key"))
    }

    fn put_salt(&mut self, out: &mut Vec<u8>) {
        if !self.salt_sent {
            out.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
    }

    fn next_payload_limit(&mut self) -> usize {
        let now = Instant::now();
        let limit = match self.last_write {
            None => V4_FRAME - 55 - self.initial_padding,
            Some(last) if now.duration_since(last) > Duration::from_secs(30) => V4_FRAME - 39,
            Some(_) => self.payload_limit,
        };
        self.last_write = Some(now);
        self.payload_limit = if limit < MAX_CHUNK {
            (limit + V4_FRAME - 39).min(MAX_CHUNK)
        } else {
            MAX_CHUNK
        };
        limit
    }

    pub(super) fn seal_stream(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        if self.scheme != Scheme::V4 {
            for chunk in data.chunks(MAX_CHUNK) {
                self.seal_chunk(out, chunk)?;
            }
            return Ok(());
        }
        let mut rest = data;
        while !rest.is_empty() {
            let limit = self.next_payload_limit().clamp(1, MAX_CHUNK);
            let (now, later) = rest.split_at(limit.min(rest.len()));
            self.seal_chunk(out, now)?;
            rest = later;
        }
        Ok(())
    }

    pub(super) fn seal_chunk(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_CHUNK {
            return Err(invalid_data("snell chunk too large"));
        }
        if self.scheme == Scheme::V4 {
            let padding = if self.salt_sent {
                0
            } else {
                self.initial_padding
            };
            return self.v4_frame(out, payload, padding);
        }
        self.put_salt(out);
        let len = u16::try_from(payload.len()).unwrap_or(0).to_be_bytes();
        let aead = self.aead()?;
        aead.seal(out, &len)?;
        aead.seal(out, payload)
    }

    pub(super) fn seal_zero(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if self.scheme == Scheme::V4 {
            return self.v4_frame(out, &[], 0);
        }
        self.put_salt(out);
        self.aead()?.seal(out, &[0, 0])
    }

    fn v4_frame(&mut self, out: &mut Vec<u8>, payload: &[u8], padding: usize) -> io::Result<()> {
        if payload.is_empty() && padding != 0 {
            return Err(invalid_data("snell v4 zero chunk with padding"));
        }
        let mut header = [0u8; V4_HEADER];
        header[0] = 4;
        header[3..5].copy_from_slice(&u16::try_from(padding).unwrap_or(0).to_be_bytes());
        header[5..7].copy_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
        self.put_salt(out);
        let aead = self.aead()?;
        aead.seal(out, &header)?;
        if payload.is_empty() {
            return Ok(());
        }
        let mut sealed = Vec::with_capacity(payload.len() + TAG);
        aead.seal(&mut sealed, payload)?;
        if padding > 0 {
            let mut pad = v4_padding(&sealed, padding);
            swap_padding(&mut pad, &mut sealed);
            out.extend_from_slice(&pad);
        }
        out.extend_from_slice(&sealed);
        Ok(())
    }
}

fn swap_padding(padding: &mut [u8], sealed: &mut [u8]) {
    for (a, b) in padding.iter_mut().zip(sealed.iter_mut()).step_by(2) {
        std::mem::swap(a, b);
    }
}

fn v4_padding(sealed: &[u8], length: usize) -> Vec<u8> {
    let ones: usize = sealed
        .get(..sealed.len() & !3)
        .unwrap_or_default()
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum();
    let zeros = 8 * sealed.len() - ones;
    let random = || {
        let mut pad = vec![0u8; length];
        rand::fill(&mut pad[..]);
        pad
    };
    if zeros == 0 {
        return random();
    }
    let ratio = ones as f64 / zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        return random();
    }
    let base = if zeros < ones { 0.4 } else { 1.6 };
    let target = base + rand::random::<f64>() / 10.0;
    let total = 8 * (length + sealed.len());
    let want = (total as f64 * (target / (target + 1.0)) - ones as f64) as i64;
    let Ok(want) = usize::try_from(want) else {
        return random();
    };
    if want > 8 * length {
        return random();
    }
    let mut bits = vec![0u8; 8 * length];
    for slot in bits.iter_mut().take(want) {
        *slot = 1;
    }
    for i in (1..bits.len()).rev() {
        bits.swap(i, rand::random_range(0..=i));
    }
    let mut pad = vec![0u8; length];
    for (i, bit) in bits.iter().enumerate() {
        if *bit == 1
            && let Some(byte) = pad.get_mut(i / 8)
        {
            *byte |= 1 << (i % 8);
        }
    }
    pad
}

pub(super) struct Opener {
    scheme: Scheme,
    psk: Vec<u8>,
    state: Option<Aead>,
    pending: Option<V4Header>,
}

struct V4Header {
    padding: usize,
    payload: usize,
}

impl Opener {
    pub(super) fn new(scheme: Scheme, psk: &[u8]) -> Self {
        Opener {
            scheme,
            psk: psk.to_vec(),
            state: None,
            pending: None,
        }
    }

    pub(super) fn at_chunk_boundary(&self) -> bool {
        self.pending.is_none()
    }

    pub(super) fn open(
        &mut self,
        input: &mut BytesMut,
        plain: &mut BytesMut,
    ) -> io::Result<Option<Chunk>> {
        if self.state.is_none() {
            if input.len() < SALT {
                return Ok(None);
            }
            let salt = input.split_to(SALT);
            self.state = Some(Aead::new(self.scheme, &self.psk, &salt)?);
        }
        let Some(aead) = self.state.as_mut() else {
            return Ok(None);
        };
        if self.scheme == Scheme::V4 {
            return Self::open_v4(aead, &mut self.pending, input, plain);
        }
        if self.pending.is_none() {
            if input.len() < 2 + TAG {
                return Ok(None);
            }
            let mut head = input.split_to(2 + TAG);
            let opened = aead.open(&mut head)?;
            let len = (usize::from(*opened.first().unwrap_or(&0)) << 8
                | usize::from(*opened.get(1).unwrap_or(&0)))
                & MAX_CHUNK;
            if len == 0 {
                return Ok(Some(Chunk::Zero));
            }
            self.pending = Some(V4Header {
                padding: 0,
                payload: len,
            });
        }
        let Some(wanted) = self.pending.as_ref().map(|head| head.payload + TAG) else {
            return Ok(None);
        };
        if input.len() < wanted {
            return Ok(None);
        }
        let mut body = input.split_to(wanted);
        plain.extend_from_slice(aead.open(&mut body)?);
        self.pending = None;
        Ok(Some(Chunk::Data))
    }

    fn open_v4(
        aead: &mut Aead,
        pending: &mut Option<V4Header>,
        input: &mut BytesMut,
        plain: &mut BytesMut,
    ) -> io::Result<Option<Chunk>> {
        if pending.is_none() {
            if input.len() < V4_HEADER + TAG {
                return Ok(None);
            }
            let mut head = input.split_to(V4_HEADER + TAG);
            let opened = aead.open(&mut head)?;
            if opened.len() != V4_HEADER || opened.first() != Some(&4) {
                return Err(invalid_data("snell v4 invalid frame header"));
            }
            let be = |at: usize| {
                usize::from(u16::from_be_bytes([
                    opened.get(at).copied().unwrap_or(0),
                    opened.get(at + 1).copied().unwrap_or(0),
                ]))
            };
            let (padding, payload) = (be(3), be(5));
            if payload == 0 {
                if padding != 0 {
                    return Err(invalid_data("snell v4 zero chunk with padding"));
                }
                return Ok(Some(Chunk::Zero));
            }
            if payload > MAX_CHUNK || padding > MAX_CHUNK {
                return Err(invalid_data("snell v4 frame too large"));
            }
            *pending = Some(V4Header { padding, payload });
        }
        let Some((padding, wanted)) = pending
            .as_ref()
            .map(|head| (head.padding, head.padding + head.payload + TAG))
        else {
            return Ok(None);
        };
        if input.len() < wanted {
            return Ok(None);
        }
        let mut frame = input.split_to(wanted);
        let (pad, sealed) = frame.split_at_mut(padding);
        swap_padding(pad, sealed);
        plain.extend_from_slice(aead.open(sealed)?);
        *pending = None;
        Ok(Some(Chunk::Data))
    }
}
