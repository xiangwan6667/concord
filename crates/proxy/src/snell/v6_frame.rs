#![allow(
    clippy::indexing_slicing,
    reason = "record slices are checked against their wire lengths before access"
)]

use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use bytes::BytesMut;
use concord_common::stream_buffer::BufferRequirements;

use super::codec::{Decode, Encode};
use super::frame::{Chunk, derive};
use super::v6_profile::Profile;
use crate::util::invalid_data;

const MAX_PAYLOAD: usize = 0xffff;
const HEADER: usize = 7;
const TAG: usize = 16;
const SALT: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Default,
    Unshaped,
    Raw,
}

impl Mode {
    pub(super) fn parse(name: &str) -> io::Result<Self> {
        match name {
            "" | "default" => Ok(Self::Default),
            "unshaped" => Ok(Self::Unshaped),
            "unsafe-raw" => Ok(Self::Raw),
            _ => Err(invalid_data(&format!("snell v6 unknown mode: {name}"))),
        }
    }
}

struct Aead {
    key: LessSafeKey,
    nonce: [u8; 12],
}

impl Aead {
    fn new(psk: &[u8], salt: &[u8]) -> io::Result<Self> {
        let key = UnboundKey::new(&AES_128_GCM, &derive(psk, salt, 16)?)
            .map_err(|_| io::Error::other("snell v6 key"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce: [0; 12],
        })
    }
    fn step(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.nonce);
        for byte in &mut self.nonce {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        nonce
    }
    fn seal(&mut self, data: &mut [u8], aad: &[u8]) -> io::Result<()> {
        let len = data
            .len()
            .checked_sub(TAG)
            .ok_or_else(|| invalid_data("snell v6 tag space"))?;
        let (plain, tag_space) = data.split_at_mut(len);
        let nonce = self.step();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), plain)
            .map_err(|_| io::Error::other("snell v6 seal"))?;
        tag_space.copy_from_slice(tag.as_ref());
        Ok(())
    }
    fn open<'a>(&mut self, data: &'a mut [u8], aad: &[u8]) -> io::Result<&'a mut [u8]> {
        let nonce = self.step();
        self.key
            .open_in_place(nonce, Aad::from(aad), data)
            .map_err(|_| invalid_data("snell v6 authentication failed"))
    }
}

pub(super) struct Sealer {
    mode: Mode,
    profile: Option<Arc<Profile>>,
    aead: Option<Aead>,
    salt: [u8; SALT],
    salt_sent: bool,
    seq: u32,
    chunk: usize,
    last_write: u64,
}

impl Sealer {
    pub(super) fn new(mode: Mode, psk: &[u8], profile: Option<Arc<Profile>>) -> io::Result<Self> {
        let mut salt = [0; SALT];
        rand::fill(&mut salt[..]);
        Ok(Self {
            mode,
            profile,
            aead: if mode == Mode::Raw {
                None
            } else {
                Some(Aead::new(psk, &salt)?)
            },
            salt,
            salt_sent: false,
            seq: 0,
            chunk: 0,
            last_write: 0,
        })
    }

    #[cfg(test)]
    pub(super) fn set_test_salt(&mut self, psk: &[u8], salt: [u8; SALT]) -> io::Result<()> {
        self.salt = salt;
        if self.mode != Mode::Raw {
            self.aead = Some(Aead::new(psk, &salt)?);
        }
        Ok(())
    }

    fn limit_at(&mut self, now: u64) -> usize {
        let Some(p) = &self.profile else {
            return MAX_PAYLOAD;
        };
        if self.last_write == 0
            || now.saturating_sub(self.last_write) > p.idle_reset
            || self.chunk == 0
        {
            self.chunk = p.chunk_initial;
        }
        let mut limit = p.payload_limit(self.seq, self.chunk);
        if self.seq == 0 {
            limit = limit.min(p.first_cap);
        }
        self.chunk = p.next_chunk(self.chunk);
        self.last_write = now;
        limit.clamp(1, MAX_PAYLOAD)
    }

    fn record(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD {
            return Err(invalid_data("snell v6 payload too large"));
        }
        let salt_len = if self.salt_sent || self.mode == Mode::Raw {
            0
        } else {
            self.profile.as_ref().map_or(SALT, |p| p.salt_len)
        };
        let prefix_len = self.profile.as_ref().map_or(0, |p| p.prefix_len(self.seq));
        let pad_len = self.profile.as_ref().map_or(0, |p| {
            p.padding_len(self.seq, payload.len(), prefix_len, salt_len)
        });
        let tag_len = if self.mode == Mode::Raw { 0 } else { TAG };
        let body_len = payload.len() + if payload.is_empty() { 0 } else { tag_len };
        let start = out.len();
        out.resize(
            start + salt_len + prefix_len + HEADER + tag_len + pad_len + body_len,
            0,
        );
        let (salt, rest) = out[start..].split_at_mut(salt_len);
        let (prefix, rest) = rest.split_at_mut(prefix_len);
        let (head, rest) = rest.split_at_mut(HEADER + tag_len);
        let (pad, body) = rest.split_at_mut(pad_len);
        if let Some(p) = &self.profile {
            if salt_len > 0 {
                p.fill(u32::MAX, salt);
                p.put_salt(&self.salt, salt);
            }
            p.fill(self.seq, prefix);
            p.fill(self.seq, pad);
        } else if salt_len > 0 {
            salt.copy_from_slice(&self.salt);
        }
        head[0] = 4;
        head[3..5].copy_from_slice(&(pad_len as u16).to_be_bytes());
        head[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        if let Some(aead) = &mut self.aead {
            aead.seal(head, prefix)?;
        }
        if !payload.is_empty() {
            body[..payload.len()].copy_from_slice(payload);
            if let Some(aead) = &mut self.aead {
                aead.seal(body, pad)?;
            }
            if let Some(p) = &self.profile {
                p.interleave(self.seq, pad, body);
            }
        }
        self.salt_sent = true;
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Encode for Sealer {
    fn seal_stream(&mut self, out: &mut Vec<u8>, mut data: &[u8]) -> io::Result<()> {
        let now = now_seconds();
        while !data.is_empty() {
            let take = self.limit_at(now).min(data.len());
            self.record(out, &data[..take])?;
            data = &data[take..];
        }
        Ok(())
    }
    fn seal_chunk(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        self.limit_at(now_seconds());
        self.record(out, data)
    }
    fn seal_zero(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        self.seal_chunk(out, &[])
    }
    fn write_requirements(&self) -> BufferRequirements {
        BufferRequirements::default()
    }
}

struct Header {
    padding: usize,
    payload: usize,
    seq: u32,
}

pub(super) struct Opener {
    mode: Mode,
    psk: Vec<u8>,
    profile: Option<Arc<Profile>>,
    aead: Option<Aead>,
    pending: Option<Header>,
    seq: u32,
}

impl Opener {
    pub(super) fn new(mode: Mode, psk: &[u8], profile: Option<Arc<Profile>>) -> Self {
        Self {
            mode,
            psk: psk.to_vec(),
            profile,
            aead: None,
            pending: None,
            seq: 0,
        }
    }

    fn init(&mut self, input: &mut BytesMut) -> io::Result<bool> {
        if self.mode == Mode::Raw || self.aead.is_some() {
            return Ok(true);
        }
        let len = self.profile.as_ref().map_or(SALT, |p| p.salt_len);
        if input.len() < len {
            return Ok(false);
        }
        let block = input.split_to(len);
        let salt = if let Some(p) = &self.profile {
            p.salt(&block)
        } else {
            block[..SALT].try_into().unwrap_or_default()
        };
        self.aead = Some(Aead::new(&self.psk, &salt)?);
        Ok(true)
    }

    fn header(&mut self, input: &mut BytesMut) -> io::Result<bool> {
        let prefix_len = self.profile.as_ref().map_or(0, |p| p.prefix_len(self.seq));
        let size = prefix_len + HEADER + if self.mode == Mode::Raw { 0 } else { TAG };
        if input.len() < size {
            return Ok(false);
        }
        let mut head = input.split_to(size);
        let (prefix, sealed) = head.split_at_mut(prefix_len);
        let plain = if let Some(aead) = &mut self.aead {
            aead.open(sealed, prefix)?
        } else {
            sealed
        };
        if plain[0] != 4 || (self.mode != Mode::Default && (plain[1] != 0 || plain[2] != 0)) {
            return Err(invalid_data("snell v6 invalid record header"));
        }
        let padding = usize::from(u16::from_be_bytes([plain[3], plain[4]]));
        let payload = usize::from(u16::from_be_bytes([plain[5], plain[6]]));
        if self.mode != Mode::Default && padding != 0 {
            return Err(invalid_data("snell v6 unexpected record padding"));
        }
        self.pending = Some(Header {
            padding,
            payload,
            seq: self.seq,
        });
        self.seq = self.seq.wrapping_add(1);
        Ok(true)
    }
}

impl Decode for Opener {
    fn at_chunk_boundary(&self) -> bool {
        self.pending.is_none()
    }
    fn open(&mut self, input: &mut BytesMut, plain: &mut BytesMut) -> io::Result<Option<Chunk>> {
        if !self.init(input)? {
            return Ok(None);
        }
        if self.pending.is_none() && !self.header(input)? {
            return Ok(None);
        }
        let Some(head) = &self.pending else {
            return Ok(None);
        };
        let len = head.padding
            + head.payload
            + if head.payload > 0 && self.mode != Mode::Raw {
                TAG
            } else {
                0
            };
        if input.len() < len {
            return Ok(None);
        }
        let mut body = input.split_to(len);
        let (pad, sealed) = body.split_at_mut(head.padding);
        let chunk = if head.payload == 0 {
            Chunk::Zero
        } else {
            if let Some(p) = &self.profile {
                p.interleave(head.seq, pad, sealed);
            }
            let data = if let Some(aead) = &mut self.aead {
                aead.open(sealed, pad)?
            } else {
                sealed
            };
            plain.extend_from_slice(data);
            Chunk::Data
        };
        self.pending = None;
        Ok(Some(chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shaped_schedule_resets_only_after_the_profile_idle_seconds() -> io::Result<()> {
        let psk = b"snell-v6-test-psk-0123456789";
        let p = Arc::new(Profile::new(psk));
        let mut sealer = Sealer::new(Mode::Default, psk, Some(p.clone()))?;
        assert_eq!(
            sealer.limit_at(100),
            p.payload_limit(0, p.chunk_initial).min(p.first_cap)
        );
        sealer.record(&mut Vec::new(), b"first")?;
        assert_eq!(
            sealer.limit_at(100 + p.idle_reset),
            p.payload_limit(1, p.next_chunk(p.chunk_initial))
        );
        sealer.record(&mut Vec::new(), b"second")?;
        assert_eq!(
            sealer.limit_at(101 + p.idle_reset * 2),
            p.payload_limit(2, p.chunk_initial)
        );
        Ok(())
    }
}
