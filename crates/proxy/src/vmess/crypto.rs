use std::io;
use std::ops::Range;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_cfb::Aes128;
use aws_lc_rs::aead::{AES_128_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::digest::{Context as DigestContext, SHA256};
use cfb_mode::cipher::KeyIvInit;
use concord_common::Address;
use concord_common::stream_buffer::{BufferRequirements, StreamBuffer};
use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use rand::Rng;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, XofReader};

use crate::addr_codec::VMESS;
use crate::util::invalid_data;

pub(crate) const VERSION: u8 = 1;
pub(crate) const CHUNK: usize = 15_000;
pub(crate) const OVERHEAD: usize = 16;
const MAX_PADDING: usize = 64;

pub(crate) const CMD_TCP: u8 = 1;
pub(crate) const CMD_UDP: u8 = 2;
pub(crate) const CMD_MUX: u8 = 3;

const OPT_CHUNK_STREAM: u8 = 1;
const OPT_CHUNK_MASKING: u8 = 4;
const OPT_GLOBAL_PADDING: u8 = 8;
const OPT_AUTH_LENGTH: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Security {
    Legacy = 1,
    Aes128Gcm = 3,
    Chacha20Poly1305 = 4,
    None = 5,
}

impl Security {
    pub(crate) fn parse(name: &str) -> Option<Security> {
        Some(match name {
            "auto" => {
                if cfg!(any(
                    target_arch = "x86_64",
                    target_arch = "aarch64",
                    target_arch = "s390x"
                )) {
                    Security::Aes128Gcm
                } else {
                    Security::Chacha20Poly1305
                }
            }
            "none" | "zero" => Security::None,
            "aes-128-cfb" => Security::Legacy,
            "aes-128-gcm" => Security::Aes128Gcm,
            "chacha20-poly1305" => Security::Chacha20Poly1305,
            _ => return None,
        })
    }

    fn is_aead(self) -> bool {
        matches!(self, Security::Aes128Gcm | Security::Chacha20Poly1305)
    }
}

fn md5_parts(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = DigestContext::new(&SHA256);
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0; 32];
    output.copy_from_slice(hasher.finish().as_ref());
    output
}

/// VMess's KDF: HMAC-SHA256 nested once per path element, each level keyed by
/// the element and hashing with the level below.
pub(crate) fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = vec![b"VMess AEAD KDF", salt.as_bytes()];
    keys.extend_from_slice(path);
    nested(keys.len(), &keys, &[key])
}

fn nested(level: usize, keys: &[&[u8]], message: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    if level == 0 {
        return sha256_parts(message);
    }
    let key = keys.get(level - 1).copied().unwrap_or_default();
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = nested(level - 1, keys, &[key]);
        block
            .iter_mut()
            .zip(hashed)
            .for_each(|(slot, byte)| *slot = byte);
    } else {
        block
            .iter_mut()
            .zip(key)
            .for_each(|(slot, byte)| *slot = *byte);
    }
    let inner_pad = block.map(|byte| byte ^ 0x36);
    let outer_pad = block.map(|byte| byte ^ 0x5c);
    let mut inner_input: Vec<&[u8]> = vec![&inner_pad];
    inner_input.extend_from_slice(message);
    let inner = nested(level - 1, keys, &inner_input);
    nested(level - 1, keys, &[&outer_pad, &inner])
}

pub(crate) fn user_id(text: &str) -> [u8; 16] {
    if let Ok(parsed) = uuid::Uuid::parse_str(text) {
        return *parsed.as_bytes();
    }
    let mut hasher = sha1::Sha1::new();
    sha1::Digest::update(&mut hasher, [0u8; 16]);
    sha1::Digest::update(&mut hasher, text.as_bytes());
    let digest = sha1::Digest::finalize(hasher);
    let mut id = [0u8; 16];
    id.iter_mut()
        .zip(digest.iter())
        .for_each(|(slot, byte)| *slot = *byte);
    if let Some(byte) = id.get_mut(6) {
        *byte = (*byte & 0x0f) | 0x50;
    }
    if let Some(byte) = id.get_mut(8) {
        *byte = (*byte & 0x3f) | 0x80;
    }
    id
}

pub(crate) fn command_key(id: &[u8; 16]) -> [u8; 16] {
    md5_parts(&[id, b"c48619fe-8f02-49e0-b9e9-edf763e17e21"])
}

pub(crate) fn alter_key(id: &[u8; 16]) -> [u8; 16] {
    let mut out = md5_parts(&[id, b"16167dc8-16b6-4e6d-b8bb-65dd68113a81"]);
    while out == *id {
        out = md5_parts(&[&out, b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2"]);
    }
    out
}

fn head16(data: &[u8]) -> io::Result<[u8; 16]> {
    data.get(..16)
        .and_then(|head| <[u8; 16]>::try_from(head).ok())
        .ok_or_else(|| invalid_data("short key material"))
}

fn aead(security: Security, key: &[u8]) -> io::Result<LessSafeKey> {
    let unbound = match security {
        Security::Chacha20Poly1305 => {
            let first = md5_parts(&[key]);
            let second = md5_parts(&[&first]);
            let mut wide = [0u8; 32];
            let (low, high) = wide.split_at_mut(16);
            low.copy_from_slice(&first);
            high.copy_from_slice(&second);
            UnboundKey::new(&CHACHA20_POLY1305, &wide)
        }
        _ => UnboundKey::new(&AES_128_GCM, key),
    };
    unbound
        .map(LessSafeKey::new)
        .map_err(|_| invalid_data("bad vmess key"))
}

fn gcm(key: &[u8]) -> io::Result<LessSafeKey> {
    aead(Security::Aes128Gcm, key)
}

fn nonce12(base: &[u8; 12], count: u16) -> Nonce {
    let mut bytes = *base;
    if let Some(head) = bytes.first_chunk_mut::<2>() {
        *head = count.to_be_bytes();
    }
    Nonce::assume_unique_for_key(bytes)
}

fn base_nonce(iv: &[u8; 16]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.iter_mut()
        .zip(iv)
        .for_each(|(slot, byte)| *slot = *byte);
    out
}

pub(crate) fn one_shot_seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plain: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = gcm(key)?;
    let nonce = <[u8; 12]>::try_from(nonce).map_err(|_| invalid_data("bad nonce"))?;
    let mut out = plain.to_vec();
    let tag = cipher
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut out,
        )
        .map_err(|_| invalid_data("seal failed"))?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

fn one_shot_open(key: &[u8], nonce: &[u8], aad: &[u8], sealed: &mut [u8]) -> io::Result<usize> {
    let cipher = gcm(key)?;
    let nonce = <[u8; 12]>::try_from(nonce).map_err(|_| invalid_data("bad nonce"))?;
    cipher
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), sealed)
        .map(|plain| plain.len())
        .map_err(|_| invalid_data("vmess header authentication failed"))
}

fn fnv1a(data: &[u8]) -> u32 {
    data.iter().fold(0x811c_9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

pub(crate) struct Request {
    pub(crate) key: [u8; 16],
    pub(crate) nonce: [u8; 16],
    pub(crate) response_header: u8,
    pub(crate) security: Security,
    pub(crate) option: u8,
    pub(crate) command: u8,
}

impl Request {
    pub(crate) fn new(
        security: Security,
        command: u8,
        global_padding: bool,
        authenticated_length: bool,
    ) -> Self {
        let mut rng = rand::rng();
        let mut option = 0;
        match security {
            Security::None => {
                if command == CMD_UDP {
                    option = OPT_CHUNK_STREAM;
                }
            }
            Security::Legacy => option = OPT_CHUNK_STREAM,
            Security::Aes128Gcm | Security::Chacha20Poly1305 => {
                option = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING;
                if global_padding {
                    option |= OPT_GLOBAL_PADDING;
                }
                if authenticated_length {
                    option |= OPT_AUTH_LENGTH;
                }
            }
        }
        Request {
            key: rng.random(),
            nonce: rng.random(),
            response_header: rng.random(),
            security,
            option,
            command,
        }
    }

    fn encode(&self, dst: &Address) -> io::Result<Vec<u8>> {
        let padding = rand::rng().random_range(0..16usize);
        let mut out = Vec::with_capacity(64 + padding);
        out.push(VERSION);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.key);
        out.push(self.response_header);
        out.push(self.option);
        out.push((u8::try_from(padding).unwrap_or(0) << 4) | self.security as u8);
        out.push(0);
        out.push(self.command);
        if self.command != CMD_MUX {
            VMESS.write(dst, &mut out)?;
        }
        let at = out.len();
        out.resize(at + padding, 0);
        if let Some(pad) = out.get_mut(at..) {
            rand::rng().fill(pad);
        }
        let hash = fnv1a(&out);
        out.extend_from_slice(&hash.to_be_bytes());
        Ok(out)
    }

    /// The AEAD handshake: auth id, sealed length, nonce, sealed header.
    pub(crate) fn seal_aead(
        &self,
        user: &[u8; 16],
        now: i64,
        dst: &Address,
    ) -> io::Result<Vec<u8>> {
        let header = self.encode(dst)?;
        let mut auth = [0u8; 16];
        {
            let (stamp, rest) = auth.split_at_mut(8);
            stamp.copy_from_slice(&now.to_be_bytes());
            let (random, check) = rest.split_at_mut(4);
            rand::rng().fill(random);
            let mut crc_input = [0u8; 12];
            let (a, b) = crc_input.split_at_mut(8);
            a.copy_from_slice(stamp);
            b.copy_from_slice(random);
            check.copy_from_slice(&crc32fast::hash(&crc_input).to_be_bytes());
        }
        let auth_key = head16(&kdf(user, "AES Auth ID Encryption", &[]))?;
        let cipher = aes::Aes128::new(&auth_key.into());
        let mut block = aes::Block::from(auth);
        cipher.encrypt_block(&mut block);
        let auth_id: [u8; 16] = block.into();

        let mut connection_nonce = [0u8; 8];
        rand::rng().fill(&mut connection_nonce);
        let path: [&[u8]; 2] = [&auth_id, &connection_nonce];
        let length = u16::try_from(header.len()).map_err(|_| invalid_data("header too long"))?;
        let length_key = kdf(user, "VMess Header AEAD Key_Length", &path);
        let length_nonce = kdf(user, "VMess Header AEAD Nonce_Length", &path);
        let header_key = kdf(user, "VMess Header AEAD Key", &path);
        let header_nonce = kdf(user, "VMess Header AEAD Nonce", &path);

        let mut out = Vec::with_capacity(16 + 18 + 8 + header.len() + 16);
        out.extend_from_slice(&auth_id);
        out.extend_from_slice(&one_shot_seal(
            length_key.get(..16).unwrap_or_default(),
            length_nonce.get(..12).unwrap_or_default(),
            &auth_id,
            &length.to_be_bytes(),
        )?);
        out.extend_from_slice(&connection_nonce);
        out.extend_from_slice(&one_shot_seal(
            header_key.get(..16).unwrap_or_default(),
            header_nonce.get(..12).unwrap_or_default(),
            &auth_id,
            &header,
        )?);
        Ok(out)
    }

    /// The legacy handshake used when `alterId > 0`.
    pub(crate) fn seal_legacy(
        &self,
        user: &[u8; 16],
        alter: &[u8; 16],
        now: u64,
        dst: &Address,
    ) -> io::Result<Vec<u8>> {
        let mut header = self.encode(dst)?;
        let mut mac =
            <Hmac<Md5> as Mac>::new_from_slice(alter).map_err(|_| invalid_data("bad alter key"))?;
        mac.update(&now.to_be_bytes());
        let id_hash = mac.finalize().into_bytes();
        let stamp = now.to_be_bytes();
        let iv = md5_parts(&[&stamp, &stamp, &stamp, &stamp]);
        cfb_mode::BufEncryptor::<Aes128>::new_from_slices(user, &iv)
            .map_err(|_| invalid_data("bad header key"))?
            .encrypt(&mut header);
        let mut out = Vec::with_capacity(16 + header.len());
        out.extend_from_slice(&id_hash);
        out.extend_from_slice(&header);
        Ok(out)
    }

    pub(crate) fn response_aead_keys(&self) -> ([u8; 16], [u8; 16]) {
        let key = sha256_parts(&[&self.key]);
        let nonce = sha256_parts(&[&self.nonce]);
        (
            head16(&key).unwrap_or_default(),
            head16(&nonce).unwrap_or_default(),
        )
    }

    pub(crate) fn response_legacy_keys(&self) -> ([u8; 16], [u8; 16]) {
        (md5_parts(&[&self.key]), md5_parts(&[&self.nonce]))
    }
}

/// Opens the sealed length and header of an AEAD response. `feed` supplies
/// exactly the bytes asked for.
pub(crate) struct ResponseOpener {
    key: [u8; 16],
    nonce: [u8; 16],
}

impl ResponseOpener {
    pub(crate) fn new(key: [u8; 16], nonce: [u8; 16]) -> Self {
        ResponseOpener { key, nonce }
    }

    pub(crate) fn open_length(&self, sealed: &mut [u8]) -> io::Result<usize> {
        let key = kdf(&self.key, "AEAD Resp Header Len Key", &[]);
        let nonce = kdf(&self.nonce, "AEAD Resp Header Len IV", &[]);
        let plain = one_shot_open(
            key.get(..16).unwrap_or_default(),
            nonce.get(..12).unwrap_or_default(),
            &[],
            sealed,
        )?;
        let bytes = sealed
            .get(..plain)
            .and_then(|p| <[u8; 2]>::try_from(p).ok());
        bytes
            .map(|b| usize::from(u16::from_be_bytes(b)))
            .ok_or_else(|| invalid_data("bad response length"))
    }

    pub(crate) fn open_header(&self, sealed: &mut [u8]) -> io::Result<()> {
        let key = kdf(&self.key, "AEAD Resp Header Key", &[]);
        let nonce = kdf(&self.nonce, "AEAD Resp Header IV", &[]);
        one_shot_open(
            key.get(..16).unwrap_or_default(),
            nonce.get(..12).unwrap_or_default(),
            &[],
            sealed,
        )
        .map(|_| ())
    }
}

/// Masking and padding both draw from one SHAKE128 stream seeded with the
/// direction's nonce: padding first, then the length mask.
struct Shake {
    reader: sha3::Shake128Reader,
    padding: bool,
    masking: bool,
}

impl Shake {
    fn new(nonce: &[u8; 16], option: u8, authenticated: bool) -> Option<Shake> {
        let padding = option & OPT_GLOBAL_PADDING != 0;
        let masking = option & OPT_CHUNK_MASKING != 0 && !authenticated;
        if !padding && !masking {
            return None;
        }
        let mut shake = Shake128::default();
        sha3::digest::Update::update(&mut shake, nonce);
        Some(Shake {
            reader: shake.finalize_xof(),
            padding,
            masking,
        })
    }

    fn next(&mut self) -> u16 {
        let mut word = [0u8; 2];
        self.reader.read(&mut word);
        u16::from_be_bytes(word)
    }

    fn padding(&mut self) -> usize {
        if self.padding {
            usize::from(self.next()) % MAX_PADDING
        } else {
            0
        }
    }

    fn mask(&mut self) -> u16 {
        if self.masking { self.next() } else { 0 }
    }
}

struct LengthAead {
    key: LessSafeKey,
    nonce: [u8; 12],
    count: u16,
}

impl LengthAead {
    fn new(security: Security, request: &Request) -> io::Result<Self> {
        let derived = kdf(&request.key, "auth_len", &[]);
        let key = aead(security, derived.get(..16).unwrap_or_default())?;
        Ok(LengthAead {
            key,
            nonce: base_nonce(&request.nonce),
            count: 0,
        })
    }

    fn next_nonce(&mut self) -> Nonce {
        let nonce = nonce12(&self.nonce, self.count);
        self.count = self.count.wrapping_add(1);
        nonce
    }
}

struct DataAead {
    key: LessSafeKey,
    nonce: [u8; 12],
    count: u16,
}

impl DataAead {
    fn new(security: Security, key: &[u8; 16], iv: &[u8; 16]) -> io::Result<Self> {
        Ok(DataAead {
            key: aead(security, key)?,
            nonce: base_nonce(iv),
            count: 0,
        })
    }

    fn next_nonce(&mut self) -> Nonce {
        let nonce = nonce12(&self.nonce, self.count);
        self.count = self.count.wrapping_add(1);
        nonce
    }
}

/// Whether the body is chunked at all: a `none` TCP stream is not.
pub(crate) fn chunked(option: u8) -> bool {
    option & OPT_CHUNK_STREAM != 0
}

pub(crate) struct BodyEncoder {
    security: Security,
    option: u8,
    data: Option<DataAead>,
    length: Option<LengthAead>,
    shake: Option<Shake>,
    cfb: Option<cfb_mode::BufEncryptor<Aes128>>,
}

impl BodyEncoder {
    pub(crate) fn new(request: &Request) -> io::Result<Self> {
        let security = request.security;
        let authenticated = request.option & OPT_AUTH_LENGTH != 0;
        Ok(BodyEncoder {
            security,
            option: request.option,
            data: security
                .is_aead()
                .then(|| DataAead::new(security, &request.key, &request.nonce))
                .transpose()?,
            length: (authenticated && chunked(request.option))
                .then(|| LengthAead::new(security, request))
                .transpose()?,
            shake: if chunked(request.option) {
                Shake::new(&request.nonce, request.option, authenticated)
            } else {
                None
            },
            cfb: (security == Security::Legacy)
                .then(|| {
                    cfb_mode::BufEncryptor::<Aes128>::new_from_slices(&request.key, &request.nonce)
                })
                .transpose()
                .map_err(|_| invalid_data("bad legacy key"))?,
        })
    }

    pub(crate) fn chunked(&self) -> bool {
        chunked(self.option)
    }

    pub(crate) fn owned_requirements(&self) -> Option<BufferRequirements> {
        self.data.as_ref()?;
        Some(BufferRequirements {
            mtu: CHUNK,
            front: 2 + if self.length.is_some() { OVERHEAD } else { 0 },
            rear: OVERHEAD
                + if self.option & OPT_GLOBAL_PADDING != 0 {
                    MAX_PADDING
                } else {
                    0
                },
        })
    }

    pub(crate) fn seal_owned(&mut self, buffer: &mut StreamBuffer) -> io::Result<()> {
        let (padding, mask) = match self.shake.as_mut() {
            Some(shake) => (shake.padding(), shake.mask()),
            None => (0, 0),
        };
        let data = self
            .data
            .as_mut()
            .ok_or_else(|| invalid_data("not an AEAD body"))?;
        let nonce = data.next_nonce();
        let tag = data
            .key
            .seal_in_place_separate_tag(nonce, Aad::empty(), buffer.as_mut_slice())
            .map_err(|_| invalid_data("seal failed"))?;
        buffer.append(OVERHEAD)?.copy_from_slice(tag.as_ref());
        rand::rng().fill(buffer.append(padding)?);
        let total = buffer.len();
        if let Some(length) = self.length.as_mut() {
            let value =
                u16::try_from(total - OVERHEAD).map_err(|_| invalid_data("chunk too long"))?;
            let nonce = length.next_nonce();
            let field = buffer.prepend(2 + OVERHEAD)?;
            let (plain, tag_room) = field.split_at_mut(2);
            plain.copy_from_slice(&value.to_be_bytes());
            let tag = length
                .key
                .seal_in_place_separate_tag(nonce, Aad::empty(), plain)
                .map_err(|_| invalid_data("seal failed"))?;
            tag_room.copy_from_slice(tag.as_ref());
        } else {
            let value = u16::try_from(total).map_err(|_| invalid_data("chunk too long"))? ^ mask;
            buffer.prepend(2)?.copy_from_slice(&value.to_be_bytes());
        }
        Ok(())
    }

    /// Appends the frame for one chunk to `out`.
    pub(crate) fn seal(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let start = out.len();
        let authenticated = self.length.is_some();
        let (padding, mask) = match self.shake.as_mut() {
            Some(shake) => (shake.padding(), shake.mask()),
            None => (0, 0),
        };
        let length_field = if authenticated { 2 + OVERHEAD } else { 2 };
        out.resize(start + length_field, 0);
        let body_start = out.len();
        if self.security == Security::Legacy {
            out.extend_from_slice(&fnv1a(payload).to_be_bytes());
        }
        let payload_start = out.len();
        out.extend_from_slice(payload);
        if let Some(data) = self.data.as_mut() {
            let nonce = data.next_nonce();
            let region = out
                .get_mut(payload_start..)
                .ok_or_else(|| invalid_data("buffer"))?;
            let tag = data
                .key
                .seal_in_place_separate_tag(nonce, Aad::empty(), region)
                .map_err(|_| invalid_data("seal failed"))?;
            out.extend_from_slice(tag.as_ref());
        }
        let sealed = out.len() - body_start;
        let pad_at = out.len();
        out.resize(pad_at + padding, 0);
        if let Some(pad) = out.get_mut(pad_at..) {
            rand::rng().fill(pad);
        }
        let total = sealed + padding;
        if let Some(length) = self.length.as_mut() {
            let value =
                u16::try_from(total - OVERHEAD).map_err(|_| invalid_data("chunk too long"))?;
            let nonce = length.next_nonce();
            let field = out
                .get_mut(start..body_start)
                .ok_or_else(|| invalid_data("buffer"))?;
            let (plain, tag_room) = field.split_at_mut(2);
            plain.copy_from_slice(&value.to_be_bytes());
            let tag = length
                .key
                .seal_in_place_separate_tag(nonce, Aad::empty(), plain)
                .map_err(|_| invalid_data("seal failed"))?;
            tag_room.copy_from_slice(tag.as_ref());
        } else {
            let value = u16::try_from(total).map_err(|_| invalid_data("chunk too long"))? ^ mask;
            let field = out
                .get_mut(start..body_start)
                .ok_or_else(|| invalid_data("buffer"))?;
            field.copy_from_slice(&value.to_be_bytes());
        }
        if let Some(cfb) = self.cfb.as_mut() {
            cfb.encrypt(out.get_mut(start..).ok_or_else(|| invalid_data("buffer"))?);
        }
        Ok(())
    }
}

pub(crate) struct Frame {
    pub(crate) sealed: usize,
    pub(crate) padding: usize,
}

pub(crate) enum Chunk {
    Data(Range<usize>),
    End,
}

pub(crate) struct BodyDecoder {
    security: Security,
    option: u8,
    data: Option<DataAead>,
    length: Option<LengthAead>,
    shake: Option<Shake>,
}

impl BodyDecoder {
    pub(crate) fn new(request: &Request, key: &[u8; 16], iv: &[u8; 16]) -> io::Result<Self> {
        let security = request.security;
        let authenticated = request.option & OPT_AUTH_LENGTH != 0;
        Ok(BodyDecoder {
            security,
            option: request.option,
            data: security
                .is_aead()
                .then(|| DataAead::new(security, key, iv))
                .transpose()?,
            length: (authenticated && chunked(request.option))
                .then(|| LengthAead::new(security, request))
                .transpose()?,
            shake: if chunked(request.option) {
                Shake::new(iv, request.option, authenticated)
            } else {
                None
            },
        })
    }

    pub(crate) fn chunked(&self) -> bool {
        chunked(self.option)
    }

    pub(crate) fn length_bytes(&self) -> usize {
        if self.length.is_some() {
            2 + OVERHEAD
        } else {
            2
        }
    }

    pub(crate) fn parse_length(&mut self, field: &mut [u8]) -> io::Result<Frame> {
        let (sealed_and_padding, padding) = if let Some(length) = self.length.as_mut() {
            let nonce = length.next_nonce();
            let plain = length
                .key
                .open_in_place(nonce, Aad::empty(), field)
                .map_err(|_| invalid_data("bad length chunk"))?;
            let value = plain
                .first_chunk::<2>()
                .copied()
                .ok_or_else(|| invalid_data("bad length chunk"))?;
            let padding = self.shake.as_mut().map_or(0, Shake::padding);
            (usize::from(u16::from_be_bytes(value)) + OVERHEAD, padding)
        } else {
            let value = field
                .first_chunk::<2>()
                .copied()
                .ok_or_else(|| invalid_data("bad length chunk"))?;
            let (padding, mask) = match self.shake.as_mut() {
                Some(shake) => (shake.padding(), shake.mask()),
                None => (0, 0),
            };
            (usize::from(u16::from_be_bytes(value) ^ mask), padding)
        };
        let sealed = sealed_and_padding
            .checked_sub(padding)
            .ok_or_else(|| invalid_data("bad length chunk"))?;
        Ok(Frame { sealed, padding })
    }

    /// Decrypts the sealed part of a frame in place.
    pub(crate) fn open(&mut self, sealed: &mut [u8]) -> io::Result<Chunk> {
        let len = sealed.len();
        if let Some(data) = self.data.as_mut() {
            let nonce = data.next_nonce();
            let plain = data
                .key
                .open_in_place(nonce, Aad::empty(), sealed)
                .map_err(|_| invalid_data("vmess chunk authentication failed"))?
                .len();
            return Ok(if plain == 0 {
                Chunk::End
            } else {
                Chunk::Data(0..plain)
            });
        }
        if self.security == Security::Legacy {
            let (check, rest) = sealed
                .split_first_chunk::<4>()
                .ok_or_else(|| invalid_data("bad chunk"))?;
            if fnv1a(rest) != u32::from_be_bytes(*check) {
                return Err(invalid_data("vmess: invalid chunk checksum"));
            }
            return Ok(if rest.is_empty() {
                Chunk::End
            } else {
                Chunk::Data(4..len)
            });
        }
        Ok(if len == 0 {
            Chunk::End
        } else {
            Chunk::Data(0..len)
        })
    }
}

pub(crate) fn legacy_response_decryptor(
    key: &[u8; 16],
    iv: &[u8; 16],
) -> io::Result<cfb_mode::BufDecryptor<Aes128>> {
    cfb_mode::BufDecryptor::<Aes128>::new_from_slices(key, iv)
        .map_err(|_| invalid_data("bad response key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_uuid_users_map_to_a_v5_uuid() {
        let id = user_id("not-a-uuid");
        assert_eq!(id.get(6).map(|b| b >> 4), Some(5));
        assert_eq!(id.get(8).map(|b| b >> 6), Some(2));
        assert_eq!(user_id("not-a-uuid"), id);
    }

    #[test]
    fn kdf_depends_on_every_path_element() {
        let a = kdf(b"key", "salt", &[b"one"]);
        assert_ne!(a, kdf(b"key", "salt", &[b"two"]));
        assert_ne!(a, kdf(b"key", "salt", &[]));
        assert_eq!(a, kdf(b"key", "salt", &[b"one"]));
    }

    #[test]
    fn sha256_parts_match_the_reference_across_block_boundaries() {
        for length in [0, 1, 55, 56, 63, 64, 65, 127, 128, 1024] {
            let input: Vec<_> = (0..length).map(|n| (n % 251) as u8).collect();
            let expected: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&input).into();
            for split in [0, length / 2, length] {
                assert_eq!(
                    sha256_parts(&[&input[..split], &[], &input[split..]]),
                    expected
                );
            }
        }
    }

    type Pair = (
        BodyEncoder,
        BodyDecoder,
        Option<cfb_mode::BufDecryptor<Aes128>>,
    );

    fn pair(security: Security, command: u8, padding: bool, authenticated: bool) -> Pair {
        let request = Request::new(security, command, padding, authenticated);
        let encoder = BodyEncoder::new(&request).unwrap();
        let cfb = (security == Security::Legacy)
            .then(|| legacy_response_decryptor(&request.key, &request.nonce).unwrap());
        let decoder = BodyDecoder::new(&request, &request.key, &request.nonce).unwrap();
        (encoder, decoder, cfb)
    }

    fn read_back(
        decoder: &mut BodyDecoder,
        cfb: &mut Option<cfb_mode::BufDecryptor<Aes128>>,
        wire: &mut [u8],
    ) -> Option<Vec<u8>> {
        if let Some(cfb) = cfb.as_mut() {
            cfb.decrypt(wire);
        }
        let head = decoder.length_bytes();
        let (field, rest) = wire.split_at_mut(head);
        let frame = decoder.parse_length(field).unwrap();
        let (sealed, _pad) = rest.split_at_mut(frame.sealed);
        match decoder.open(sealed).unwrap() {
            Chunk::Data(range) => Some(sealed[range].to_vec()),
            Chunk::End => None,
        }
    }

    #[test]
    fn every_security_round_trips_a_chunk() {
        for (security, command, padding, authenticated) in [
            (Security::Aes128Gcm, CMD_TCP, false, false),
            (Security::Aes128Gcm, CMD_TCP, true, false),
            (Security::Aes128Gcm, CMD_TCP, true, true),
            (Security::Chacha20Poly1305, CMD_TCP, false, true),
            (Security::Chacha20Poly1305, CMD_TCP, true, false),
            (Security::None, CMD_UDP, false, false),
            (Security::Legacy, CMD_TCP, false, false),
        ] {
            let (mut encoder, mut decoder, mut cfb) =
                pair(security, command, padding, authenticated);
            for text in [&b"first"[..], b"second chunk", b""] {
                let mut wire = Vec::new();
                encoder.seal(text, &mut wire).unwrap();
                let got = read_back(&mut decoder, &mut cfb, &mut wire);
                if text.is_empty() {
                    assert!(got.is_none(), "{security:?} end marker");
                } else {
                    assert_eq!(got.as_deref(), Some(text), "{security:?}");
                }
            }
        }
    }

    #[test]
    fn owned_aead_chunks_preserve_wire_nonces_padding_and_payload_storage() {
        use concord_common::stream_buffer::ReadBufferOptions;

        for security in [Security::Aes128Gcm, Security::Chacha20Poly1305] {
            for padding in [false, true] {
                for authenticated in [false, true] {
                    let request = Request::new(security, CMD_TCP, padding, authenticated);
                    let mut scalar = BodyEncoder::new(&request).unwrap();
                    let mut owned = BodyEncoder::new(&request).unwrap();
                    let mut decoder =
                        BodyDecoder::new(&request, &request.key, &request.nonce).unwrap();
                    let requirements = owned.owned_requirements().unwrap();
                    for length in [1, 127, 128, CHUNK - 1, CHUNK] {
                        let payload: Vec<_> = (0..length).map(|n| (n % 251) as u8).collect();
                        let options =
                            ReadBufferOptions::for_copy(Default::default(), requirements).unwrap();
                        let mut buffer = options.take();
                        buffer.spare_mut()[..length].copy_from_slice(&payload);
                        buffer.advance(length).unwrap();
                        let payload_pointer = buffer.as_slice().as_ptr();
                        let mut expected = Vec::new();
                        scalar.seal(&payload, &mut expected).unwrap();
                        owned.seal_owned(&mut buffer).unwrap();
                        assert_eq!(
                            buffer.as_slice().as_ptr().wrapping_add(requirements.front),
                            payload_pointer
                        );
                        assert_eq!(buffer.len(), expected.len());
                        let sealed_end = requirements.front + length + OVERHEAD;
                        assert_eq!(&buffer.as_slice()[..sealed_end], &expected[..sealed_end]);
                        let mut wire = buffer.as_slice().to_vec();
                        assert_eq!(
                            read_back(&mut decoder, &mut None, &mut wire).unwrap(),
                            payload
                        );
                    }
                    let mut end = Vec::new();
                    owned.seal(&[], &mut end).unwrap();
                    assert!(read_back(&mut decoder, &mut None, &mut end).is_none());
                }
            }
        }
    }
}
