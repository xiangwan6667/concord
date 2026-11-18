#![allow(
    clippy::indexing_slicing,
    reason = "profile indices and sizes are derived within fixed protocol bounds"
)]

use blake2::{Blake2b, Digest, digest::consts::U32};

type Blake2b256 = Blake2b<U32>;

const GAMMA: u64 = 0x9e3779b97f4a7c15;
const DOMAIN: u64 = 0xd6e8feb86659fd93;
const COEF_B: u64 = 0x589965cc75374cc3;
const ADD_B: u64 = 0x33a213ec50ffe2e9;
const COEF_A: u64 = 0xe7037ed1a0b428db;
const ADD_A: u64 = 0x8f3907f7b2b80c35;
const EXTRA: usize = 0x2da;
const SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];
const ROTATE: [u8; 128] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16,
    32, 64, 128, 3, 5, 9, 17, 33, 65, 129, 6, 10, 18, 34, 66, 130, 12, 24, 36, 7, 11, 19, 35, 67,
    131, 13, 25, 49, 97, 193, 14, 28, 56, 112, 224, 15, 23, 39, 71, 135, 27, 51, 99, 195, 29, 57,
    113, 225, 60, 120, 240, 248, 244, 236, 220, 188, 124, 242, 230, 206, 158, 62, 241, 227, 199,
    143, 31, 252, 250, 246, 238, 222, 190, 126, 249, 245, 237, 221, 189, 125, 243, 231, 219, 254,
    253, 251, 247, 239, 223, 191, 127, 254, 253, 251, 247, 239, 223, 191, 127,
];

mod label {
    pub(super) const PADDING: u32 = 0;
    pub(super) const BIT_PERCENT: u32 = 1;
    pub(super) const MOTIF: u32 = 2;
    pub(super) const MIX_OFFSET: u32 = 3;
    pub(super) const SALT: u32 = 3;
    pub(super) const PROFILE_ID: u32 = 5;
    pub(super) const GENERATOR: u32 = 6;
    pub(super) const PAD_MIN: u32 = 7;
    pub(super) const PAD_MAX: u32 = 8;
    pub(super) const PAD_COUNT: u32 = 9;
    pub(super) const PAD_INTERVAL: u32 = 10;
    pub(super) const SMALL_LIMIT: u32 = 11;
    pub(super) const BIT_MIN: u32 = 12;
    pub(super) const BIT_MAX: u32 = 13;
    pub(super) const PREFIX_MIN: u32 = 14;
    pub(super) const PREFIX_MAX: u32 = 15;
    pub(super) const MIX_MODE: u32 = 16;
    pub(super) const MIX_ROUNDS: u32 = 17;
    pub(super) const MIX_STRIDE: u32 = 18;
    pub(super) const MIX_OFFSET_BASE: u32 = 19;
    pub(super) const MIX_BLOCK: u32 = 20;
    pub(super) const CHUNK_POLICY: u32 = 21;
    pub(super) const CHUNK_INITIAL: u32 = 22;
    pub(super) const CHUNK_FIRST_CAP: u32 = 22;
    pub(super) const CHUNK_MAX: u32 = 23;
    pub(super) const CHUNK_STEP: u32 = 24;
    pub(super) const CHUNK_JITTER: u32 = 25;
    pub(super) const CHUNK_BUCKET: u32 = 26;
    pub(super) const IDLE_RESET: u32 = 27;
    pub(super) const WRITE_POLICY: u32 = 28;
    pub(super) const WRITE_FIRST: u32 = 29;
    pub(super) const WRITE_BUCKET: u32 = 30;
    pub(super) const WRITE_SEQ: u32 = 31;
    pub(super) const WRITE_JITTER: u32 = 32;
    pub(super) const RECORD_PREFIX: u32 = 33;
    pub(super) const PAYLOAD_PAD: u32 = 34;
    pub(super) const WRITE_TARGET: u32 = 35;
    pub(super) const WRITE_JITTER_V: u32 = 36;
    pub(super) const WRITE_NEXT: u32 = 37;
    pub(super) const CHUNK_SIZE: u32 = 38;
    pub(super) const CHUNK_JITTER_V: u32 = 39;
}

const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;
const WRITE_POLICY_DOMAIN: u32 = 0x504c;

fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

fn fold(ns: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = ns
        ^ b.wrapping_mul(COEF_B).wrapping_add(ADD_B)
        ^ u64::from(label).wrapping_mul(GAMMA)
        ^ a.wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let y = mix(x);
    (y ^ (y >> 32)) as u32
}

fn pick(raw: u32, lo: usize, hi: usize) -> usize {
    lo + raw as usize % (hi - lo + 1)
}

#[derive(Clone)]
struct Namespaces([u64; 7]);

impl Namespaces {
    fn new(psk: &[u8]) -> Self {
        let secret = Blake2b256::new()
            .chain_update(SEED)
            .chain_update(psk)
            .finalize();
        let mut words = [0u64; 4];
        for (word, bytes) in words.iter_mut().zip(secret.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*bytes);
        }
        let seeds = [
            (label::PROFILE_ID, 0xb46c2e7d9a1538f1u64),
            (label::PADDING, 0x5d9217c083e64ab9),
            (label::MOTIF, 0xa71f0c54d8396e2b),
            (label::SALT, 0x3e8a91b52740f6cd),
            (label::MIX_MODE, 0xc9f4260b7d1e835a),
            (label::CHUNK_POLICY, 0x62d0b5e19c4a783f),
            (label::WRITE_POLICY, 0x917b3c48e6a205d4),
        ];
        Self(seeds.map(|(label, seed)| {
            mix((label as u64).wrapping_mul(DOMAIN)
                ^ seed.wrapping_add(0xa0761d6478bd642f)
                ^ words[0]
                ^ words[1].wrapping_add(GAMMA)
                ^ words[2].rotate_left(17)
                ^ words[3].rotate_right(11))
        }))
    }

    fn for_label(&self, label: u32) -> u64 {
        self.0[match label {
            label::PADDING
            | label::BIT_PERCENT
            | label::PREFIX_MIN
            | label::PREFIX_MAX
            | label::RECORD_PREFIX
            | label::PAYLOAD_PAD => 1,
            label::MOTIF => 2,
            label::MIX_OFFSET
            | label::MIX_MODE
            | label::MIX_ROUNDS
            | label::MIX_STRIDE
            | label::MIX_OFFSET_BASE
            | label::MIX_BLOCK => 4,
            label::CHUNK_POLICY
            | label::CHUNK_INITIAL
            | label::CHUNK_MAX
            | label::CHUNK_STEP
            | label::CHUNK_JITTER
            | label::CHUNK_BUCKET
            | label::CHUNK_SIZE
            | label::CHUNK_JITTER_V => 5,
            label::WRITE_POLICY
            | label::WRITE_FIRST
            | label::WRITE_BUCKET
            | label::WRITE_SEQ
            | label::WRITE_JITTER
            | label::WRITE_TARGET
            | label::WRITE_JITTER_V
            | label::WRITE_NEXT => 6,
            _ => 0,
        }]
    }

    fn prf(&self, label: u32, a: u32, b: u32) -> u32 {
        fold(self.for_label(label), label, u64::from(a), u64::from(b))
    }

    fn fixed(&self, label: u32, domain: u32) -> u32 {
        self.prf(label, 0, domain)
    }

    fn bytes(&self, label: u32, seq: u32, out: &mut [u8]) {
        let seed = self.for_label(label)
            ^ u64::from(seq)
                .wrapping_mul(DOMAIN)
                .wrapping_add(0xb57de1f3f82cb33f)
            ^ u64::from(label).wrapping_mul(0xa24baed4963ee407)
            ^ (out.len() as u64)
                .wrapping_mul(0x165667b19e3779f9)
                .wrapping_add(0x0d4cd3e7b14a36d7);
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            let block = mix(seed.wrapping_add((i as u64 + 1).wrapping_mul(GAMMA))).to_le_bytes();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

#[derive(Clone)]
pub(super) struct Profile {
    ns: Namespaces,
    generator: usize,
    pad_min: usize,
    pad_max: usize,
    pad_count: u32,
    pad_interval: u32,
    small_limit: usize,
    bit_min: usize,
    bit_max: usize,
    prefix_min: usize,
    prefix_max: usize,
    mix_mode: usize,
    mix_rounds: u32,
    mix_stride: usize,
    mix_offset: usize,
    mix_block: usize,
    chunk_policy: usize,
    pub(super) chunk_initial: usize,
    pub(super) first_cap: usize,
    chunk_max: usize,
    chunk_step: usize,
    chunk_jitter: usize,
    pub(super) idle_reset: u64,
    write_policy: usize,
    write_first: u32,
    chunk_buckets: [usize; 8],
    write_buckets: [usize; 8],
    write_seq: [usize; 8],
    write_jitter: usize,
    write_pct: usize,
    g: [usize; 6],
    pub(super) salt_len: usize,
    salt_stride: u8,
    salt_rounds: u32,
}

impl Profile {
    pub(super) fn new(psk: &[u8]) -> Self {
        let ns = Namespaces::new(psk);
        let value = |label, domain, lo, hi| pick(ns.fixed(label, domain), lo, hi);
        let pad_min = value(label::PAD_MIN, 0, 0x18, 0xa0);
        let pad_max = (pad_min + value(label::PAD_MAX, 0, 0xa0, 0x3c0)).min(EXTRA);
        let hs_min = value(label::PREFIX_MIN, HANDSHAKE_DOMAIN, 0x10, 0x60);
        let hs_max = (hs_min + value(label::PREFIX_MAX, HANDSHAKE_DOMAIN, 0x10, 0xa0)).min(0x80);
        let salt_len = 16
            + value(
                label::RECORD_PREFIX,
                HANDSHAKE_DOMAIN,
                hs_min.min(hs_max),
                hs_max,
            );
        let prefix_min = value(label::PREFIX_MIN, 0, 8, 0x50);
        let prefix_max = (prefix_min + value(label::PREFIX_MAX, 0, 0x10, 0xa0)).min(0x80);
        let chunk_initial = value(label::CHUNK_INITIAL, 0, 0x200, 0x5b4).clamp(0x60, 0x5b4);
        let first_cap = value(label::CHUNK_FIRST_CAP, CHUNK_INITIAL_DOMAIN, 0x100, 0x300)
            .min(chunk_initial.min(0x300))
            .max(0x100);
        let chunk_max = value(label::CHUNK_MAX, 0, 0x2000, 0x3fff).max(chunk_initial);
        Self {
            generator: ns.fixed(label::GENERATOR, 0) as usize & 3,
            pad_min,
            pad_max,
            pad_count: value(label::PAD_COUNT, 0, 2, 8) as u32,
            pad_interval: value(label::PAD_INTERVAL, 0, 2, 11) as u32,
            small_limit: value(label::SMALL_LIMIT, 0, 0x60, 0x300),
            bit_min: value(label::BIT_MIN, 0, 0x18, 0x29),
            bit_max: value(label::BIT_MAX, 0, 0x3a, 0x4c),
            prefix_min: prefix_min.min(prefix_max),
            prefix_max,
            mix_mode: ns.fixed(label::MIX_MODE, 0) as usize % 3,
            mix_rounds: value(label::MIX_ROUNDS, 0, 1, 3) as u32,
            mix_stride: value(label::MIX_STRIDE, 0, 2, 13),
            mix_offset: value(label::MIX_OFFSET_BASE, 0, 0, 15),
            mix_block: value(label::MIX_BLOCK, 0, 8, 0x40),
            chunk_policy: ns.fixed(label::CHUNK_POLICY, 0) as usize % 3,
            chunk_initial,
            first_cap,
            chunk_max,
            chunk_step: value(label::CHUNK_STEP, 0, 0x400, 0x1000).min(0xb68),
            chunk_jitter: value(label::CHUNK_JITTER, 0, 0x10, 0xc0).min(0xb6),
            idle_reset: value(label::IDLE_RESET, 0, 0xc, 0x5a) as u64,
            write_policy: ns.fixed(label::WRITE_POLICY, 0) as usize % 3,
            write_first: value(label::WRITE_FIRST, 0, 4, 8) as u32,
            write_jitter: value(label::WRITE_JITTER, 0, 8, 0x60),
            write_pct: value(label::WRITE_POLICY, WRITE_POLICY_DOMAIN, 8, 0x30),
            g: [
                value(label::GENERATOR, 1, 0x18, 0x80),
                value(label::GENERATOR, 2, 0x10, 0x60),
                value(label::GENERATOR, 3, 0x10, 0x60),
                value(label::GENERATOR, 4, 0, 9),
                value(label::GENERATOR, 5, 1, 8),
                value(label::GENERATOR, 6, 7, 0x17),
            ],
            salt_len,
            salt_stride: value(label::MIX_STRIDE, MIX_HANDSHAKE_DOMAIN, 0x11, 0xfb) as u8,
            salt_rounds: value(label::MIX_ROUNDS, MIX_HANDSHAKE_DOMAIN, 1, 4) as u32,
            chunk_buckets: std::array::from_fn(|i| {
                value(label::CHUNK_BUCKET, i as u32, 0x1000, chunk_max)
            }),
            write_buckets: std::array::from_fn(|i| {
                value(label::WRITE_BUCKET, i as u32, 0x140, 0x5b4)
            }),
            write_seq: std::array::from_fn(|i| value(label::WRITE_SEQ, i as u32, 0x168, 0x5b4)),
            ns,
        }
    }

    pub(super) fn prefix_len(&self, seq: u32) -> usize {
        pick(
            self.ns.prf(label::RECORD_PREFIX, seq, 0),
            self.prefix_min,
            self.prefix_max,
        )
    }

    pub(super) fn payload_limit(&self, seq: u32, mut size: usize) -> usize {
        if size == 0 {
            size = self.chunk_initial;
        }
        size = match self.chunk_policy {
            1 => self.chunk_buckets[self.ns.prf(label::CHUNK_SIZE, seq, size as u32) as usize % 8],
            2 => {
                (size
                    + self.ns.prf(label::CHUNK_JITTER_V, seq, size as u32) as usize
                        % (self.chunk_jitter * 2 + 1))
                    - self.chunk_jitter
            }
            _ => size,
        };
        size.clamp(0x40, self.chunk_max)
    }

    pub(super) fn next_chunk(&self, size: usize) -> usize {
        if size == 0 {
            self.chunk_initial
        } else {
            (size + self.chunk_step).min(self.chunk_max)
        }
    }

    pub(super) fn padding_len(
        &self,
        seq: u32,
        payload: usize,
        prefix: usize,
        salt: usize,
    ) -> usize {
        let mut pad = if seq < self.pad_count
            || (payload > 0 && payload <= self.small_limit)
            || seq.is_multiple_of(self.pad_interval)
        {
            pick(
                self.ns.prf(label::PAYLOAD_PAD, seq, payload as u32),
                self.pad_min,
                self.pad_max,
            )
        } else {
            0
        };
        let frame = salt + prefix + 23 + pad + payload + if payload > 0 { 16 } else { 0 };
        pad += self
            .write_target(seq, frame)
            .saturating_sub(frame)
            .min(EXTRA);
        if salt > 0 {
            let threshold = ((payload + if payload == 0 { 0x27 } else { 0x37 }) * 25)
                .div_ceil(75)
                .max(0xc0);
            if salt - 16 + prefix + pad < threshold {
                let target = threshold
                    .saturating_sub(salt - 16 + prefix)
                    .min(self.pad_max + EXTRA);
                if target <= 0xfffe {
                    pad = target;
                }
            }
        }
        pad.min(0xffff)
    }

    fn write_target(&self, seq: u32, frame: usize) -> usize {
        if frame > 0x5b3 {
            return frame.min(0xffff);
        }
        let mut target = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            self.write_buckets[self.ns.prf(label::WRITE_TARGET, seq, frame as u32) as usize % 8]
        };
        if self.write_policy == 2 {
            let jitter =
                self.ns.prf(label::WRITE_JITTER_V, seq, 0) as usize % (self.write_jitter * 2 + 1);
            target = (target + jitter).saturating_sub(self.write_jitter).max(1);
        }
        let spread = (frame * self.write_pct / 100).min(EXTRA);
        if self.ns.prf(label::WRITE_TARGET, seq, spread as u32) & 1 == 0 {
            target = (target + spread).min(0xffff);
        } else if target > spread / 2 {
            target -= spread / 2;
        }
        while frame > target {
            let next =
                self.write_buckets[self.ns.prf(label::WRITE_NEXT, seq, target as u32) as usize % 8];
            target = if next > target {
                next
            } else {
                (target + self.pad_max).min(0xffff)
            };
        }
        target
    }

    pub(super) fn fill(&self, seq: u32, out: &mut [u8]) {
        self.ns.bytes(label::PADDING, seq, out);
        let mut motif = [0u8; 32];
        if self.generator == 3 {
            self.ns.bytes(label::MOTIF, seq, &mut motif);
        }
        let bits = pick(
            self.ns.prf(label::BIT_PERCENT, seq, 0),
            self.bit_min,
            self.bit_max,
        ) * 8;
        let rotate = if bits <= 0x31 {
            1
        } else if bits <= 0x2ed {
            (bits + 0x32) / 100
        } else {
            7
        };
        for (i, slot) in out.iter_mut().enumerate() {
            let v = *slot;
            *slot = match self.generator {
                0 => {
                    let raw = v.wrapping_add(i as u8);
                    ROTATE[rotate.max(1) * 16 + usize::from((raw ^ v) & 15)]
                        .rotate_left(u32::from((raw ^ (v >> 4)) & 7))
                }
                1 => {
                    let bucket = usize::from(v) % (self.g[0] + self.g[1] + self.g[2]);
                    if bucket < self.g[0] {
                        pick(u32::from(v.wrapping_add(i as u8)), 0x20, 0x7e) as u8
                    } else if bucket < self.g[0] + self.g[1] {
                        pick(u32::from(v ^ i as u8), 0x80, 0xbf) as u8
                    } else {
                        pick(
                            u32::from(v.wrapping_add((i as u8).wrapping_mul(7))),
                            0xc0,
                            0xff,
                        ) as u8
                    }
                }
                2 => {
                    let low = (usize::from(v & 15) + self.g[3] + (i & 1)) % 10;
                    let high = (usize::from(v) + ((i & 3) << 4) + 0x30) & 0xf0;
                    (high | low) as u8
                }
                _ => {
                    let offset = i % self.g[5].max(5);
                    if offset < self.g[5].max(5) - 3 {
                        ((self.g[4] + 3) * i) as u8 ^ motif[(i % (self.g[4] * 4)) % 32]
                    } else if offset < self.g[5].max(5) - 1 {
                        0x30 | (v % 10)
                    } else {
                        v
                    }
                }
            };
        }
    }

    fn salt_perm(&self) -> Vec<usize> {
        let mut perm: Vec<usize> = (0..self.salt_len).collect();
        for round in 0..self.salt_rounds {
            for i in 0..self.salt_len {
                let x = (i as u64).wrapping_mul(COEF_B).wrapping_add(ADD_B)
                    ^ (self.ns.0[3] ^ 0xdaa66d2c7ddf743f)
                    ^ u64::from(MIX_HANDSHAKE_DOMAIN + round)
                        .wrapping_mul(COEF_A)
                        .wrapping_add(ADD_A);
                let y = mix(x);
                let raw = (y ^ (y >> 32)) as u32;
                let j = i + raw as usize % (self.salt_len - i);
                perm.swap(i, j);
            }
        }
        perm
    }

    fn salt_mask(&self, i: usize) -> u8 {
        (i as u8).wrapping_mul(self.salt_stride)
            ^ fold(
                self.ns.0[3],
                label::MOTIF,
                MIX_HANDSHAKE_DOMAIN.into(),
                i as u64,
            ) as u8
    }

    pub(super) fn put_salt(&self, salt: &[u8; 16], block: &mut [u8]) {
        for (i, pos) in self.salt_perm().into_iter().take(16).enumerate() {
            block[pos] = self.salt_mask(i) ^ salt[i];
        }
    }

    pub(super) fn salt(&self, block: &[u8]) -> [u8; 16] {
        let mut salt = [0u8; 16];
        for (i, pos) in self.salt_perm().into_iter().take(16).enumerate() {
            salt[i] = self.salt_mask(i) ^ block[pos];
        }
        salt
    }

    pub(super) fn interleave(&self, seq: u32, pad: &mut [u8], sealed: &mut [u8]) {
        let n = pad.len().min(sealed.len());
        for round in 0..self.mix_rounds {
            if self.mix_mode == 1 {
                let block = self.mix_block;
                for off in ((round as usize & 1) * block..n).step_by(block * 2) {
                    if off + block <= n {
                        for i in off..off + block {
                            std::mem::swap(&mut pad[i], &mut sealed[i]);
                        }
                    }
                }
            } else {
                let stride = self.mix_stride + round as usize % 3;
                let offset = if self.mix_mode == 0 {
                    self.mix_offset % stride
                } else {
                    ((u64::from(self.ns.prf(label::MIX_OFFSET, seq, round))
                        + self.mix_offset as u64)
                        % stride as u64) as usize
                };
                for i in (offset..n).step_by(stride) {
                    std::mem::swap(&mut pad[i], &mut sealed[i]);
                }
            }
        }
    }
}
