use std::io;

use aes::cipher::{BlockEncrypt, KeyInit};
use aws_lc_rs::aead::{AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, Tag, UnboundKey};

use super::{invalid, kdf};

pub(super) struct Aead {
    key: LessSafeKey,
    nonce: [u8; 12],
    aes: bool,
}

impl Aead {
    pub(super) fn new(context: &[u8], material: &[u8], aes: bool) -> io::Result<Self> {
        let algorithm = if aes {
            &AES_256_GCM
        } else {
            &CHACHA20_POLY1305
        };
        let key = UnboundKey::new(algorithm, &kdf::derive(context, material)).map_err(invalid)?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce: [0; 12],
            aes,
        })
    }

    fn next(&mut self) -> [u8; 12] {
        increment(&mut self.nonce);
        self.nonce
    }

    pub(super) fn seal(&mut self, data: &mut Vec<u8>, aad: &[u8]) -> io::Result<()> {
        let tag = self.seal_slice(data, aad)?;
        data.extend_from_slice(tag.as_ref());
        Ok(())
    }

    pub(super) fn seal_slice(&mut self, data: &mut [u8], aad: &[u8]) -> io::Result<Tag> {
        let nonce = self.next();
        self.key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), data)
            .map_err(invalid)
    }

    pub(super) fn open(&mut self, data: &mut Vec<u8>, aad: &[u8]) -> io::Result<()> {
        let len = self.open_slice(data, aad)?;
        data.truncate(len);
        Ok(())
    }

    pub(super) fn open_slice(&mut self, data: &mut [u8], aad: &[u8]) -> io::Result<usize> {
        let nonce = self.next();
        self.key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), data)
            .map(|plain| plain.len())
            .map_err(invalid)
    }

    pub(super) fn open_nonce(
        &self,
        data: &mut Vec<u8>,
        aad: &[u8],
        nonce: [u8; 12],
    ) -> io::Result<()> {
        let len = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), data)
            .map_err(invalid)?
            .len();
        data.truncate(len);
        Ok(())
    }

    pub(super) fn needs_rekey(&self) -> bool {
        self.nonce == [255; 12]
    }

    pub(super) fn nonce_wrapped(&self) -> bool {
        self.nonce == [0; 12]
    }
    pub(super) fn uses_aes(&self) -> bool {
        self.aes
    }
}

fn increment(bytes: &mut [u8]) {
    for byte in bytes.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

pub(super) struct Ctr {
    key: aes::Aes256,
    counter: [u8; 16],
    block: [u8; 16],
    used: usize,
}

impl Ctr {
    pub(super) fn new(material: &[u8], iv: [u8; 16]) -> Self {
        let key = aes::Aes256::new(&kdf::derive(b"VLESS", material).into());
        Self {
            key,
            counter: iv,
            block: [0; 16],
            used: 16,
        }
    }

    pub(super) fn apply(&mut self, mut data: &mut [u8]) {
        while !data.is_empty() {
            if self.used == 16 {
                let mut block = self.counter.into();
                self.key.encrypt_block(&mut block);
                self.block.copy_from_slice(&block);
                increment(&mut self.counter);
                self.used = 0;
            }
            let key = self.block.split_at(self.used).1;
            let take = data.len().min(key.len());
            let (part, rest) = data.split_at_mut(take);
            for (byte, key) in part.iter_mut().zip(key) {
                *byte ^= key;
            }
            self.used += take;
            data = rest;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctr_matches_aws_lc_across_full_counter_carry() {
        use aws_lc_rs::cipher::{
            AES_256, EncryptionContext, StreamingEncryptingKey, UnboundCipherKey,
        };
        let material = b"CTR differential material";
        let iv = [255; 16];
        let input = vec![17; 1088];
        let mut reference = StreamingEncryptingKey::less_safe_ctr(
            UnboundCipherKey::new(&AES_256, &kdf::derive(b"VLESS", material)).unwrap(),
            EncryptionContext::Iv128(iv.as_slice().try_into().unwrap()),
        )
        .unwrap();
        let mut output = vec![0; input.len() + 16];
        let update = reference.update(&input, &mut output).unwrap();
        let expected = update.written().to_vec();
        let mut actual = input;
        let mut ctr = Ctr::new(material, iv);
        for bytes in actual.chunks_mut(5) {
            ctr.apply(bytes);
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn aead_nonce_wrap_uses_zero_once_before_record_rekey() {
        for aes in [false, true] {
            let mut send = Aead::new(b"ctx", b"key", aes).unwrap();
            let mut recv = Aead::new(b"ctx", b"key", aes).unwrap();
            send.nonce = [255; 12];
            recv.nonce = [255; 12];
            assert!(recv.needs_rekey());
            let mut data = b"payload".to_vec();
            send.seal(&mut data, b"head").unwrap();
            assert!(send.nonce_wrapped());
            let mut record = b"head".to_vec();
            record.extend_from_slice(&data);
            let mut next_send = Aead::new(&record, b"key", aes).unwrap();
            let mut next_recv = Aead::new(&record, b"key", aes).unwrap();
            recv.open(&mut data, b"head").unwrap();
            assert_eq!(data, b"payload");
            next_send.seal(&mut data, b"head").unwrap();
            next_recv.open(&mut data, b"head").unwrap();
            assert_eq!(data, b"payload");
        }
    }
}
