use std::io;

use chacha20::cipher::consts::U10;
use chacha20::cipher::{Block, KeyIvInit, StreamCipher, StreamCipherCore, StreamCipherSeekCore};
use chacha20::{ChaCha20, hchacha};

pub(super) struct ChaCha64 {
    key: chacha20::Key,
    nonce: [u8; 12],
    cipher: ChaCha20,
    position: u64,
    last: Block<chacha20::ChaChaCore<U10>>,
}

impl ChaCha64 {
    pub(super) fn new(key: &[u8], iv: &[u8]) -> io::Result<Self> {
        let mut key = chacha20::Key::clone_from_slice(
            <&[u8; 32]>::try_from(key).map_err(|_| io::ErrorKind::InvalidInput)?,
        );
        let mut nonce = [0u8; 12];
        let (_, tail) = nonce.split_at_mut(4);
        match iv.len() {
            8 => tail.copy_from_slice(iv),
            24 => {
                let (head, rest) = iv.split_at(16);
                key = hchacha::<U10>(&key, head.into());
                tail.copy_from_slice(rest);
            }
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        }
        Ok(Self {
            cipher: ChaCha20::new(&key, &nonce.into()),
            key,
            nonce,
            position: 0,
            last: Block::<chacha20::ChaChaCore<U10>>::default(),
        })
    }

    // RustCrypto reserves the last 32-bit counter block; Go's djb/XChaCha streams carry
    // into word 13. Use that block directly, then put the high counter in the IETF nonce.
    pub(super) fn apply(&mut self, mut data: &mut [u8]) -> io::Result<()> {
        let final_block_offset = u64::from(u32::MAX) * 64;
        while !data.is_empty() {
            if self.position < final_block_offset {
                let available =
                    usize::try_from(final_block_offset - self.position).unwrap_or(usize::MAX);
                let count = data.len().min(available);
                let (head, rest) = data.split_at_mut(count);
                self.cipher
                    .try_apply_keystream(head)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                self.position += count as u64;
                data = rest;
            } else {
                let offset = (self.position - final_block_offset) as usize;
                if offset == 0 {
                    let mut core = chacha20::ChaChaCore::<U10>::new(&self.key, &self.nonce.into());
                    core.set_block_pos(u32::MAX);
                    core.write_keystream_block(&mut self.last);
                }
                let count = data.len().min(64 - offset);
                let (head, rest) = data.split_at_mut(count);
                for (byte, key) in head
                    .iter_mut()
                    .zip(self.last.iter().skip(offset).take(count))
                {
                    *byte ^= key;
                }
                self.position += count as u64;
                data = rest;
                if self.position == final_block_offset + 64 {
                    let (high_bytes, _) = self.nonce.split_at_mut(4);
                    let high = u32::from_le_bytes(
                        (&*high_bytes)
                            .try_into()
                            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
                    )
                    .wrapping_add(1);
                    high_bytes.copy_from_slice(&high.to_le_bytes());
                    self.cipher = ChaCha20::new(&self.key, &self.nonce.into());
                    self.position = 0;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
