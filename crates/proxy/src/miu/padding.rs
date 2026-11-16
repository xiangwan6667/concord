use std::io;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::anytls::padding::Padding;

struct Reader {
    key: Vec<u8>,
    block: Vec<u8>,
    position: usize,
    counter: u32,
}

fn authenticate(key: &[u8], parts: &[&[u8]]) -> io::Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(io::Error::other)?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().to_vec())
}

fn expand(key: &[u8], info: &[u8]) -> io::Result<Vec<u8>> {
    let mut block = Vec::with_capacity(128);
    let mut previous = Vec::new();
    for counter in 1..=4u8 {
        previous = authenticate(key, &[&previous, info, &[counter]])?;
        block.extend_from_slice(&previous);
    }
    Ok(block)
}

impl Reader {
    fn new(token: &[u8; 32]) -> io::Result<Self> {
        let key = authenticate(b"miu/v2/padding-profile/salt", &[token])?;
        let block = expand(&key, b"miu/v2/padding-profile/v1/psk-only")?;
        Ok(Self {
            key,
            block,
            position: 0,
            counter: 0,
        })
    }

    fn sample(&mut self, low: usize, high: usize) -> io::Result<usize> {
        let span = high
            .checked_sub(low)
            .filter(|span| *span > 0)
            .ok_or_else(|| io::Error::other("invalid miu padding range"))?;
        let limit = 65536 - 65536 % span;
        loop {
            if self.position + 2 > self.block.len() {
                self.counter += 1;
                self.block = expand(
                    &self.key,
                    format!(
                        "miu/v2/padding-profile/v1/psk-only/counter/{}",
                        self.counter
                    )
                    .as_bytes(),
                )?;
                self.position = 0;
            }
            let bytes = self
                .block
                .get(self.position..self.position + 2)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .ok_or_else(|| io::Error::other("incomplete miu padding profile"))?;
            self.position += 2;
            let value = usize::from(u16::from_be_bytes(bytes));
            if value < limit {
                return Ok(low + value % span);
            }
        }
    }

    fn range(&mut self, cap: usize, width: usize) -> io::Result<(usize, usize)> {
        let low = self.sample(128, cap - (2 * width - 1))?;
        Ok((low, self.sample(low + width, cap + 1)?))
    }
}

pub(super) fn derive(token: &[u8; 32]) -> io::Result<Padding> {
    let mut reader = Reader::new(token)?;
    let count = reader.sample(4, 10)?;
    let low = reader.sample(24, 41)?;
    let high = reader.sample(low + 16, 65)?;
    let cap = (1984 - high) / count;
    let mut lines = vec![format!("stop={}", count + 1), format!("0={low}-{high}")];
    for packet in 1..=count {
        if cap >= 384 && reader.sample(0, 2)? == 1 {
            let (a, b) = reader.range(cap / 2, 8)?;
            let (c, d) = reader.range(cap / 2, 8)?;
            lines.push(format!("{packet}={a}-{b},c,{c}-{d}"));
        } else {
            let (a, b) = reader.range(cap, 16)?;
            lines.push(format!("{packet}={a}-{b}"));
        }
    }
    Padding::parse(lines.join("\n").as_bytes())
        .ok_or_else(|| io::Error::other("invalid miu padding profile"))
}
