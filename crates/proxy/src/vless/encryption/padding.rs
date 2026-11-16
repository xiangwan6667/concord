use std::io;
use std::time::Duration;

use rand::Rng;

#[derive(Clone)]
struct Choice {
    chance: u32,
    from: u32,
    to: u32,
}

impl Choice {
    fn pick(&self) -> u32 {
        let mut rng = rand::rng();
        if self.chance < rng.random_range(0..100) {
            return 0;
        }
        if self.from == self.to {
            self.from
        } else {
            rng.random_range(self.from.min(self.to)..self.from.max(self.to))
        }
    }
}

pub(super) struct Padding {
    lengths: Vec<Choice>,
    gaps: Vec<Choice>,
}

impl Padding {
    pub(super) fn parse(text: &str) -> io::Result<Self> {
        let text = if text.is_empty() {
            "100-111-1111.75-0-111.50-0-3333"
        } else {
            text
        };
        let mut padding = Self {
            lengths: Vec::new(),
            gaps: Vec::new(),
        };
        for (index, part) in text.split('.').enumerate() {
            let numbers = part
                .split('-')
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| io::Error::other("invalid VLESS Encryption padding"))?;
            let &[chance, from, to, ..] = numbers.as_slice() else {
                return Err(io::Error::other("invalid VLESS Encryption padding"));
            };
            if index == 0 && (chance < 100 || from < 35 || to < 35) {
                return Err(io::Error::other(
                    "invalid VLESS Encryption first padding length",
                ));
            }
            let choice = Choice { chance, from, to };
            if index % 2 == 0 {
                padding.lengths.push(choice);
            } else {
                padding.gaps.push(choice);
            }
        }
        let total = padding
            .lengths
            .iter()
            .try_fold(0_u32, |total, choice| {
                total.checked_add(choice.from.max(choice.to))
            })
            .ok_or_else(|| io::Error::other("VLESS Encryption padding is too large"))?;
        if total > 65553 {
            return Err(io::Error::other("VLESS Encryption padding is too large"));
        }
        Ok(padding)
    }

    pub(super) fn create(&self) -> (usize, Vec<usize>, Vec<Duration>) {
        let lengths: Vec<_> = self
            .lengths
            .iter()
            .map(|choice| choice.pick() as usize)
            .collect();
        let gaps = self
            .gaps
            .iter()
            .map(|choice| Duration::from_millis(u64::from(choice.pick())))
            .collect();
        (lengths.iter().sum(), lengths, gaps)
    }
}
