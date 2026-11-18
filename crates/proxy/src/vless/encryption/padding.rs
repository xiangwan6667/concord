use std::io;
use std::time::Duration;

use rand::Rng;

use super::invalid;

pub(super) struct Padding(Vec<[i64; 3]>);

impl Padding {
    pub(super) fn parse(items: &[&str]) -> io::Result<Self> {
        if items.is_empty() || items == [""] {
            return Ok(Self(vec![[100, 111, 1111], [75, 0, 111], [50, 0, 3333]]));
        }
        let mut parsed = Vec::new();
        let mut maximum = 0i64;
        for (index, item) in items.iter().enumerate() {
            let mut fields = item.split('-');
            let mut triple = [0; 3];
            for number in &mut triple {
                *number = fields
                    .next()
                    .ok_or_else(|| invalid("invalid padding length/gap"))?
                    .parse::<i64>()
                    .map_err(invalid)?;
            }
            if index == 0 && (triple[0] < 100 || triple[1] < 35 || triple[2] < 35) {
                return Err(invalid("first padding length must not be smaller than 35"));
            }
            if index % 2 == 0 {
                maximum = maximum
                    .checked_add(triple[1].max(triple[2]))
                    .ok_or_else(|| invalid("padding length overflow"))?;
            }
            parsed.push(triple);
        }
        if maximum > 65553 {
            return Err(invalid(
                "total padding length must not be larger than 65553",
            ));
        }
        Ok(Self(parsed))
    }

    pub(super) fn sample(&self) -> (Vec<usize>, Vec<Duration>) {
        let mut rng = rand::rng();
        let mut lengths = Vec::new();
        let mut gaps = Vec::new();
        for (index, &[probability, from, to]) in self.0.iter().enumerate() {
            let value = if probability >= rng.random_range(0..100) {
                if from == to {
                    from
                } else {
                    rng.random_range(from.min(to)..from.max(to))
                }
            } else {
                0
            };
            if index % 2 == 0 {
                lengths.push(usize::try_from(value).unwrap_or(0));
            } else {
                let nanos = value.wrapping_mul(1_000_000);
                gaps.push(Duration::from_nanos(u64::try_from(nanos).unwrap_or(0)));
            }
        }
        (lengths, gaps)
    }
}
