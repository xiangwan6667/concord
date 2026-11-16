use std::collections::HashMap;

use md5::{Digest, Md5};
use rand::Rng;

pub(super) const DEFAULT_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Size {
    Bytes(usize),
    /// Stops the record plan once the payload is spent.
    Check,
}

pub(crate) struct Padding {
    pub(crate) md5: String,
    pub(crate) stop: u32,
    rules: HashMap<String, String>,
}

pub(super) fn parse_map(text: &str) -> HashMap<String, String> {
    text.split('\n')
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

impl Padding {
    pub(crate) fn parse(raw: &[u8]) -> Option<Padding> {
        let rules = parse_map(&String::from_utf8_lossy(raw));
        if rules.is_empty() {
            return None;
        }
        let stop = rules.get("stop")?.parse::<i64>().ok()?;
        Some(Padding {
            md5: hex::encode(Md5::digest(raw)),
            stop: stop as u32,
            rules,
        })
    }

    pub(super) fn default_scheme() -> Padding {
        Padding::parse(DEFAULT_SCHEME.as_bytes()).unwrap_or_else(|| Padding {
            md5: String::new(),
            stop: 0,
            rules: HashMap::new(),
        })
    }

    /// The record sizes planned for the `packet`-th write.
    pub(crate) fn sizes(&self, packet: u32) -> Vec<Size> {
        let Some(spec) = self.rules.get(&packet.to_string()) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for part in spec.split(',') {
            if part == "c" {
                out.push(Size::Check);
                continue;
            }
            let Some((low, high)) = part.split_once('-') else {
                continue;
            };
            let (Ok(mut low), Ok(mut high)) = (low.parse::<i64>(), high.parse::<i64>()) else {
                continue;
            };
            if low > high {
                std::mem::swap(&mut low, &mut high);
            }
            if low <= 0 || high <= 0 {
                continue;
            }
            let size = if low == high {
                low
            } else {
                rand::rng().random_range(low..high)
            };
            out.push(Size::Bytes(size as usize));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_scheme_parses() {
        let padding = Padding::default_scheme();
        assert_eq!(padding.stop, 8);
        assert_eq!(padding.sizes(0), vec![Size::Bytes(30)]);
        assert_eq!(padding.md5.len(), 32);
    }

    #[test]
    fn check_marks_and_ranges_are_kept_in_order() {
        let padding = Padding::default_scheme();
        let plan = padding.sizes(2);
        assert_eq!(plan.len(), 9);
        assert_eq!(plan.get(1), Some(&Size::Check));
        assert!(matches!(plan.first(), Some(Size::Bytes(400..=499))));
    }

    #[test]
    fn a_scheme_needs_a_numeric_stop() {
        assert!(Padding::parse(b"").is_none());
        assert!(Padding::parse(b"0=1-2").is_none());
        assert!(Padding::parse(b"stop=x").is_none());
        let swapped = Padding::parse(b"stop=2\n1=9-3\n").unwrap();
        assert!(matches!(swapped.sizes(1).first(), Some(Size::Bytes(3..=8))));
    }
}
