#[derive(Default)]
pub(super) struct RecordScan {
    header: [u8; 5],
    have: usize,
    remaining: usize,
    handshake: Vec<u8>,
    gathering: bool,
    seen: usize,
    dead: bool,
    ready: bool,
}

impl RecordScan {
    pub(super) fn feed(&mut self, mut data: &[u8], tls13: &mut bool) -> bool {
        if self.ready || self.dead {
            return self.ready;
        }
        self.seen = self.seen.saturating_add(data.len());
        if self.seen > 64 << 10 {
            self.dead = true;
            return false;
        }
        while !data.is_empty() {
            if self.remaining > 0 {
                let count = self.remaining.min(data.len());
                if self.gathering {
                    self.handshake
                        .extend_from_slice(data.get(..count).unwrap_or_default());
                }
                self.remaining -= count;
                data = data.get(count..).unwrap_or_default();
                if self.remaining == 0 && self.gathering {
                    *tls13 |= is_tls13_server_hello(&self.handshake);
                    self.handshake.clear();
                    self.gathering = false;
                }
                continue;
            }
            let count = (5 - self.have).min(data.len());
            if let (Some(dst), Some(src)) = (
                self.header.get_mut(self.have..self.have + count),
                data.get(..count),
            ) {
                dst.copy_from_slice(src);
            }
            self.have += count;
            data = data.get(count..).unwrap_or_default();
            if self.have < 5 {
                break;
            }
            let [kind, major, _, hi, lo] = self.header;
            if major != 3 || !(20..=23).contains(&kind) {
                self.dead = true;
                return false;
            }
            if kind == 23 && *tls13 {
                self.ready = true;
                return true;
            }
            self.remaining = usize::from(u16::from_be_bytes([hi, lo]));
            self.gathering = kind == 22 && !*tls13;
            self.have = 0;
        }
        false
    }
}

fn is_tls13_server_hello(data: &[u8]) -> bool {
    if data.first() != Some(&2) {
        return false;
    }
    let Some((&session_len, rest)) = data.get(38..).and_then(<[u8]>::split_first) else {
        return false;
    };
    let Some(lengths) = rest.get(usize::from(session_len) + 3..) else {
        return false;
    };
    let Some((&hi, tail)) = lengths.split_first() else {
        return false;
    };
    let Some((&lo, mut extensions)) = tail.split_first() else {
        return false;
    };
    let length = usize::from(u16::from_be_bytes([hi, lo]));
    extensions = extensions.get(..length).unwrap_or_default();
    while let Some([kind_hi, kind_lo, len_hi, len_lo]) = extensions.get(..4) {
        let kind = u16::from_be_bytes([*kind_hi, *kind_lo]);
        let length = usize::from(u16::from_be_bytes([*len_hi, *len_lo]));
        let Some(value) = extensions.get(4..4 + length) else {
            return false;
        };
        if kind == 43 && value == [3, 4] {
            return true;
        }
        extensions = extensions.get(4 + length..).unwrap_or_default();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_records_switch_only_after_tls13_is_selected() {
        let mut hello = vec![2, 0, 0, 46, 3, 3];
        hello.resize(38, 0);
        hello.extend_from_slice(&[0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
        let mut record = vec![22, 3, 3, 0, hello.len() as u8];
        record.extend_from_slice(&hello);
        for chunk in 1..=record.len() {
            let mut tls13 = false;
            let mut down = RecordScan::default();
            for part in record.chunks(chunk) {
                assert!(!down.feed(part, &mut tls13));
            }
            assert!(tls13);
            let mut up = RecordScan::default();
            for byte in [23, 3, 3, 0] {
                assert!(!up.feed(&[byte], &mut tls13));
            }
            assert!(up.feed(&[17], &mut tls13));
        }
    }

    #[test]
    fn plaintext_tls12_and_false_record_headers_stay_framed() {
        for input in [b"plain text".as_slice(), &[23, 3, 3, 0, 5, 23, 3, 3, 0, 0]] {
            let mut tls13 = false;
            assert!(!RecordScan::default().feed(input, &mut tls13));
            assert!(!tls13);
        }
    }
}
