#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert fixed wire vectors"
)]

use super::*;

#[test]
fn chacha_stream_encoding_matches_go_vectors_across_writes() {
    let plain: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
    for line in include_str!("../tests/chacha-kat.txt").lines() {
        let (iv_len, wire) = line.split_once(' ').unwrap();
        let wire = hex::decode(wire).unwrap();
        let name = if iv_len == "8" {
            "chacha20"
        } else {
            "xchacha20"
        };
        let cipher = SsrCipher::pick(name, "ssr-test-password").unwrap();
        let mut layer = cipher.layer().unwrap();
        layer.iv = wire[..cipher.iv_len()].to_vec();
        layer.enc = Some(KeyStream::new(layer.kind.unwrap(), &layer.key, &layer.iv).unwrap());
        let mut encoded = Vec::new();
        for data in plain.chunks(37) {
            layer.encode(&mut encoded, data).unwrap();
        }
        assert_eq!(encoded, wire, "{name}");
        for len in 0..cipher.iv_len() {
            let mut short = concord_common::PacketBuf::from_slice(&wire[..len]);
            assert_eq!(
                cipher.open_packet(&mut short).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
