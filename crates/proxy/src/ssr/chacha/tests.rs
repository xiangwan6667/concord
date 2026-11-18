#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert fixed cipher states"
)]

use super::*;
use chacha20::cipher::StreamCipherSeek;

#[test]
fn both_stream_ciphers_carry_the_counter_past_256_gib() {
    for iv_len in [8, 24] {
        let iv: Vec<u8> = (0..iv_len).map(|i| 0xa0 + i).collect();
        let mut cipher = ChaCha64::new(&[7; 32], &iv).unwrap();
        let boundary = u64::from(u32::MAX) * 64;
        cipher.position = boundary - 5;
        cipher.cipher.seek(cipher.position);
        let mut got = [0; 140];
        for part in got.chunks_mut(17) {
            cipher.apply(part).unwrap();
        }
        let mut expected = [0; 140];
        let mut original = ChaCha64::new(&[7; 32], &iv).unwrap();
        original.cipher.seek(boundary - 5);
        original.cipher.apply_keystream(&mut expected[..5]);
        let mut last = chacha20::ChaChaCore::<U10>::new(&original.key, &original.nonce.into());
        last.set_block_pos(u32::MAX);
        let mut block = Block::<chacha20::ChaChaCore<U10>>::default();
        last.write_keystream_block(&mut block);
        expected[5..69].copy_from_slice(&block);
        let mut nonce = original.nonce;
        nonce[..4].copy_from_slice(&1u32.to_le_bytes());
        ChaCha20::new(&original.key, &nonce.into()).apply_keystream(&mut expected[69..]);
        assert_eq!(got, expected, "{iv_len}-byte IV");
        assert_eq!(cipher.position, 71);
        assert_eq!(&cipher.nonce[..4], &1u32.to_le_bytes());
    }
}

#[test]
fn both_stream_ciphers_match_go_vectors_across_the_256_gib_boundary() {
    // Go 1.27.3, metacubex/chacha v0.1.5 NewChaCha20IgnoreCounterOverflow: key 32 bytes of 7,
    // SetCounter(2^32 - 1), then 140 zero bytes; each line is the IV followed by the output.
    for line in include_str!("../tests/chacha-boundary.txt").lines() {
        let (iv_len, wire) = line.split_once(' ').unwrap();
        let iv_len = iv_len.parse::<usize>().unwrap();
        let wire = hex::decode(wire).unwrap();
        let (iv, expected) = wire.split_at(iv_len);
        let mut cipher = ChaCha64::new(&[7; 32], iv).unwrap();
        cipher.position = u64::from(u32::MAX) * 64;
        cipher.cipher.seek(cipher.position);
        let mut got = vec![0; 140];
        for chunk in got.chunks_mut(5) {
            cipher.apply(chunk).unwrap();
        }
        assert_eq!(got, expected, "{iv_len}-byte IV");
    }
}
