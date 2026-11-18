use blake3::hazmat::HasherExt;

pub(super) fn context_key(context: &[u8]) -> [u8; 32] {
    blake3::hazmat::hash_derive_key_context_bytes(context)
}

pub(super) fn derive(context: &[u8], material: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new_from_context_key(&context_key(context))
        .update(material)
        .finalize()
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    #[test]
    fn binary_context_matches_blake3_for_random_utf8_at_tree_boundaries() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x564c455353);
        for len in [
            0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 3072, 4096, 17005, 32769,
        ] {
            for _ in 0..8 {
                let context: String = (0..len)
                    .map(|_| char::from(rng.random_range(0..=127)))
                    .collect();
                assert_eq!(
                    context_key(context.as_bytes()),
                    blake3::hazmat::hash_derive_key_context(&context)
                );
                let material: [u8; 32] = rng.random();
                assert_eq!(
                    derive(context.as_bytes(), &material),
                    blake3::derive_key(&context, &material)
                );
            }
        }
        for _ in 0..64 {
            let context: String = (0..rng.random_range(0..4096))
                .map(|_| rng.random::<char>())
                .collect();
            assert_eq!(
                context_key(context.as_bytes()),
                blake3::hazmat::hash_derive_key_context(&context)
            );
        }
    }
    #[test]
    fn official_blake3_derive_key_vectors() {
        // BLAKE3 1.8.3 test_vectors/test_vectors.json, first 32 output bytes.
        let vectors = [
            (
                0,
                "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
            ),
            (
                1,
                "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c",
            ),
            (
                63,
                "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3",
            ),
            (
                64,
                "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e",
            ),
            (
                65,
                "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8",
            ),
            (
                1023,
                "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5",
            ),
            (
                1024,
                "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706",
            ),
            (
                1025,
                "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb",
            ),
            (
                2048,
                "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23",
            ),
            (
                2049,
                "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273",
            ),
            (
                3072,
                "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b",
            ),
            (
                4096,
                "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9",
            ),
            (
                8192,
                "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d",
            ),
            (
                16384,
                "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e1",
            ),
            (
                31744,
                "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e",
            ),
        ];
        for (len, expected) in vectors {
            let material: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                hex::encode(derive(
                    b"BLAKE3 2019-12-27 16:29:52 test vectors context",
                    &material
                )),
                expected
            );
        }
    }
}
