use super::crypto::{Aead, Ctr};
use super::*;
use concord_common::Stream;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

fn client(mode: &str, rtt: &str) -> Arc<Client> {
    let private = StaticSecret::from([7; 32]);
    Client::parse(&format!(
        "mlkem768x25519plus.{mode}.{rtt}.100-35-35.{}",
        URL_SAFE_NO_PAD.encode(XPublic::from(&private).as_bytes())
    ))
    .unwrap()
    .unwrap()
}

#[test]
fn encryption_grammar_preserves_modes_padding_and_key_order() {
    for mode in ["native", "xorpub", "random"] {
        for rtt in ["1rtt", "0rtt"] {
            assert!(client(mode, rtt).padding.sample().0 == [35]);
        }
    }
    assert!(Client::parse("").unwrap().is_none());
    assert!(Client::parse("none").unwrap().is_none());
    for value in [
        "aes",
        "mlkem768x25519plus.native.1rtt",
        "mlkem768x25519plus.x.1rtt.x",
        "mlkem768x25519plus.native.2rtt.x",
        "mlkem768x25519plus.native.1rtt.100-35-35",
    ] {
        assert!(Client::parse(value).is_err(), "{value}");
    }
    let key = URL_SAFE_NO_PAD.encode([7; 32]);
    assert!(Client::parse(&format!("mlkem768x25519plus.native.1rtt..{key}")).is_ok());
    let invalid_kem = URL_SAFE_NO_PAD.encode([255; 1184]);
    assert!(Client::parse(&format!("mlkem768x25519plus.native.1rtt.{invalid_kem}")).is_err());

    for padding in [
        "99-35-35",
        "100-34-35",
        "100-35-35.0-0",
        "100-65554-65554",
        "100-a-35",
    ] {
        assert!(Client::parse(&format!("mlkem768x25519plus.native.1rtt.{padding}.{key}")).is_err());
    }
}

#[test]
fn nonce_is_incremented_before_aead_and_ctr_is_fragment_independent() {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
    for aes in [true, false] {
        let mut aead = Aead::new(b"context", b"material", aes).unwrap();
        let mut got = b"plaintext".to_vec();
        aead.seal(&mut got, b"aad").unwrap();
        let key = LessSafeKey::new(
            UnboundKey::new(
                if aes {
                    &AES_256_GCM
                } else {
                    &CHACHA20_POLY1305
                },
                &blake3::derive_key("context", b"material"),
            )
            .unwrap(),
        );
        let mut expected = b"plaintext".to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Aad::from(b"aad"),
            &mut expected,
        )
        .unwrap();
        assert_eq!(got, expected);
        Aead::new(b"context", b"material", aes)
            .unwrap()
            .open(&mut got, b"aad")
            .unwrap();
        assert_eq!(got, b"plaintext");
    }
    let mut whole = vec![0; 123];
    let mut pieces = whole.clone();
    Ctr::new(b"key", [255; 16]).apply(&mut whole);
    let mut ctr = Ctr::new(b"key", [255; 16]);
    for part in pieces.chunks_mut(3) {
        ctr.apply(part);
    }
    assert_eq!(whole, pieces);
}

#[tokio::test]
async fn records_match_wire_chunking_and_survive_split_backpressure() {
    for aes in [true, false] {
        for random in [true, false] {
            let (near, mut far) = tokio::io::duplex(37);
            let united: Arc<[u8]> = Arc::from(&b"united"[..]);
            let session = record::Session {
                united: united.clone(),
                send: Aead::new(b"upload", &united, aes).unwrap(),
                recv: Some(Aead::new(b"download", &united, aes).unwrap()),
                aes,
                iv: [9; 16],
                recv_iv: Some([8; 16]),
                padding: 16,
                prewrite: Vec::new(),
                resume: None,
                random,
            };
            let io = Encrypted::new(Box::new(near), session);
            let (mut reader, mut writer) = Box::new(io).into_split();
            let data: Vec<u8> = (0..20000).map(|i| (i % 251) as u8).collect();
            let send = data.clone();
            let writing = tokio::spawn(async move {
                writer.write_all(&send).await.unwrap();
                writer.shutdown().await.unwrap();
            });
            let mut uploaded = Vec::new();
            far.read_to_end(&mut uploaded).await.unwrap();
            writing.await.unwrap();
            if random {
                let mut mask = mask::HeaderMask::new(&united, [9; 16], 0);
                mask.apply(&mut uploaded, true);
            }
            let mut decrypt = Aead::new(b"upload", &united, aes).unwrap();
            let mut offset = 0;
            for part in data.chunks(8192) {
                let head = &uploaded[offset..offset + 5];
                assert_eq!(&head[..3], &[23, 3, 3]);
                let size = usize::from(u16::from_be_bytes([head[3], head[4]]));
                assert_eq!(size, part.len() + 16);
                let mut sealed = uploaded[offset + 5..offset + 5 + size].to_vec();
                decrypt.open(&mut sealed, head).unwrap();
                assert_eq!(sealed, part);
                offset += 5 + size;
            }
            assert_eq!(offset, uploaded.len());
            let mut encrypt = Aead::new(b"download", &united, aes).unwrap();
            let mut wire = Vec::new();
            encrypt.seal(&mut wire, &[]).unwrap();
            let head = [23, 3, 3, 0, 21];
            let mut body = b"reply".to_vec();
            encrypt.seal(&mut body, &head).unwrap();
            wire.extend_from_slice(&head);
            wire.extend_from_slice(&body);
            if random {
                mask::HeaderMask::new(&united, [8; 16], 16).apply(&mut wire, false);
            }
            let sending = tokio::spawn(async move {
                for part in wire.chunks(2) {
                    far.write_all(part).await.unwrap();
                }
                far.shutdown().await.unwrap();
            });
            let mut reply = Vec::new();
            reader.read_to_end(&mut reply).await.unwrap();
            sending.await.unwrap();
            assert_eq!(reply, b"reply");
        }
    }
}

#[tokio::test]
async fn low_order_nfs_keys_fail_before_sending_a_hello() {
    let value = format!(
        "mlkem768x25519plus.native.1rtt.{}",
        URL_SAFE_NO_PAD.encode([0; 32])
    );
    let client = Client::parse(&value).unwrap().unwrap();
    let (near, _far) = tokio::io::duplex(64);
    assert!(client.handshake(Box::new(near)).await.is_err());
}

#[test]
fn relay_chain_is_irreplaceable_and_binds_next_public_key_hash() {
    let secrets = [[7; 32], [11; 32], [21; 32]];
    for mode in ["native", "xorpub", "random"] {
        let keys: Vec<_> = secrets
            .iter()
            .map(|key| URL_SAFE_NO_PAD.encode(XPublic::from(&StaticSecret::from(*key)).as_bytes()))
            .collect();
        let value = format!("mlkem768x25519plus.{mode}.1rtt.{}", keys.join("."));
        let client = Client::parse(&value).unwrap().unwrap();
        let iv = rand::rng().random();
        let (hello, nfs) = client.relay_hello(iv).unwrap();
        let mut relays = hello[16..].to_vec();
        let mut previous: Option<Ctr> = None;
        let mut last = Vec::new();
        for (i, key) in secrets.iter().enumerate() {
            if let Some(ctr) = &mut previous {
                ctr.apply(&mut relays[..32]);
            }
            let public = XPublic::from(&StaticSecret::from(*key));
            if mode != "native" {
                Ctr::new(public.as_bytes(), iv).apply(&mut relays[..32]);
            }
            let peer = XPublic::from(<[u8; 32]>::try_from(&relays[..32]).unwrap());
            last = StaticSecret::from(*key)
                .diffie_hellman(&peer)
                .as_bytes()
                .to_vec();
            relays.drain(..32);
            if let Some(next) = secrets.get(i + 1) {
                let mut ctr = Ctr::new(&last, iv);
                ctr.apply(&mut relays[..32]);
                assert_eq!(
                    &relays[..32],
                    blake3::hash(XPublic::from(&StaticSecret::from(*next)).as_bytes()).as_bytes()
                );
                relays.drain(..32);
                previous = Some(ctr);
            }
        }
        assert_eq!(nfs, last);
        assert!(relays.is_empty());
    }
}

#[tokio::test]
async fn resumption_defers_hello_and_uses_sealed_ticket_context() {
    use futures_util::FutureExt;
    use std::time::Duration;
    for mode in ["native", "xorpub", "random"] {
        for aes in [true, false] {
            let client = client(mode, "0rtt");
            let ticket = Ticket {
                expires: Instant::now() + Duration::from_secs(60),
                pfs: [6; 64],
                bytes: [5; 16],
            };
            *concord_common::sync::lock(&client.ticket) = Some(ticket.clone());
            let (near, mut far) = tokio::io::duplex(37);
            let mut io = client
                .handshake_with_cipher(Box::new(near), aes)
                .await
                .unwrap();
            assert!(far.read(&mut [0]).now_or_never().is_none());
            let writing = tokio::spawn(async move {
                io.write_all(b"hi").await.unwrap();
                io
            });
            let mut hello = vec![0; 48 + 18 + 32 + 5 + 2 + 16];
            far.read_exact(&mut hello).await.unwrap();
            let iv: [u8; 16] = hello[..16].try_into().unwrap();
            let mut relay: [u8; 32] = hello[16..48].try_into().unwrap();
            let private = StaticSecret::from([7; 32]);
            if mode != "native" {
                Ctr::new(XPublic::from(&private).as_bytes(), iv).apply(&mut relay);
            }
            let nfs = private.diffie_hellman(&XPublic::from(relay));
            let mut nfs_aead = Aead::new(&iv, nfs.as_bytes(), aes).unwrap();
            let mut length = hello[48..66].to_vec();
            nfs_aead.open(&mut length, &[]).unwrap();
            assert_eq!(length, 32u16.to_be_bytes());
            let sealed_ticket = hello[66..98].to_vec();
            let mut plain_ticket = sealed_ticket.clone();
            nfs_aead.open(&mut plain_ticket, &[]).unwrap();
            assert_eq!(plain_ticket, ticket.bytes);
            let mut united = ticket.pfs.to_vec();
            united.extend_from_slice(nfs.as_bytes());
            let mut record = hello[98..].to_vec();
            if mode == "random" {
                mask::HeaderMask::new(&united, iv, 0).apply(&mut record, true);
            }
            let mut payload = record[5..].to_vec();
            Aead::new(&sealed_ticket, &united, aes)
                .unwrap()
                .open(&mut payload, &record[..5])
                .unwrap();
            assert_eq!(payload, b"hi");
            let mut io = writing.await.unwrap();
            let random = [0xf1; 16];
            let mut response = random.to_vec();
            let mut payload = b"ok".to_vec();
            let header = [23, 3, 3, 0, 18];
            Aead::new(&random, &united, aes)
                .unwrap()
                .seal(&mut payload, &header)
                .unwrap();
            response.extend_from_slice(&header);
            response.extend_from_slice(&payload);
            if mode == "random" {
                mask::HeaderMask::new(&united, random, 16).apply(&mut response, false);
            }
            let sending = tokio::spawn(async move {
                far.write_all(&response).await.unwrap();
            });
            let mut got = [0; 2];
            io.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"ok");
            sending.await.unwrap();
        }
    }
}

#[tokio::test]
async fn rejected_resumption_invalidates_only_the_matching_ticket() {
    for replacement in [false, true] {
        let client = client("native", "0rtt");
        let ticket = Ticket {
            expires: Instant::now() + std::time::Duration::from_secs(60),
            pfs: [1; 64],
            bytes: [2; 16],
        };
        *concord_common::sync::lock(&client.ticket) = Some(ticket.clone());
        let (near, mut far) = tokio::io::duplex(64);
        let mut io = client.handshake(Box::new(near)).await.unwrap();
        if replacement {
            *concord_common::sync::lock(&client.ticket) = Some(Ticket {
                pfs: [3; 64],
                ..ticket
            });
        }
        far.write_all(&[0; 21]).await.unwrap();
        assert!(io.read_u8().await.is_err());
        assert!(io.read_u8().await.is_err());
        assert_eq!(
            concord_common::sync::lock(&client.ticket).is_some(),
            replacement
        );
    }
}

#[tokio::test]
async fn tampered_padding_records_and_truncated_records_never_release_plaintext() {
    for fault in ["padding", "header", "tag", "truncated"] {
        let (near, mut far) = tokio::io::duplex(64);
        let session = record::Session {
            united: Arc::from(&b"united"[..]),
            send: Aead::new(b"send", b"united", true).unwrap(),
            recv: Some(Aead::new(b"recv", b"united", true).unwrap()),
            aes: true,
            iv: [0; 16],
            recv_iv: Some([0; 16]),
            padding: 16,
            prewrite: Vec::new(),
            resume: None,
            random: false,
        };
        let mut io = Encrypted::new(Box::new(near), session);
        let mut aead = Aead::new(b"recv", b"united", true).unwrap();
        let mut wire = Vec::new();
        aead.seal(&mut wire, &[]).unwrap();
        let header = [23, 3, 3, 0, 22];
        let mut body = b"secret".to_vec();
        aead.seal(&mut body, &header).unwrap();
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&body);
        match fault {
            "padding" => wire[0] ^= 1,
            "header" => wire[16] ^= 1,
            "tag" => *wire.last_mut().unwrap() ^= 1,
            _ => {
                wire.pop();
            }
        }
        far.write_all(&wire).await.unwrap();
        far.shutdown().await.unwrap();
        let mut out = [0; 32];
        assert!(io.read(&mut out).await.is_err(), "{fault}");
        assert_eq!(out, [0; 32]);
    }
}

async fn full_handshake_peer(
    mut peer: tokio::io::DuplexStream,
    mode: &str,
    aes: bool,
    corrupt: bool,
) -> [u8; 64] {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
    use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
    let mut prefix = [0; 48];
    peer.read_exact(&mut prefix).await.unwrap();
    let iv: [u8; 16] = prefix[..16].try_into().unwrap();
    let mut relay: [u8; 32] = prefix[16..].try_into().unwrap();
    let private = StaticSecret::from([7; 32]);
    if mode != "native" {
        Ctr::new(XPublic::from(&private).as_bytes(), iv).apply(&mut relay);
    }
    let nfs = private.diffie_hellman(&XPublic::from(relay));
    let mut nfs_aead = Aead::new(&iv, nfs.as_bytes(), aes).unwrap();
    let mut len = vec![0; 18];
    peer.read_exact(&mut len).await.unwrap();
    nfs_aead.open(&mut len, &[]).unwrap();
    assert_eq!(len, 1232u16.to_be_bytes());
    let mut public = vec![0; 1232];
    peer.read_exact(&mut public).await.unwrap();
    nfs_aead.open(&mut public, &[]).unwrap();
    assert_eq!(public.len(), 1216);
    let mut len = vec![0; 18];
    peer.read_exact(&mut len).await.unwrap();
    nfs_aead.open(&mut len, &[]).unwrap();
    let mut pad = vec![0; usize::from(u16::from_be_bytes([len[0], len[1]]))];
    peer.read_exact(&mut pad).await.unwrap();
    nfs_aead.open(&mut pad, &[]).unwrap();
    assert!(pad.iter().all(|&byte| byte == 0));
    let (ct, shared) = EncapsulationKey::new(&ML_KEM_768, &public[..1184])
        .unwrap()
        .encapsulate()
        .unwrap();
    let xs = StaticSecret::from(rand::rng().random::<[u8; 32]>());
    let xp = XPublic::from(<[u8; 32]>::try_from(&public[1184..]).unwrap());
    let mut pfs = [0; 64];
    pfs[..32].copy_from_slice(shared.as_ref());
    pfs[32..].copy_from_slice(xs.diffie_hellman(&xp).as_bytes());
    let mut united = pfs.to_vec();
    united.extend_from_slice(nfs.as_bytes());
    let mut reply = ct.as_ref().to_vec();
    reply.extend_from_slice(XPublic::from(&xs).as_bytes());
    let key = LessSafeKey::new(
        UnboundKey::new(
            if aes {
                &AES_256_GCM
            } else {
                &CHACHA20_POLY1305
            },
            &kdf::derive(&iv, nfs.as_bytes()),
        )
        .unwrap(),
    );
    let mut wire = reply.clone();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([255; 12]),
        Aad::empty(),
        &mut wire,
    )
    .unwrap();
    if corrupt {
        wire[0] ^= 1;
        peer.write_all(&wire).await.unwrap();
        return pfs;
    }
    let mut down = Aead::new(&reply, &united, aes).unwrap();
    let mut ticket = [7; 16];
    ticket[..2].copy_from_slice(&60u16.to_be_bytes());
    let mut sealed = ticket.to_vec();
    down.seal(&mut sealed, &[]).unwrap();
    wire.extend_from_slice(&sealed);
    let mut sealed = 16u16.to_be_bytes().to_vec();
    down.seal(&mut sealed, &[]).unwrap();
    wire.extend_from_slice(&sealed);
    let mut padding = Vec::new();
    down.seal(&mut padding, &[]).unwrap();
    let head = [23, 3, 3, 0, 21];
    let mut body = b"hello".to_vec();
    down.seal(&mut body, &head).unwrap();
    let mut records = padding;
    records.extend_from_slice(&head);
    records.extend_from_slice(&body);
    if mode == "random" {
        mask::HeaderMask::new(&united, ticket, 16).apply(&mut records, false);
    }
    wire.extend_from_slice(&records);
    for part in wire.chunks(3) {
        peer.write_all(part).await.unwrap();
    }
    pfs
}

#[tokio::test]
async fn full_mlkem_pfs_handshake_and_late_server_padding_work_for_both_ciphers() {
    for mode in ["native", "xorpub", "random"] {
        for aes in [true, false] {
            let client = client(mode, "0rtt");
            let (near, far) = tokio::io::duplex(37);
            let server = tokio::spawn(full_handshake_peer(far, mode, aes, false));
            let mut io = client
                .handshake_with_cipher(Box::new(near), aes)
                .await
                .unwrap();
            let mut reply = [0; 5];
            io.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"hello");
            let expected = server.await.unwrap();
            assert_eq!(
                concord_common::sync::lock(&client.ticket)
                    .as_ref()
                    .unwrap()
                    .pfs,
                expected
            );
        }
    }
}

#[tokio::test]
async fn unauthenticated_pfs_reply_never_installs_a_ticket() {
    let client = client("native", "0rtt");
    let (near, far) = tokio::io::duplex(37);
    let server = tokio::spawn(full_handshake_peer(far, "native", true, true));
    assert!(
        client
            .handshake_with_cipher(Box::new(near), true)
            .await
            .is_err()
    );
    server.await.unwrap();
    assert!(concord_common::sync::lock(&client.ticket).is_none());
}

#[tokio::test]
async fn vision_direct_drains_decrypted_tail_and_keeps_random_header_mask() {
    use crate::vless::stream::Vision;
    for random in [false, true] {
        let (near, mut far) = tokio::io::duplex(37);
        let session = record::Session {
            united: Arc::from(&b"united"[..]),
            send: Aead::new(b"send", b"united", true).unwrap(),
            recv: Some(Aead::new(b"recv", b"united", true).unwrap()),
            aes: true,
            iv: [8; 16],
            recv_iv: Some([9; 16]),
            padding: 16,
            prewrite: Vec::new(),
            resume: None,
            random,
        };
        let (read, write) = Encrypted::new(Box::new(near), session).into_halves();
        let user = [7; 16];
        let mut io = Vision::from_halves(read, write, Vec::new(), user);
        let mut aead = Aead::new(b"recv", b"united", true).unwrap();
        let mut wire = Vec::new();
        aead.seal(&mut wire, &[]).unwrap();
        let mut content = vec![0, 0];
        content.extend_from_slice(&user);
        content.extend_from_slice(&[2, 0, 1, 0, 0]);
        content.extend_from_slice(b"xtail");
        let len = u16::try_from(content.len() + 16).unwrap().to_be_bytes();
        let head = [23, 3, 3, len[0], len[1]];
        aead.seal(&mut content, &head).unwrap();
        wire.extend_from_slice(&head);
        wire.extend_from_slice(&content);
        wire.extend_from_slice(&[23, 3, 3, 0, 3, b'r', b'a', b'w']);
        if random {
            mask::HeaderMask::new(b"united", [9; 16], 16).apply(&mut wire, false);
        }
        let server = tokio::spawn(async move {
            for part in wire.chunks(2) {
                far.write_all(part).await.unwrap();
            }
            far.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        io.read_to_end(&mut got).await.unwrap();
        assert_eq!(
            got,
            [b"xtail".as_slice(), &[23, 3, 3, 0, 3, b'r', b'a', b'w']].concat()
        );
        let (_read, _write) = Box::new(io).into_split();
        server.await.unwrap();
    }
}

#[test]
fn mlkem_modulus_check_covers_both_coefficients_and_excludes_seed() {
    let parse = |bytes: &[u8]| {
        Client::parse(&format!(
            "mlkem768x25519plus.native.1rtt.{}",
            URL_SAFE_NO_PAD.encode(bytes)
        ))
    };
    for at in [0, 381, 768, 1149] {
        let mut key = [0; 1184];
        key[1152..].fill(255);
        key[at] = 0;
        key[at + 1] = 13;
        assert!(parse(&key).is_ok());
        key[at] = 1;
        assert!(parse(&key).is_err());
        key[at] = 0;
        key[at + 1] = 0;
        key[at + 2] = 208;
        assert!(parse(&key).is_ok());
        key[at + 1] = 16;
        assert!(parse(&key).is_err());
    }
}

#[tokio::test]
async fn resumed_hello_and_first_record_match_mihomo_generated_bytes() {
    // mihomo v1.19.33, Go 1.27.3: in the mihomo checkout, go run <generator.go> > <vectors.json>.
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/vless-encryption/vectors.json"
    ))
    .unwrap();
    let vectors = vectors.as_array().unwrap();
    assert_eq!(vectors.len(), 6);
    for v in vectors {
        let bytes = |field: &str| hex::decode(v[field].as_str().unwrap()).unwrap();
        let client = Client::parse(v["config"].as_str().unwrap())
            .unwrap()
            .unwrap();
        let iv: [u8; 16] = bytes("iv").try_into().unwrap();
        let mut ephemeral = v["ephemeral"].as_array().unwrap().iter();
        let (hello, nfs) = client
            .relay_hello_with_x25519(iv, || {
                hex::decode(ephemeral.next().unwrap().as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .unwrap();
        let ticket = Ticket {
            expires: Instant::now() + std::time::Duration::from_secs(60),
            pfs: bytes("pfs").try_into().unwrap(),
            bytes: bytes("ticket").try_into().unwrap(),
        };
        let session = client
            .resumed_session(hello, nfs, iv, v["aes"].as_bool().unwrap(), ticket)
            .unwrap();
        let expected_hello = bytes("hello");
        assert_eq!(session.prewrite, expected_hello, "{} hello", v["mode"]);
        let (near, mut far) = tokio::io::duplex(37);
        let mut io = Encrypted::new(Box::new(near), session);
        let payload = bytes("payload");
        let sending = tokio::spawn(async move {
            io.write_all(&payload).await.unwrap();
            io.shutdown().await.unwrap();
        });
        let mut wire = Vec::new();
        far.read_to_end(&mut wire).await.unwrap();
        sending.await.unwrap();
        assert_eq!(&wire[..expected_hello.len()], &expected_hello);
        assert_eq!(
            &wire[expected_hello.len()..],
            &bytes("record"),
            "{} record, AES {}",
            v["mode"],
            v["aes"]
        );
    }
}

#[test]
fn raw_url_base64_matches_go_noncanonical_tail_bits_and_newlines() {
    let raw = URL_SAFE_NO_PAD.encode([7; 32]);
    let canonical = Client::parse(&format!("mlkem768x25519plus.native.1rtt.{raw}"))
        .unwrap()
        .unwrap();
    let mut alias = raw.into_bytes();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = alphabet
        .iter()
        .position(|b| Some(b) == alias.last())
        .unwrap();
    *alias.last_mut().unwrap() = alphabet[last | 3];
    alias.splice(7..7, *b"\r\n");
    let alias = String::from_utf8(alias).unwrap();
    let parsed = Client::parse(&format!("mlkem768x25519plus.native.1rtt.{alias}"))
        .unwrap()
        .unwrap();
    assert_eq!(canonical.relays[0].bytes, parsed.relays[0].bytes);
    assert!(Client::parse(&format!("mlkem768x25519plus.native.1rtt.{alias}=")).is_err());
}

#[tokio::test]
async fn valid_resumption_header_with_bad_aead_or_eof_keeps_ticket() {
    for eof in [false, true] {
        let client = client("native", "0rtt");
        *concord_common::sync::lock(&client.ticket) = Some(Ticket {
            expires: Instant::now() + std::time::Duration::from_secs(60),
            pfs: [1; 64],
            bytes: [2; 16],
        });
        let (near, mut far) = tokio::io::duplex(64);
        let mut io = client.handshake(Box::new(near)).await.unwrap();
        let mut wire = vec![9; 16];
        wire.extend_from_slice(&[23, 3, 3, 0, 17]);
        wire.extend_from_slice(&[0; 17]);
        if eof {
            wire.pop();
        }
        far.write_all(&wire).await.unwrap();
        far.shutdown().await.unwrap();
        assert!(io.read_u8().await.is_err());
        assert!(concord_common::sync::lock(&client.ticket).is_some());
    }
}

#[tokio::test]
async fn record_body_length_accepts_17_and_17000_and_rejects_adjacent_values() {
    for size in [16u16, 17, 17000, 17001] {
        let (near, mut far) = tokio::io::duplex(37);
        let session = record::Session {
            united: Arc::from(&b"united"[..]),
            send: Aead::new(b"send", b"united", true).unwrap(),
            recv: Some(Aead::new(b"recv", b"united", true).unwrap()),
            aes: true,
            iv: [0; 16],
            recv_iv: Some([0; 16]),
            padding: 16,
            prewrite: Vec::new(),
            resume: None,
            random: false,
        };
        let mut io = Encrypted::new(Box::new(near), session);
        let mut aead = Aead::new(b"recv", b"united", true).unwrap();
        let mut wire = Vec::new();
        aead.seal(&mut wire, &[]).unwrap();
        let header = [23, 3, 3, size.to_be_bytes()[0], size.to_be_bytes()[1]];
        wire.extend_from_slice(&header);
        let accepted = [17, 17000].contains(&size);
        let expected: Vec<_> = (0..usize::from(size) - 16)
            .map(|i| (i % 251) as u8)
            .collect();
        if accepted {
            let mut body = expected.clone();
            aead.seal(&mut body, &header).unwrap();
            wire.extend_from_slice(&body);
        }
        let sending = tokio::spawn(async move {
            far.write_all(&wire).await.unwrap();
            far.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        let result = io.read_to_end(&mut got).await;
        if accepted {
            result.unwrap();
            assert_eq!(got, expected);
        } else {
            assert!(result.is_err());
            assert!(got.is_empty());
        }
        sending.await.unwrap();
    }
}
