#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert fixed wire shapes"
)]
use super::codec::{Decode, Encode};
use super::frame::Chunk;
use super::v6_frame::{Mode, Opener, Sealer};
use super::v6_profile::Profile;
use bytes::BytesMut;
use std::sync::Arc;

const PSK: &[u8] = b"snell-v6-test-psk-0123456789";
fn codecs(mode: Mode) -> (Sealer, Opener) {
    let profile = (mode == Mode::Default).then(|| Arc::new(Profile::new(PSK)));
    (
        Sealer::new(mode, PSK, profile.clone()).unwrap(),
        Opener::new(mode, PSK, profile),
    )
}

#[test]
fn v6_stream_and_packet_boundaries_survive_fragmentation() {
    for mode in [Mode::Default, Mode::Unshaped, Mode::Raw] {
        let (mut sealer, mut opener) = codecs(mode);
        let data: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let packet = vec![42; 0xffff];
        let mut wire = Vec::new();
        sealer.seal_stream(&mut wire, &data).unwrap();
        sealer.seal_chunk(&mut wire, &packet).unwrap();
        sealer.seal_zero(&mut wire).unwrap();
        let (mut input, mut plain) = (BytesMut::new(), BytesMut::new());
        let mut got = Vec::new();
        let mut last = Vec::new();
        let mut zero = false;
        for piece in wire.chunks(131) {
            input.extend_from_slice(piece);
            while let Some(chunk) = opener.open(&mut input, &mut plain).unwrap() {
                match chunk {
                    Chunk::Data => {
                        got.extend_from_slice(&plain);
                        last = plain.split().to_vec();
                    }
                    Chunk::Zero => zero = true,
                }
            }
        }
        assert!(zero, "{mode:?}");
        assert_eq!(last, packet);
        assert_eq!(&got[..data.len()], data);
        assert_eq!(&got[data.len()..], packet);
        assert!(input.is_empty());
    }
}

#[test]
fn v6_client_id_request_bytes_match_upstream() {
    use concord_common::Address;
    let dst = Address::Domain("example.com".into(), 443);
    for cmd in [1, 5] {
        let mut expected = vec![1, cmd, 9];
        expected.extend_from_slice(b"alice-key\x0bexample.com\x01\xbb");
        assert_eq!(
            super::v6::header(cmd, b"alice-key", Some(&dst)).unwrap(),
            expected
        );
    }
    assert_eq!(
        super::v6::header(6, b"alice-key", None).unwrap(),
        b"\x01\x06\x09alice-key"
    );
    assert!(super::v6::header(6, &[0; 256], None).is_err());
}

#[test]
fn v6_raw_header_bytes_and_validation() {
    let (mut sealer, mut opener) = codecs(Mode::Raw);
    let mut wire = Vec::new();
    sealer.seal_chunk(&mut wire, b"hello").unwrap();
    assert_eq!(wire, b"\x04\0\0\0\0\0\x05hello");
    for bad in [
        vec![3, 0, 0, 0, 0, 0, 1, 42],
        vec![4, 1, 0, 0, 0, 0, 1, 42],
        vec![4, 0, 0, 0, 1, 0, 1, 42],
    ] {
        assert!(
            opener
                .open(&mut BytesMut::from(&bad[..]), &mut BytesMut::new())
                .is_err()
        );
    }
    assert!(sealer.seal_chunk(&mut Vec::new(), &vec![0; 65536]).is_err());
}

#[test]
fn v6_authentication_rejects_modified_records() {
    for mode in [Mode::Default, Mode::Unshaped] {
        let (mut sealer, _) = codecs(mode);
        let mut wire = Vec::new();
        sealer.seal_chunk(&mut wire, b"hello").unwrap();
        for at in [
            wire.len() - 1,
            if mode == Mode::Default {
                Profile::new(PSK).salt_len
            } else {
                16
            },
        ] {
            let (_, mut opener) = codecs(mode);
            let mut changed = wire.clone();
            changed[at] ^= 1;
            assert!(
                opener
                    .open(&mut BytesMut::from(&changed[..]), &mut BytesMut::new())
                    .is_err(),
                "{mode:?}"
            );
        }
    }
}

#[test]
fn v6_adapter_options_follow_upstream() {
    use serde_json::json;
    let build = |extra: serde_json::Value| {
        let mut base = json!({"version":6,"psk":"snell-v6-test-psk-0123456789","udp":true});
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        super::tests::build(base)
    };
    for mode in ["", "default", "unshaped", "unsafe-raw"] {
        assert!(build(json!({"mode":mode,"userkey":"alice-key","reuse":true})).is_ok());
    }
    for extra in [
        json!({"mode":"bogus"}),
        json!({"psk":"short"}),
        json!({"psk":"a".repeat(256)}),
        json!({"obfs-opts":{"mode":"tls"}}),
        json!({"obfs-opts":{"mode":"http"}}),
    ] {
        assert!(build(extra.clone()).is_err(), "{extra}");
    }
    for version in [2, 3] {
        assert!(build(json!({"obfs-opts":{"mode":"shadow-tls","host":"a.test","password":"pw","version":version}})).is_ok());
    }
}

#[tokio::test]
async fn v6_partial_records_fail_at_eof_and_split_halves_keep_reading() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for mode in [Mode::Default, Mode::Unshaped, Mode::Raw] {
        let (mut sealer, _) = codecs(mode);
        let mut wire = Vec::new();
        sealer.seal_stream(&mut wire, b"\0hello").unwrap();
        for cut in [wire.len(), wire.len() - 1] {
            let (io, mut peer) = tokio::io::duplex(65536);
            peer.write_all(&wire[..cut]).await.unwrap();
            drop(peer);
            let (sealer, opener) = codecs(mode);
            let mut stream = super::stream::SnellStream::with_codecs(io, sealer, opener);
            let mut got = Vec::new();
            let result = stream.read_to_end(&mut got).await;
            if cut == wire.len() {
                result.unwrap();
                assert_eq!(got, b"hello");
            } else {
                assert_eq!(
                    result.unwrap_err().kind(),
                    std::io::ErrorKind::UnexpectedEof
                );
            }
        }
        let (io, mut peer) = tokio::io::duplex(65536);
        let (sealer, opener) = codecs(mode);
        let stream: concord_common::BoxStream =
            Box::new(super::stream::SnellStream::with_codecs(io, sealer, opener));
        let (mut read, mut write) = stream.into_split();
        write.write_all(b"up").await.unwrap();
        write.shutdown().await.unwrap();
        let mut incoming = Vec::new();
        peer.read_to_end(&mut incoming).await.unwrap();
        let (_, mut opener) = codecs(mode);
        let mut plain = BytesMut::new();
        let mut input = BytesMut::from(&incoming[..]);
        assert!(matches!(
            opener.open(&mut input, &mut plain).unwrap(),
            Some(Chunk::Data)
        ));
        assert_eq!(&plain[..], b"up");
        assert!(matches!(
            opener.open(&mut input, &mut plain).unwrap(),
            Some(Chunk::Zero)
        ));
        peer.write_all(&wire).await.unwrap();
        drop(peer);
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");
    }
}

#[test]
fn v6_fixed_salt_wire_matches_upstream_alpha() {
    use sha2::{Digest, Sha256};
    // Go 1.27.3, mihomo 3c0d10a5 transport/snell, salt 00..0f: each PSK and mode's v6 record
    // writer (newV6Profile, v6AEAD) writes the same packets and stream, then a zero chunk.
    let vectors: serde_json::Value = serde_json::from_str(include_str!("v6_vectors.json")).unwrap();
    for vector in vectors.as_array().unwrap() {
        let psk = vector["psk"].as_str().unwrap().as_bytes();
        let mode = Mode::parse(vector["mode"].as_str().unwrap()).unwrap();
        let profile = (mode == Mode::Default).then(|| Arc::new(Profile::new(psk)));
        let mut sealer = Sealer::new(mode, psk, profile.clone()).unwrap();
        sealer
            .set_test_salt(psk, std::array::from_fn(|i| i as u8))
            .unwrap();
        let mut wire = Vec::new();
        sealer.seal_chunk(&mut wire, b"hello\0world").unwrap();
        sealer.seal_stream(&mut wire, &vec![0x43; 3000]).unwrap();
        sealer.seal_chunk(&mut wire, &vec![0x42; 2000]).unwrap();
        for round in 0..12 {
            sealer
                .seal_chunk(&mut wire, &vec![round as u8; 5 + round * 31])
                .unwrap();
        }
        sealer.seal_zero(&mut wire).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&wire)),
            vector["hash"].as_str().unwrap(),
            "PSK {} mode {mode:?}",
            String::from_utf8_lossy(psk)
        );
        if let Some(upstream) = vector["wire"].as_str() {
            let upstream = hex::decode(upstream).unwrap();
            assert_eq!(wire, upstream);
            let mut opener = Opener::new(mode, psk, profile);
            let mut input = BytesMut::from(&upstream[..]);
            let mut plain = BytesMut::new();
            let mut zero = false;
            while let Some(chunk) = opener.open(&mut input, &mut plain).unwrap() {
                zero |= matches!(chunk, Chunk::Zero);
            }
            assert!(zero);
            assert!(input.is_empty());
            let mut expected = b"hello\0world".to_vec();
            expected.extend_from_slice(&vec![0x43; 3000]);
            expected.extend_from_slice(&vec![0x42; 2000]);
            for round in 0..12 {
                expected.extend_from_slice(&vec![round as u8; 5 + round * 31]);
            }
            assert_eq!(&plain[..], expected);
        }
    }
}

#[test]
fn v6_options_warn_for_older_versions_and_quarantine_oversized_id() {
    use concord_config::{Capabilities, ProxyParse, parse_proxy};
    use serde_json::json;
    for version in [0, 1, 2, 3, 4, 5] {
        for extra in [json!({"mode":"default"}), json!({"userkey":"alice-key"})] {
            let mut node = json!({"name":"s","type":"snell","server":"a.test","port":443,
                "psk":"snell-v6-test-psk-0123456789","version":version});
            node.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let parsed = parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap();
            let ProxyParse::Ok(def) = parsed else {
                panic!("{node}");
            };
            let concord_config::proxy::ProxyKind::Snell(opts) = &def.kind else {
                unreachable!();
            };
            assert!(opts.mode.is_empty() && opts.userkey.is_empty());
            let key = extra.as_object().unwrap().keys().next().unwrap();
            assert!(
                concord_config::proxy::proxy_warnings(&def)
                    .iter()
                    .any(|message| message
                        == &format!("{key} is ignored: only snell version 6 reads it")),
                "{node}"
            );
        }
    }
    let node = json!({"name":"s","type":"snell","server":"a.test","port":443,
        "psk":"snell-v6-test-psk-0123456789","version":6,"userkey":"a".repeat(256)});
    assert!(matches!(
        parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap(),
        ProxyParse::Quarantined { .. }
    ));
}
