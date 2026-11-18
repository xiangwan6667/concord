#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert on fixed shapes"
)]

use std::sync::Arc;
use std::time::Duration;

use concord_common::{Address, BoxStream, BoxWrite, DialCx, Initiator, Outbound, PacketBuf};
use concord_config::proxy::ProxyKind;
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::cipher::{Seal, Sealer, derive_key, hash_password};
use super::meta::{self, Meta};
use super::padding::{decode_low, encode_low, encoded_len, new_half_mask};
use super::pattern::Pattern;
use super::stream::MieruStream;
use super::underlay::{Reader, Underlay};
use crate::BuildCtx;
use crate::build_outbound;
use crate::dgram::{Decoded, Decoder, Encoder};
use crate::testing::HeldLookup;
use crate::util::lock;

const USER: &str = "mieru-user";
const PASSWORD: &str = "mieru-pass";

fn key() -> [u8; 32] {
    derive_key(&hash_password(PASSWORD, USER), 1_730_000_000)
}

#[test]
fn keys_match_the_pbkdf2_reference() {
    let hashed = hash_password(PASSWORD, USER);
    assert_eq!(
        hex::encode(hashed),
        "f3ceb81f087cd53472f14970ab5bbdba190c56c57982f545105746b2688f2915"
    );
    let early = "a1601f3191b9a6915cce7fbb34115ce307da14970051e3fe496fdc4efe6a20e9";
    let late = "5183f0bd3cd638d8360497da4c88466cd103613437d48f1229607441f7dbc0b9";
    for (secs, want) in [
        (1_730_000_000, early),
        (1_730_000_059, early),
        (1_730_000_060, early),
        (1_730_000_119, late),
        (1_730_000_120, late),
    ] {
        assert_eq!(hex::encode(derive_key(&hashed, secs)), want, "{secs}");
    }
}

#[test]
fn the_documented_low_entropy_example_encodes_as_written() {
    let source = [0x12, 0x34, 0x56, 0x78];
    let zero = encode_low(&source, 1, 0x0f0f_0f0f, 0, false).unwrap();
    assert_eq!(zero, [1, 2, 3, 4, 5, 6, 7, 8]);
    let one = encode_low(&source, 1, 0x0f0f_0f0f, 0, true).unwrap();
    assert_eq!(one, [0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8]);
    assert_eq!(decode_low(&zero, 4, 1, 0x0f0f_0f0f, 0).unwrap(), source);
    assert_eq!(decode_low(&one, 4, 1, 0x0f0f_0f0f, 0).unwrap(), source);
}

#[test]
fn low_entropy_round_trips_in_every_mode_and_rotation() {
    for mode in 1..=4u8 {
        for rotation in [0u8, 1, 7, 15, 16, 80, 240] {
            for size in [1usize, 3, 4, 5, 7, 8, 100, 1000] {
                let data: Vec<u8> = (0..size).map(|i| (i * 31 % 256) as u8).collect();
                let half = new_half_mask(mode).unwrap();
                for bit in [false, true] {
                    let wire = encode_low(&data, mode, half, rotation, bit).unwrap();
                    assert_eq!(wire.len(), encoded_len(size, mode).unwrap());
                    assert_eq!(
                        decode_low(&wire, size, mode, half, rotation).unwrap(),
                        data,
                        "mode {mode} rotation {rotation} size {size}"
                    );
                }
            }
        }
    }
}

#[test]
fn mixed_low_entropy_padding_is_rejected() {
    let half = 0x0f0f_0f0f;
    let mut wire = encode_low(&[9; 8], 1, half, 0, false).unwrap();
    if let Some(byte) = wire.get_mut(12) {
        *byte |= 0xf0;
    }
    assert!(decode_low(&wire, 8, 1, half, 0).is_err());
    assert!(decode_low(&wire, 8, 1, 0x0f0f_0f1f, 0).is_err());
}

#[test]
fn metadata_round_trips() {
    let session = Meta::Session {
        kind: meta::OPEN_REQUEST,
        id: 7,
        seq: 3,
        status: 1,
        payload_len: 22,
        suffix_len: 9,
    };
    assert_eq!(Meta::decode(&session.encode()).unwrap(), session);
    let data = Meta::Data {
        kind: meta::DATA_C2S_LOW,
        id: 70,
        seq: 31,
        unack: 5,
        window: 4096,
        fragment: 0,
        prefix_len: 4,
        payload_len: 64,
        suffix_len: 8,
        low: meta::LowEntropyMeta {
            mode: 2,
            mask: 0x1234_5678,
            extracted_len: 40,
            rotation: 32,
        },
    };
    assert_eq!(Meta::decode(&data.encode()).unwrap(), data);
    assert!(Meta::decode(&[0u8; 32]).is_err());
    assert!(Meta::decode(&[2u8; 31]).is_err());
}

#[test]
fn an_empty_pattern_gets_printable_nonces_and_bounded_padding() {
    let pattern = Pattern::parse("").unwrap();
    assert!(!pattern.fragment.enable);
    assert!(pattern.low_entropy.is_none());
    assert!(pattern.max_middle <= 127);
    assert_eq!(pattern.max_end, 255);
    assert!((6..=12).contains(&pattern.nonce.min_len));
    assert!(pattern.nonce.max_len >= pattern.nonce.min_len && pattern.nonce.max_len <= 12);
}

#[test]
fn a_pattern_with_a_seed_is_stable_and_bad_ones_are_rejected() {
    use base64::Engine;
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let seeded = encode(&[0x08, 0x2a]);
    let a = Pattern::parse(&seeded).unwrap();
    let b = Pattern::parse(&seeded).unwrap();
    assert_eq!(a.max_middle, b.max_middle);
    assert_eq!(a.nonce.min_len, b.nonce.min_len);
    let explicit = encode(&[0x1a, 0x04, 0x08, 0x01, 0x10, 0x05]);
    let pattern = Pattern::parse(&explicit).unwrap();
    assert!(pattern.fragment.enable);
    assert_eq!(pattern.fragment.max_sleep_ms, 5);
    let too_sleepy = encode(&[0x1a, 0x04, 0x08, 0x01, 0x10, 0x65]);
    assert!(Pattern::parse(&too_sleepy).is_err());
    assert!(Pattern::parse("!!!").is_err());
    let bad_mode = encode(&[0x32, 0x02, 0x08, 0x09]);
    assert!(Pattern::parse(&bad_mode).is_err());
}

#[test]
fn udp_frames_round_trip() {
    for dst in [
        Address::new("example.com", 5353),
        Address::new("10.1.2.3", 53),
        Address::new("2001:db8::1", 443),
    ] {
        let mut pkt = PacketBuf::with_headroom(super::udp::Frames.headroom());
        pkt.extend_from_slice(b"payload");
        super::udp::Frames.encode(&mut pkt, &dst).unwrap();
        let mut wire = pkt.as_slice().to_vec();
        assert_eq!(wire.first(), Some(&0x00));
        assert_eq!(wire.last(), Some(&0xff));
        let Decoded::Packet {
            addr,
            payload,
            consumed,
        } = super::udp::Frames.decode(&mut wire).unwrap()
        else {
            panic!("expected a packet");
        };
        assert_eq!(addr, Some(dst));
        assert_eq!(&wire[payload], b"payload");
        assert_eq!(consumed, wire.len());
    }
    let mut cut = vec![0x00, 0x00, 0x10];
    assert!(matches!(
        super::udp::Frames.decode(&mut cut).unwrap(),
        Decoded::NeedMore
    ));
    let mut bad = vec![0x01, 0, 0, 0xff];
    assert!(super::udp::Frames.decode(&mut bad).is_err());
}

struct Server {
    reader: Reader,
    sink: BoxWrite,
    sealer: Sealer,
}

impl Server {
    fn new(io: DuplexStream, pattern: &Pattern) -> Server {
        let (read, sink) = (Box::new(io) as BoxStream).into_split();
        Server {
            reader: Reader::new(read, &key()),
            sink,
            sealer: Sealer::new(&key(), USER, pattern.nonce.clone()),
        }
    }

    async fn send_session(&mut self, kind: u8, id: u32, payload: &[u8]) {
        let meta = Meta::Session {
            kind,
            id,
            seq: 0,
            status: 0,
            payload_len: payload.len() as u16,
            suffix_len: 3,
        };
        let mut out = Vec::new();
        self.sealer.seal(&mut out, &meta.encode()).unwrap();
        if !payload.is_empty() {
            self.sealer.seal(&mut out, payload).unwrap();
        }
        out.extend_from_slice(b"pad");
        self.sink.write_all(&out).await.unwrap();
    }

    async fn send_data(&mut self, id: u32, payload: &[u8]) {
        let meta = Meta::Data {
            kind: meta::DATA_S2C,
            id,
            seq: 1,
            unack: 0,
            window: 100,
            fragment: 0,
            prefix_len: 2,
            payload_len: payload.len() as u16,
            suffix_len: 1,
            low: meta::LowEntropyMeta::default(),
        };
        let mut out = Vec::new();
        self.sealer.seal(&mut out, &meta.encode()).unwrap();
        out.extend_from_slice(b"xx");
        self.sealer.seal(&mut out, payload).unwrap();
        out.push(b'z');
        self.sink.write_all(&out).await.unwrap();
    }
}

fn client(pattern: &str, factor: usize) -> (Arc<Underlay>, Server) {
    let (near, far) = tokio::io::duplex(1 << 20);
    let pattern = Arc::new(Pattern::parse(pattern).unwrap());
    let server = Server::new(far, &pattern);
    let underlay = Underlay::start(
        Box::new(near),
        &key(),
        USER,
        pattern,
        factor,
        &Default::default(),
    );
    (underlay, server)
}

fn session(underlay: &Arc<Underlay>, id: u32) -> MieruStream {
    let events = underlay.open_session(id).unwrap();
    MieruStream::new(id, underlay.clone(), events, meta::MAX_PDU)
}

#[tokio::test]
async fn the_first_write_carries_the_request_and_the_reply_is_stripped() {
    let (underlay, mut server) = client("", 1);
    let mut stream = session(&underlay, 9);
    stream.set_head(vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 80]);
    stream.write_all(b"GET /").await.unwrap();

    let opened = server.reader.segment().await.unwrap();
    assert!(matches!(
        opened.meta,
        Meta::Session {
            kind: meta::OPEN_REQUEST,
            id: 9,
            ..
        }
    ));
    assert_eq!(
        opened.payload,
        [
            5, 1, 0, 1, 127, 0, 0, 1, 0, 80, b'G', b'E', b'T', b' ', b'/'
        ]
    );

    server.send_session(meta::OPEN_RESPONSE, 9, &[]).await;
    server
        .send_data(9, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0, b'o', b'k'])
        .await;
    let mut got = [0u8; 2];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ok");

    stream.write_all(b"more").await.unwrap();
    let data = server.reader.segment().await.unwrap();
    assert!(matches!(
        data.meta,
        Meta::Data {
            kind: meta::DATA_C2S,
            id: 9,
            ..
        }
    ));
    assert_eq!(data.payload, b"more");

    server.send_session(meta::CLOSE_REQUEST, 9, &[]).await;
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    let ack = server.reader.segment().await.unwrap();
    assert!(matches!(
        ack.meta,
        Meta::Session {
            kind: meta::CLOSE_RESPONSE,
            id: 9,
            ..
        }
    ));
}

#[tokio::test]
async fn sessions_share_one_connection_and_keep_their_own_data() {
    let (underlay, mut server) = client("", 1);
    let mut first = session(&underlay, 1);
    let mut second = session(&underlay, 2);
    for stream in [&mut first, &mut second] {
        stream.set_head(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 1]);
        stream.write_all(b"x").await.unwrap();
    }
    let mut ids = Vec::new();
    for _ in 0..2 {
        let segment = server.reader.segment().await.unwrap();
        if let Meta::Session { id, .. } = segment.meta {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    assert_eq!(ids, [1, 2]);

    let reply = |tail: &[u8]| {
        let mut bytes = vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(tail);
        bytes
    };
    server.send_data(2, &reply(b"two")).await;
    server.send_data(1, &reply(b"one")).await;
    let mut got = [0u8; 3];
    first.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"one");
    second.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"two");

    drop(first);
    let closed = server.reader.segment().await.unwrap();
    assert!(matches!(
        closed.meta,
        Meta::Session {
            kind: meta::CLOSE_REQUEST,
            id: 1,
            ..
        }
    ));
    assert!(!underlay.has_session(1));
    assert!(underlay.has_session(2));
}

#[tokio::test]
async fn a_large_first_write_goes_as_data_after_an_empty_open() {
    let (underlay, mut server) = client("", 1);
    let mut stream = session(&underlay, 5);
    stream.set_head(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 1]);
    let big = vec![7u8; 5000];
    assert_eq!(stream.write(&big).await.unwrap(), 5000);
    let opened = server.reader.segment().await.unwrap();
    assert!(matches!(
        opened.meta,
        Meta::Session {
            kind: meta::OPEN_REQUEST,
            payload_len: 0,
            ..
        }
    ));
    let data = server.reader.segment().await.unwrap();
    assert_eq!(data.payload.len(), 5010);
    assert_eq!(&data.payload[..3], [5, 1, 0]);
}

#[tokio::test]
async fn a_low_entropy_pattern_sends_low_entropy_data() {
    use base64::Engine;
    let mut inner = Vec::new();
    inner.extend_from_slice(&[0x08, 0x03, 0x10, 0x05]);
    let mut pattern = vec![0x32, inner.len() as u8];
    pattern.extend_from_slice(&inner);
    let encoded = base64::engine::general_purpose::STANDARD.encode(pattern);
    let (underlay, mut server) = client(&encoded, 1);
    let mut stream = session(&underlay, 4);
    stream.set_head(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 1]);
    stream.write_all(b"hello low entropy").await.unwrap();
    let opened = server.reader.segment().await.unwrap();
    assert!(matches!(
        opened.meta,
        Meta::Session {
            kind: meta::OPEN_REQUEST,
            payload_len: 0,
            ..
        }
    ));
    let data = server.reader.segment().await.unwrap();
    assert!(matches!(
        data.meta,
        Meta::Data {
            kind: meta::DATA_C2S_LOW,
            ..
        }
    ));
    assert_eq!(&data.payload[10..], b"hello low entropy");
}

#[tokio::test]
async fn a_dead_connection_fails_the_session() {
    let (underlay, server) = client("", 1);
    let mut stream = session(&underlay, 3);
    stream.set_head(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 1]);
    stream.write_all(b"x").await.unwrap();
    drop(server);
    let mut buf = [0u8; 4];
    let err = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
    ));
    assert!(underlay.is_closed());
}

#[tokio::test]
async fn a_socks_error_reply_fails_the_read() {
    let (underlay, mut server) = client("", 1);
    let mut stream = session(&underlay, 6);
    stream.set_head(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 1]);
    stream.write_all(b"x").await.unwrap();
    server.reader.segment().await.unwrap();
    server.send_data(6, &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    let mut buf = [0u8; 4];
    let err = stream.read(&mut buf).await.unwrap_err();
    assert!(err.to_string().contains("error code 5"), "{err}");
}

fn definition(extra: Value) -> Result<(), String> {
    let mut base = json!({
        "name": "m", "type": "mieru", "server": "127.0.0.1", "port": 2999,
        "transport": "TCP", "username": USER, "password": PASSWORD,
    });
    if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            if value.is_null() {
                base.remove(key);
            } else {
                base.insert(key.clone(), value.clone());
            }
        }
    }
    let map = base.as_object().unwrap();
    match parse_proxy(map, &Capabilities::full()) {
        Ok(ProxyParse::Ok(def)) => {
            assert!(matches!(def.kind, ProxyKind::Mieru(_)));
            let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
            build_outbound(&def, &ctx).map(|_| ()).map_err(|err| {
                if err.is_unsupported() {
                    format!("unsupported: {err}")
                } else {
                    err.to_string()
                }
            })
        }
        Ok(_) => Err("quarantined".to_string()),
        Err(err) => Err(err.to_string()),
    }
}

#[test]
fn the_options_are_validated_like_mihomo() {
    assert!(definition(json!({})).is_ok());
    assert!(definition(json!({"port": null, "port-range": "2090-2099"})).is_ok());
    for (extra, needle) in [
        (json!({"port": null}), "port"),
        (json!({"port-range": "2090-2099"}), "same time"),
        (
            json!({"port": null, "port-range": "2099-2090"}),
            "less than",
        ),
        (json!({"port": null, "port-range": "0-2"}), "begin port"),
        (json!({"port": null, "port-range": "abc"}), "port-range"),
        (json!({"transport": "tcp"}), "transport"),
        (json!({"transport": null}), "transport"),
        (json!({"username": null}), "username"),
        (json!({"multiplexing": "MULTIPLEXING_HUGE"}), "multiplexing"),
        (json!({"handshake-mode": "HANDSHAKE_FAST"}), "handshake"),
        (json!({"traffic-pattern": "%%%"}), "traffic pattern"),
    ] {
        let err = definition(extra.clone()).unwrap_err();
        assert!(err.contains(needle), "{extra}: {err}");
    }
    definition(json!({"transport": "UDP"})).unwrap();
    definition(json!({"transport": "UDP", "dialer-proxy": "hop"})).unwrap();
}

#[tokio::test]
async fn an_underlay_made_across_a_reset_is_not_kept() {
    #[allow(clippy::disallowed_methods, reason = "a loopback server")]
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut sink = Vec::new();
                let _ = conn.read_to_end(&mut sink).await;
            });
        }
    });
    let proxy = json!({
        "name": "m", "type": "mieru", "server": "localhost", "port": port,
        "transport": "TCP", "username": USER, "password": PASSWORD,
        "handshake-mode": "HANDSHAKE_NO_WAIT",
    });
    let Ok(ProxyParse::Ok(def)) = parse_proxy(proxy.as_object().unwrap(), &Capabilities::full())
    else {
        panic!("does not parse");
    };
    let ProxyKind::Mieru(opts) = &def.kind else {
        unreachable!()
    };
    let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
    let node = Arc::new(super::construct(&def, opts, &ctx).unwrap());
    let held = HeldLookup::new();
    let straddling = {
        let (node, env) = (node.clone(), held.env());
        tokio::spawn(async move {
            let cx = DialCx::new(&env, Initiator::Direct, None);
            node.connect(&cx, &Address::new("example.test", 80)).await
        })
    };
    held.entered().await;
    node.reset_sessions();
    held.release();
    let outcome = crate::testing::settled(straddling).await;
    assert!(
        lock(&node.pool.underlays)
            .live
            .iter()
            .all(|underlay| underlay.is_closed()),
        "the underlay made before the reset is still pooled"
    );
    assert!(outcome.is_err());
}
