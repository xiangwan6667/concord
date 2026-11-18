#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert on fixed shapes"
)]

use bytes::BytesMut;
use concord_config::proxy::ProxyKind;
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use serde_json::{Value, json};

use super::frame::{Chunk, Opener, Scheme, Sealer};
use crate::ctx::BuildCtx;

fn round_trip(scheme: Scheme) {
    let mut sealer = Sealer::new(scheme, b"psk");
    let mut opener = Opener::new(scheme, b"psk");
    let mut wire = Vec::new();
    let mut expected = Vec::new();
    for size in [1usize, 700, 5000, 40_000] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        sealer.seal_stream(&mut wire, &data).unwrap();
        expected.extend_from_slice(&data);
    }
    sealer.seal_chunk(&mut wire, b"packet").unwrap();
    sealer.seal_zero(&mut wire).unwrap();

    let mut input = BytesMut::new();
    let mut plain = BytesMut::new();
    let mut got = Vec::new();
    let mut packets = Vec::new();
    let mut zero = false;
    for piece in wire.chunks(1301) {
        input.extend_from_slice(piece);
        while let Some(chunk) = opener.open(&mut input, &mut plain).unwrap() {
            match chunk {
                Chunk::Data => {
                    got.extend_from_slice(&plain);
                    packets.push(plain.split().to_vec());
                }
                Chunk::Zero => zero = true,
            }
        }
    }
    assert!(zero, "{scheme:?} lost the zero chunk");
    assert_eq!(packets.last().map(Vec::as_slice), Some(&b"packet"[..]));
    expected.extend_from_slice(b"packet");
    assert_eq!(got, expected, "{scheme:?}");
}

#[test]
fn every_scheme_round_trips_in_odd_sized_pieces() {
    for scheme in [Scheme::Chacha, Scheme::Aes, Scheme::V4] {
        round_trip(scheme);
    }
}

#[test]
fn a_wrong_key_is_rejected() {
    let mut sealer = Sealer::new(Scheme::Aes, b"one");
    let mut wire = Vec::new();
    sealer.seal_chunk(&mut wire, b"hello").unwrap();
    let mut opener = Opener::new(Scheme::Aes, b"two");
    let mut input = BytesMut::from(&wire[..]);
    assert!(opener.open(&mut input, &mut BytesMut::new()).is_err());
}

#[test]
fn the_first_v4_frame_is_padded_and_later_ones_are_not() {
    let mut sealer = Sealer::new(Scheme::V4, b"psk");
    let mut first = Vec::new();
    sealer.seal_chunk(&mut first, b"x").unwrap();
    let mut second = Vec::new();
    sealer.seal_chunk(&mut second, b"x").unwrap();
    assert!(first.len() >= 16 + 23 + 0x100 + 1 + 16);
    assert_eq!(second.len(), 23 + 1 + 16);
}

pub(super) fn build(extra: Value) -> Result<(), crate::ctx::BuildError> {
    let mut proxy =
        json!({"name": "s", "type": "snell", "server": "127.0.0.1", "port": 1, "psk": "p"});
    if let (Some(base), Some(more)) = (proxy.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        unreachable!()
    };
    let ProxyKind::Snell(opts) = &def.kind else {
        unreachable!()
    };
    super::build(&def, opts, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).map(drop)
}

#[test]
fn options_follow_the_go_adapter() {
    assert!(build(json!({})).is_ok());
    assert!(build(json!({"version": 5, "udp": true})).is_ok());
    assert!(build(json!({"version": 1, "udp": true})).is_err());
    assert!(build(json!({"version": 2, "udp": true})).is_err());
    assert!(build(json!({"version": 6})).is_err());
    assert!(build(json!({"version": 6, "psk": "snell-v6-test-psk-0123456789"})).is_ok());
    assert!(build(json!({"version": 7})).is_err());
    let unsupported = build(json!({"obfs-opts": {"mode": "restls"}}))
        .err()
        .unwrap();
    assert!(unsupported.is_unsupported());
    for version in [1, 4, 6] {
        assert!(
            build(
                json!({"version": version, "psk": "snell-jls-psk", "obfs-opts": {
                    "mode": "jls", "host": "a.test", "username": "name", "password": "secret"
                }})
            )
            .is_ok()
        );
    }
    for version in 1..=3 {
        let shadow = json!({"obfs-opts": {
            "mode": "shadow-tls", "host": "a.test", "password": "p", "version": version}});
        assert!(build(shadow).is_ok(), "shadow-tls v{version}");
    }
    assert!(
        !build(json!({"obfs-opts": {"mode": "bogus"}}))
            .err()
            .unwrap()
            .is_unsupported()
    );
}

#[test]
fn shadow_tls_options_are_read_as_the_ss_plugin_reads_them() {
    let proxy = json!({"name": "s", "type": "snell", "server": "127.0.0.1", "port": 1,
        "psk": "p", "client-fingerprint": "chrome",
        "obfs-opts": {"mode": "shadow-tls", "host": "a.test", "password": "pw",
            "skip-cert-verify": true}});
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        unreachable!()
    };
    let ProxyKind::Snell(opts) = &def.kind else {
        unreachable!()
    };
    let tls = opts.shadow_tls.as_ref().unwrap();
    assert_eq!(
        (tls.host.as_str(), tls.password.as_str(), tls.version),
        ("a.test", "pw", 2)
    );
    assert!(tls.skip_cert_verify);
    assert_eq!(tls.alpn, ["h2", "http/1.1"]);

    let wrong = json!({"name": "s", "type": "snell", "server": "h", "port": 1, "psk": "p",
        "obfs-opts": {"mode": "shadow-tls", "host": "a.test", "version": 4}});
    let Ok(ProxyParse::Quarantined { reason, .. }) =
        parse_proxy(wrong.as_object().unwrap(), &Capabilities::full())
    else {
        panic!("a shadow-tls version mihomo checks only when dialing sets the node aside");
    };
    assert!(reason.contains("shadow-tls version error: 4"), "{reason}");
}

async fn read_after_close_with(scheme: Scheme, wire: Vec<u8>) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    server.write_all(&wire).await.unwrap();
    drop(server);
    let mut stream = super::stream::SnellStream::new(client, scheme, b"psk");
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.map(|_| got)
}

async fn read_after_close(wire: Vec<u8>) -> std::io::Result<Vec<u8>> {
    read_after_close_with(Scheme::Aes, wire).await
}

#[tokio::test]
async fn eof_after_a_complete_header_still_requires_its_body() {
    for scheme in [Scheme::Chacha, Scheme::Aes, Scheme::V4] {
        let mut wire = Vec::new();
        let mut sealer = Sealer::new(scheme, b"psk");
        sealer.seal_chunk(&mut wire, b"\0hi").unwrap();
        let first_end = wire.len();
        sealer.seal_chunk(&mut wire, b"more").unwrap();
        assert_eq!(
            read_after_close_with(scheme, wire.clone()).await.unwrap(),
            b"himore"
        );
        assert_eq!(
            read_after_close_with(scheme, wire[..first_end].to_vec())
                .await
                .unwrap(),
            b"hi"
        );
        let header_len = if scheme == Scheme::V4 { 7 + 16 } else { 2 + 16 };
        let truncated = wire[..first_end + header_len].to_vec();
        let error = read_after_close_with(scheme, truncated).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}

#[tokio::test]
async fn a_close_between_chunks_ends_the_stream_and_one_inside_a_chunk_does_not() {
    let mut wire = Vec::new();
    Sealer::new(Scheme::Aes, b"psk")
        .seal_stream(&mut wire, b"\0hi")
        .unwrap();
    assert_eq!(read_after_close(wire.clone()).await.unwrap(), b"hi");
    wire.pop();
    let err = read_after_close(wire).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn the_halves_move_data_both_ways_and_shutdown_keeps_reading() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let stream: concord_common::BoxStream =
        Box::new(super::stream::SnellStream::new(client, Scheme::Aes, b"psk"));
    let (mut read, mut write) = stream.into_split();
    let reader = tokio::spawn(async move {
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        got
    });
    let mut reply = Vec::new();
    let mut sealer = Sealer::new(Scheme::Aes, b"psk");
    sealer.seal_stream(&mut reply, b"\0down").unwrap();
    server.write_all(&reply).await.unwrap();
    write.write_all(b"up").await.unwrap();
    write.shutdown().await.unwrap();
    let mut opener = Opener::new(Scheme::Aes, b"psk");
    let (mut input, mut plain) = (BytesMut::new(), BytesMut::new());
    let mut buf = [0u8; 256];
    let mut zero = false;
    while !zero {
        let n = server.read(&mut buf).await.unwrap();
        assert!(n > 0);
        input.extend_from_slice(&buf[..n]);
        while let Some(chunk) = opener.open(&mut input, &mut plain).unwrap() {
            zero |= matches!(chunk, Chunk::Zero);
        }
    }
    assert_eq!(&plain[..], b"up");
    let mut more = Vec::new();
    sealer.seal_zero(&mut more).unwrap();
    server.write_all(&more).await.unwrap();
    assert_eq!(reader.await.unwrap(), b"down");
}
