use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{Address, BoxStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use super::h2mux::client_builder;
use super::padding::{encode_request, padding_conn, protocol_conn};
use super::wire::{Kind, client_stream, encode_stream_request, put_address, read_address};
use super::{MuxDialFn, MuxProtocol, SingMuxClient, SingMuxOptions};

#[tokio::test]
async fn addresses_round_trip_in_all_three_families() {
    for address in [
        Address::new("1.2.3.4", 80),
        Address::new("2001:db8::1", 443),
        Address::new("example.com", 65535),
    ] {
        let mut wire = Vec::new();
        put_address(&mut wire, &address).unwrap();
        let mut reader = wire.as_slice();
        assert_eq!(read_address(&mut reader).await.unwrap(), address);
        assert!(reader.is_empty());
    }
    let mut out = Vec::new();
    put_address(&mut out, &Address::new("example.com", 1)).unwrap();
    assert_eq!(&out[..2], [3, 11]);
}

#[test]
fn session_request_layout() {
    assert_eq!(encode_request(0, 2, false), [0, 2]);
    let padded = encode_request(1, 1, true);
    assert_eq!(&padded[..3], [1, 1, 1]);
    let len = usize::from(u16::from_be_bytes([padded[3], padded[4]]));
    assert!((256..768).contains(&len));
    assert_eq!(padded.len(), 5 + len);
    assert_eq!(encode_request(1, 0, false), [1, 0, 0]);
}

#[tokio::test]
async fn padding_applies_to_the_first_sixteen_frames_each_way() {
    let (a, b) = duplex(1 << 20);
    let mut near = padding_conn(Box::new(a));
    let mut far = padding_conn(Box::new(b));
    for i in 0..40u8 {
        let payload = vec![i; 100 + usize::from(i)];
        near.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        far.write_all(&payload).await.unwrap();
        let mut back = vec![0u8; payload.len()];
        near.read_exact(&mut back).await.unwrap();
        assert_eq!(back, payload);
    }
}

#[tokio::test]
async fn padded_frames_grow_the_wire_only_at_the_start() {
    let (a, mut raw) = duplex(1 << 20);
    let mut near = padding_conn(Box::new(a));
    for _ in 0..17 {
        near.write_all(b"x").await.unwrap();
    }
    near.flush().await.unwrap();
    drop(near);
    let mut wire = Vec::new();
    raw.read_to_end(&mut wire).await.unwrap();
    let mut at = 0;
    for _ in 0..16 {
        assert_eq!(&wire[at..at + 2], [0, 1]);
        let pad = usize::from(u16::from_be_bytes([wire[at + 2], wire[at + 3]]));
        assert!((256..768).contains(&pad));
        at += 4 + 1 + pad;
    }
    assert_eq!(&wire[at..], b"x");
}

#[tokio::test]
async fn the_request_leads_the_first_write() {
    let (a, mut raw) = duplex(1 << 16);
    let mut conn = protocol_conn(Box::new(a), vec![9, 9]);
    conn.write_all(b"first").await.unwrap();
    conn.write_all(b"second").await.unwrap();
    drop(conn);
    let mut wire = Vec::new();
    raw.read_to_end(&mut wire).await.unwrap();
    assert_eq!(wire, b"\x09\x09firstsecond");
}

#[tokio::test]
async fn split_padding_halves_move_data_both_ways_at_once() {
    let (a, b) = duplex(1 << 20);
    let (mut near_read, near_write) = padding_conn(Box::new(a)).into_split();
    let (mut far_read, far_write) = padding_conn(Box::new(b)).into_split();
    let payload = vec![7u8; 3000];
    let send = |mut write: concord_common::BoxWrite| {
        let payload = payload.clone();
        tokio::spawn(async move {
            for chunk in payload.chunks(100) {
                write.write_all(chunk).await.unwrap();
            }
            write.shutdown().await.unwrap();
        })
    };
    let (s1, s2) = (send(near_write), send(far_write));
    let (mut got_far, mut got_near) = (Vec::new(), Vec::new());
    let (r1, r2) = tokio::join!(
        far_read.read_to_end(&mut got_far),
        near_read.read_to_end(&mut got_near)
    );
    r1.unwrap();
    r2.unwrap();
    s1.await.unwrap();
    s2.await.unwrap();
    assert_eq!(got_far, payload);
    assert_eq!(got_near, payload);
}

#[tokio::test]
async fn split_protocol_conn_still_leads_with_the_request() {
    let (a, b) = duplex(1 << 16);
    let (mut read, mut write) = protocol_conn(Box::new(a), vec![9, 9]).into_split();
    let (mut far_read, mut far_write) = tokio::io::split(b);
    let writer = tokio::spawn(async move {
        write.write_all(b"hi").await.unwrap();
        write.shutdown().await.unwrap();
    });
    far_write.write_all(b"yo").await.unwrap();
    far_write.shutdown().await.unwrap();
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"yo");
    let mut wire = Vec::new();
    far_read.read_to_end(&mut wire).await.unwrap();
    assert_eq!(wire, b"\x09\x09hi");
    writer.await.unwrap();
}

#[tokio::test]
async fn split_client_stream_reads_after_its_write_half_shuts() {
    let (a, b) = duplex(1 << 16);
    let stream = client_stream(Box::new(a), Kind::Tcp, &Address::new("1.2.3.4", 80)).unwrap();
    let (mut read, mut write) = (Box::new(stream) as BoxStream).into_split();
    let (mut far_read, mut far_write) = tokio::io::split(b);
    let writer = tokio::spawn(async move {
        write.write_all(b"ping").await.unwrap();
        write.shutdown().await.unwrap();
    });
    let mut wire = Vec::new();
    far_read.read_to_end(&mut wire).await.unwrap();
    assert!(wire.ends_with(b"ping"));
    writer.await.unwrap();
    far_write.write_all(&[0]).await.unwrap();
    far_write.write_all(b"pong").await.unwrap();
    far_write.shutdown().await.unwrap();
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"pong");
}

#[tokio::test]
async fn a_read_before_any_write_gets_the_request_out_with_a_zero_length_write() {
    let (a, mut far) = duplex(1 << 16);
    let destination = Address::new("1.2.3.4", 25);
    let mut stream = client_stream(Box::new(a), Kind::Tcp, &destination).unwrap();
    assert_eq!(stream.write(&[]).await.unwrap(), 0);
    let request = encode_stream_request(Kind::Tcp, &destination).unwrap();
    let mut wire = vec![0u8; request.len()];
    tokio::time::timeout(Duration::from_secs(5), far.read_exact(&mut wire))
        .await
        .expect("the request did not leave on a zero-length write")
        .unwrap();
    assert_eq!(wire, request);
    far.write_all(b"\x00220 ready").await.unwrap();
    let mut banner = [0u8; 9];
    stream.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"220 ready");
    assert_eq!(stream.write(&[]).await.unwrap(), 0);
    stream.write_all(b"EHLO").await.unwrap();
    drop(stream);
    let mut rest = Vec::new();
    far.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"EHLO");
}

#[tokio::test]
async fn h2mux_advertises_the_sing_mux_frame_size_and_go_connection_window() {
    let (near, mut far) = duplex(1 << 16);
    let observed = tokio::spawn(async move { crate::h2io::tests::client_settings(&mut far).await });
    let io = Box::new(near) as BoxStream;
    let (sender, conn) = client_builder()
        .handshake::<_, bytes::Bytes>(io)
        .await
        .unwrap();
    let driver = tokio::spawn(conn);
    let (settings, update) = observed.await.unwrap();
    assert_eq!(settings.get(&2), Some(&0));
    assert_eq!(settings.get(&4), Some(&(4 << 20)));
    assert_eq!(settings.get(&5), Some(&(32 << 10)));
    assert_eq!(update, 1 << 30);
    drop(sender);
    driver.abort();
}

#[tokio::test]
async fn a_closed_client_dials_a_new_session_for_the_next_stream() {
    let peers = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let dial: MuxDialFn = {
        let peers = peers.clone();
        std::sync::Arc::new(move |_| {
            let (near, far) = duplex(1 << 16);
            lock(&peers).push(far);
            Box::pin(async move { Ok(Box::new(near) as BoxStream) })
        })
    };
    let options = SingMuxOptions {
        protocol: MuxProtocol::Smux,
        ..SingMuxOptions::default()
    };
    let client = SingMuxClient::new(options, dial, Default::default());
    let target = Address::new("1.2.3.4", 80);
    client.connect_tcp(&target).await.unwrap();
    client.close().await;
    client.connect_tcp(&target).await.unwrap();
    assert_eq!(lock(&peers).len(), 2);
}
