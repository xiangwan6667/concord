#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert on fixed shapes"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "the tests talk to loopback peers directly"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use concord_common::{Address, DialCx, Initiator, NodeDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use super::cipher::{PacketCipher, derive_key, hash_password};
use super::congestion::{Cubic, Rtt};
use super::frame::{self, DataFrame};
use super::meta::{self, Meta};
use super::packet::{Carrier, Inbound, PacketUnderlay, parse};
use super::pattern::{Fragment, LowEntropy, NonceKind, NoncePattern, Pattern};
use super::session::MAX_BACK_OFF;
use super::stream::MieruStream;
use super::underlay::Wire;
use crate::testing::{LoopbackHop, test_env};

const USER: &str = "mieru-user";
const PASSWORD: &str = "mieru-pass";
const REPLY: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

fn key() -> [u8; 32] {
    derive_key(&hash_password(PASSWORD, USER), 1_730_000_000)
}

fn pattern(kind: NonceKind, every_udp_packet: bool, low: Option<LowEntropy>) -> Arc<Pattern> {
    Arc::new(Pattern {
        fragment: Fragment {
            enable: false,
            max_sleep_ms: 0,
        },
        nonce: NoncePattern {
            kind,
            min_len: 8,
            max_len: 8,
            fixed: Vec::new(),
            every_udp_packet,
        },
        max_middle: 40,
        max_end: 255,
        low_entropy: low,
    })
}

fn bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

struct Peer {
    socket: UdpSocket,
    cipher: PacketCipher,
    client: Option<SocketAddr>,
}

impl Peer {
    async fn new(pattern: &Pattern) -> Peer {
        Peer {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            cipher: PacketCipher::new(&key(), USER, pattern.nonce.clone()),
            client: None,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    async fn recv_within(&mut self, wait: Duration) -> Option<Inbound> {
        let mut buf = vec![0u8; 2048];
        let (len, from) = tokio::time::timeout(wait, self.socket.recv_from(&mut buf))
            .await
            .ok()?
            .unwrap();
        self.client = Some(from);
        Some(parse(&self.cipher, &buf[..len]).unwrap())
    }

    async fn recv(&mut self) -> Inbound {
        self.recv_within(MAX_BACK_OFF * 3).await.unwrap()
    }

    async fn send(&self, datagram: &[u8]) {
        self.socket
            .send_to(datagram, self.client.unwrap())
            .await
            .unwrap();
    }

    fn session(&self, kind: u8, id: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        frame::write_session(
            &mut self.cipher.sealer(),
            kind,
            id,
            seq,
            payload,
            b"pad",
            &mut out,
        )
        .unwrap();
        out
    }

    fn data(&self, kind: u8, id: u32, seq: u32, unack: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let frame = DataFrame {
            kind,
            id,
            seq,
            unack,
            window: 4096,
            fragment: 0,
            prefix: b"xx",
            suffix: b"z",
            payload,
            low: None,
        };
        frame::write_data(&mut self.cipher.sealer(), &frame, &mut out).unwrap();
        out
    }
}

async fn client(peer: &Peer, pattern: Arc<Pattern>, id: u32) -> (Arc<PacketUnderlay>, MieruStream) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let underlay = PacketUnderlay::start(
        socket,
        peer.addr(),
        &key(),
        USER,
        pattern,
        1400,
        1,
        &Default::default(),
    );
    let events = underlay.open_session(id).unwrap();
    let stream = MieruStream::new(id, underlay.clone(), events, meta::MAX_PDU);
    (underlay, stream)
}

fn plain_pattern() -> Arc<Pattern> {
    pattern(NonceKind::Random, true, None)
}

#[tokio::test]
async fn datagrams_fit_the_mtu_and_parse_back() {
    let pattern = pattern(NonceKind::Random, true, None);
    let peer = Peer::new(&pattern).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let underlay = PacketUnderlay::start(
        socket,
        peer.addr(),
        &key(),
        USER,
        pattern.clone(),
        1400,
        1,
        &Default::default(),
    );
    assert_eq!(underlay.fragment_size(), 1400 - 88);
    for size in [1usize, 17, 500, 1311, 1312] {
        let payload = bytes(size);
        let datagram = underlay
            .data_datagram(meta::DATA_C2S, 7, 9, (3, 4096), 2, &payload)
            .unwrap();
        assert!(datagram.len() <= 1400, "{size}");
        let parsed = parse(&peer.cipher, &datagram).unwrap();
        assert_eq!(parsed.payload, payload);
        assert!(matches!(
            parsed.meta,
            Meta::Data {
                kind: meta::DATA_C2S,
                id: 7,
                seq: 9,
                unack: 3,
                window: 4096,
                fragment: 2,
                ..
            }
        ));
    }
    let full = underlay
        .data_datagram(meta::DATA_C2S, 1, 1, (0, 1), 0, &bytes(1312))
        .unwrap();
    assert_eq!(full.len(), 1400);
    let ack = underlay
        .data_datagram(meta::ACK_C2S, 1, 4, (5, 4000), 0, &[])
        .unwrap();
    let parsed = parse(&peer.cipher, &ack).unwrap();
    assert!(parsed.payload.is_empty());
    assert!(matches!(
        parsed.meta,
        Meta::Data {
            kind: meta::ACK_C2S,
            unack: 5,
            window: 4000,
            ..
        }
    ));
    let open = underlay
        .session_datagram(meta::OPEN_REQUEST, 7, 0, &bytes(1024))
        .unwrap();
    assert!(open.len() <= 1400);
    assert_eq!(parse(&peer.cipher, &open).unwrap().payload, bytes(1024));
    underlay.close();
}

#[tokio::test]
async fn low_entropy_datagrams_carry_whole_chunks() {
    let low = LowEntropy {
        mode: 2,
        rotation: 5,
    };
    let pattern = pattern(NonceKind::Random, true, Some(low));
    let peer = Peer::new(&pattern).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let underlay = PacketUnderlay::start(
        socket,
        peer.addr(),
        &key(),
        USER,
        pattern.clone(),
        1400,
        1,
        &Default::default(),
    );
    let size = underlay.fragment_size();
    assert_eq!(size, (1400 - 88) / 8 * 5);
    let payload = bytes(size);
    let datagram = underlay
        .data_datagram(meta::DATA_C2S, 3, 1, (0, 4096), 0, &payload)
        .unwrap();
    assert!(datagram.len() <= 1400);
    let parsed = parse(&peer.cipher, &datagram).unwrap();
    assert_eq!(parsed.payload, payload);
    assert!(matches!(
        parsed.meta,
        Meta::Data {
            kind: meta::DATA_C2S_LOW,
            ..
        }
    ));
    underlay.close();
}

fn printable(prefix: &[u8]) -> bool {
    prefix.iter().all(|byte| (0x20..=0x7e).contains(byte))
}

async fn nonces(every: bool) -> Vec<Vec<u8>> {
    let pattern = pattern(NonceKind::Printable, every, None);
    let peer = Peer::new(&pattern).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let underlay = PacketUnderlay::start(
        socket,
        peer.addr(),
        &key(),
        USER,
        pattern,
        1400,
        1,
        &Default::default(),
    );
    let nonces = (0..24)
        .map(|seq| {
            underlay
                .data_datagram(meta::DATA_C2S, 1, seq, (0, 1), 0, b"x")
                .unwrap()[..8]
                .to_vec()
        })
        .collect();
    underlay.close();
    nonces
}

#[tokio::test]
async fn the_nonce_pattern_applies_to_every_datagram_only_when_asked() {
    let first_only = nonces(false).await;
    assert!(printable(&first_only[0]));
    assert!(first_only[1..].iter().any(|nonce| !printable(nonce)));
    assert!(nonces(true).await.iter().all(|nonce| printable(nonce)));
}

async fn open(peer: &mut Peer, id: u32) -> Inbound {
    let opened = peer.recv().await;
    assert!(matches!(
        opened.meta,
        Meta::Session {
            kind: meta::OPEN_REQUEST,
            id: got,
            seq: 0,
            ..
        } if got == id
    ));
    let reply = peer.session(meta::OPEN_RESPONSE, id, 0, &REPLY);
    peer.send(&reply).await;
    opened
}

#[tokio::test]
async fn a_dialer_proxy_session_carries_the_datagrams() {
    let pattern = plain_pattern();
    let mut peer = Peer::new(&pattern).await;
    let hop = LoopbackHop::default();
    let carried = hop.datagrams.clone();
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let session = hop
        .associate_via("hop", &cx, &Address::from(peer.addr()))
        .await
        .unwrap();
    let underlay = PacketUnderlay::start(
        Carrier::Session(session),
        peer.addr(),
        &key(),
        USER,
        pattern,
        1400,
        1,
        &Default::default(),
    );
    let events = underlay.open_session(5).unwrap();
    let mut stream = MieruStream::new(5, underlay.clone(), events, meta::MAX_PDU);
    let client = tokio::spawn(async move {
        stream
            .handshake(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let mut got = [0u8; 4];
        stream.read_exact(&mut got).await.unwrap();
        got
    });
    open(&mut peer, 5).await;
    let reply = peer.data(meta::DATA_S2C, 5, 1, 1, b"pong");
    peer.send(&reply).await;
    assert_eq!(&client.await.unwrap(), b"pong");
    assert!(carried.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    underlay.close();
}

#[tokio::test]
async fn a_lossy_upload_arrives_whole_and_in_order() {
    let pattern = plain_pattern();
    let mut peer = Peer::new(&pattern).await;
    let (underlay, mut stream) = client(&peer, pattern, 21).await;
    let data = bytes(200_000);
    let writer = {
        let data = data.clone();
        tokio::spawn(async move {
            stream
                .handshake(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
                .await
                .unwrap();
            stream.write_all(&data).await.unwrap();
            stream.flush().await.unwrap();
            stream
        })
    };
    let opened = open(&mut peer, 21).await;
    assert_eq!(opened.payload, [5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
    let mut next = 1;
    let mut held = std::collections::BTreeMap::new();
    let mut got = Vec::new();
    let mut seen = 0u32;
    // A fixed drop period can lock onto the sender's retransmission cycle and drop the
    // same segment every time.
    let mut rng = 0x2545_f491_4f6c_dd1du64;
    while got.len() < data.len() {
        let segment = peer.recv().await;
        seen += 1;
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        if seen > 3 && rng.is_multiple_of(5) {
            continue;
        }
        if let Meta::Data {
            kind: meta::DATA_C2S,
            seq,
            ..
        } = segment.meta
        {
            held.insert(seq, segment.payload);
        }
        while let Some(chunk) = held.remove(&next) {
            got.extend_from_slice(&chunk);
            next += 1;
        }
        if !seen.is_multiple_of(4) {
            let ack = peer.data(meta::ACK_S2C, 21, 0, next, &[]);
            peer.send(&ack).await;
        }
    }
    assert!(got == data);
    drop(writer.await.unwrap());
    underlay.close();
}

#[tokio::test]
async fn a_lossy_reordered_download_is_delivered_in_order() {
    let pattern = plain_pattern();
    let mut peer = Peer::new(&pattern).await;
    let (underlay, mut stream) = client(&peer, pattern, 22).await;
    let data = bytes(200_000);
    let reader = tokio::spawn(async move {
        stream
            .handshake(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let mut got = vec![0u8; 200_000];
        stream.read_exact(&mut got).await.unwrap();
        got
    });
    open(&mut peer, 22).await;
    let chunks: Vec<&[u8]> = data.chunks(1000).collect();
    let last = chunks.len() as u32;
    let mut acked = 1u32;
    let mut round = 0u32;
    while acked <= last && !reader.is_finished() {
        round += 1;
        let upper = (acked + 64).min(last + 1);
        for seq in (acked..upper).rev() {
            if (seq + round).is_multiple_of(4) {
                continue;
            }
            let datagram = peer.data(meta::DATA_S2C, 22, seq, 1, chunks[seq as usize - 1]);
            peer.send(&datagram).await;
        }
        while let Some(segment) = peer.recv_within(Duration::from_millis(30)).await {
            if let Meta::Data { unack, .. } = segment.meta {
                acked = acked.max(unack);
            }
        }
    }
    assert!(reader.await.unwrap() == data);
    underlay.close();
}

#[tokio::test]
async fn closing_waits_for_the_data_and_the_peer_close_ends_the_read() {
    let pattern = plain_pattern();
    let mut peer = Peer::new(&pattern).await;
    let (underlay, mut stream) = client(&peer, pattern, 23).await;
    let task = tokio::spawn(async move {
        stream
            .handshake(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        stream.write_all(&bytes(5000)).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        rest
    });
    open(&mut peer, 23).await;
    let mut received = 0;
    let mut next = 1;
    loop {
        let segment = peer.recv().await;
        match segment.meta {
            Meta::Data {
                kind: meta::DATA_C2S,
                seq,
                ..
            } => {
                assert_eq!(seq, next);
                next += 1;
                received += segment.payload.len();
                let ack = peer.data(meta::ACK_S2C, 23, 0, next, &[]);
                peer.send(&ack).await;
            }
            Meta::Session {
                kind: meta::CLOSE_REQUEST,
                id: 23,
                seq,
                ..
            } => {
                assert_eq!(received, 5000);
                assert_eq!(seq, next);
                break;
            }
            _ => {}
        }
    }
    let reply = peer.session(meta::CLOSE_RESPONSE, 23, 1, &[]);
    peer.send(&reply).await;
    assert!(task.await.unwrap().is_empty());
    underlay.close();
}

#[tokio::test]
async fn the_peer_closing_delivers_what_came_before_and_is_answered() {
    let pattern = plain_pattern();
    let mut peer = Peer::new(&pattern).await;
    let (underlay, mut stream) = client(&peer, pattern, 24).await;
    let task = tokio::spawn(async move {
        stream
            .handshake(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        rest
    });
    open(&mut peer, 24).await;
    let data = peer.data(meta::DATA_S2C, 24, 1, 1, b"last words");
    peer.send(&data).await;
    let close = peer.session(meta::CLOSE_REQUEST, 24, 2, &[]);
    peer.send(&close).await;
    assert_eq!(task.await.unwrap(), b"last words");
    loop {
        let segment = peer.recv().await;
        if matches!(
            segment.meta,
            Meta::Session {
                kind: meta::CLOSE_RESPONSE,
                id: 24,
                ..
            }
        ) {
            break;
        }
    }
    underlay.close();
}

#[tokio::test]
async fn data_for_an_unknown_session_is_answered_with_a_close() {
    let pattern = plain_pattern();
    let mut peer = Peer::new(&pattern).await;
    let (underlay, mut stream) = client(&peer, pattern, 25).await;
    stream.set_head(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
    stream.write_all(b"hi").await.unwrap();
    peer.recv().await;
    let stray = peer.data(meta::DATA_S2C, 999, 5, 17, b"stray");
    peer.send(&stray).await;
    loop {
        let segment = peer.recv().await;
        if let Meta::Session {
            kind: meta::CLOSE_REQUEST,
            id: 999,
            seq,
            ..
        } = segment.meta
        {
            assert_eq!(seq, 17);
            break;
        }
    }
    underlay.close();
}

#[tokio::test]
async fn split_halves_move_data_both_ways_and_shutdown_leaves_the_read_half() {
    use concord_common::Stream;
    let pattern = plain_pattern();
    let mut peer = Peer::new(&pattern).await;
    let (underlay, mut stream) = client(&peer, pattern, 26).await;
    stream.set_head(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
    let (mut read, mut write) = Box::new(stream).into_split();
    let reader = tokio::spawn(async move {
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        got
    });
    let writer = tokio::spawn(async move {
        write.write_all(b"up").await.unwrap();
        write.shutdown().await.unwrap();
        write
    });
    let opened = open(&mut peer, 26).await;
    assert!(opened.payload.starts_with(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]));
    let _write = writer.await.unwrap();
    let tail = peer.data(meta::DATA_S2C, 26, 1, 1, b"down");
    peer.send(&tail).await;
    let close = peer.session(meta::CLOSE_REQUEST, 26, 2, &[]);
    peer.send(&close).await;
    assert_eq!(reader.await.unwrap(), b"down");
    underlay.close();
}

#[test]
fn the_congestion_window_follows_cubic() {
    let mut cubic = Cubic::new(16, 4096);
    assert_eq!(cubic.window(), 16);
    for _ in 0..100 {
        cubic.on_ack();
    }
    assert_eq!(cubic.window(), 116);
    cubic.on_loss();
    assert_eq!(cubic.window(), 81);
    cubic.on_timeout();
    assert_eq!(cubic.window(), 16);
}

#[test]
fn the_retransmission_timeout_follows_the_estimator() {
    let mut rtt = Rtt::new(Duration::from_millis(1), 1.5);
    assert_eq!(rtt.rto(), Duration::from_secs(2));
    rtt.update(Duration::from_millis(100));
    assert_eq!(rtt.rto(), Duration::from_micros(451_500));
    rtt.update(Duration::from_millis(100));
    assert_eq!(rtt.rto(), Duration::from_micros(376_500));
}
