use std::io::IoSlice;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::wire::{
    FLAG_FIN, FLAG_PSH, FLAG_SYN, L4Checksum, PROTO_TCP, Parsed, TcpHeader, TcpOptions, emit_tcp,
    finish, parse_packet, parse_tcp, pseudo_header, sum_bytes,
};
use crate::{Admit, Congestion, Egress, NetStream, StackConfig, TcpInput, TcpStack};

mod zero_window;

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn receive_lifetimes_end_at_the_last_fin_before_connection_metadata() {
    let mut link = Link::new(0, 0);
    let (first, server_addr) = addrs();
    let second = SocketAddr::new(first.ip(), first.port() + 1);
    let mut a = link
        .client
        .connect(first, server_addr, Congestion::Cubic)
        .unwrap();
    let mut b = link
        .client
        .connect(second, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| l.accepted.len() == 2, 10).await;
    assert_eq!(link.server.receive_epoch(), 0);
    a.write_all(b"before-fin").await.unwrap();
    a.shutdown().await.unwrap();
    drive(
        &mut link,
        |l| {
            l.delivered.iter().any(|(to_server, packet)| {
                *to_server
                    && matches!(parse_packet(packet), Ok(Parsed::Packet(view))
                if parse_tcp(view.l4).is_ok_and(|seg| seg.has(FLAG_FIN)))
            })
        },
        10,
    )
    .await;
    assert_eq!(
        link.server.receive_epoch(),
        0,
        "the other receiver is still open"
    );
    b.shutdown().await.unwrap();
    drive(&mut link, |l| l.server.receive_epoch() == 1, 10).await;
    assert_eq!(
        link.server.len(),
        2,
        "half-closed connections still own metadata"
    );
    let fins: Vec<_> = link
        .delivered
        .iter()
        .filter(|(to_server, packet)| {
            *to_server
                && matches!(parse_packet(packet), Ok(Parsed::Packet(view))
            if parse_tcp(view.l4).is_ok_and(|seg| seg.has(FLAG_FIN)))
        })
        .map(|(_, packet)| packet.clone())
        .collect();
    for packet in fins {
        link.deliver(true, &packet);
    }
    assert_eq!(
        link.server.receive_epoch(),
        1,
        "duplicate FINs do not retire twice"
    );
    link.server.shutdown();
    assert_eq!(link.server.receive_epoch(), 1);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn receive_lifetimes_retire_on_unestablished_cancel_and_shutdown() {
    for cancel in [true, false] {
        let mut stack = TcpStack::new(StackConfig::default());
        let (client, server) = addrs();
        let stream = stack.connect(client, server, Congestion::Cubic).unwrap();
        let mut wire = Wire::default();
        stack.poll(&mut wire);
        if cancel {
            drop(stream);
            stack.poll(&mut wire);
        } else {
            stack.shutdown();
            drop(stream);
        }
        assert_eq!(stack.receive_epoch(), 1);
        stack.poll(&mut wire);
        stack.shutdown();
        assert_eq!(stack.receive_epoch(), 1);
    }
}

#[derive(Default)]
struct Wire {
    packets: Vec<Vec<u8>>,
    limit: Option<usize>,
    segment_limit: usize,
    segmented: usize,
    /// Takes payloads in place and completes checksums as an offloading device does.
    in_place: bool,
    placed: usize,
    mtu: Option<usize>,
}

impl Egress for Wire {
    fn send(&mut self, build: &mut dyn FnMut(&mut [u8]) -> Option<usize>) -> bool {
        if self.limit.is_some_and(|limit| self.packets.len() >= limit) {
            return false;
        }
        let mut buf = vec![0u8; self.mtu.unwrap_or(2048)];
        let Some(n) = build(&mut buf) else {
            assert!(
                self.mtu.is_none(),
                "the stack built a packet larger than the MTU"
            );
            return true;
        };
        buf.truncate(n);
        if self.in_place {
            buf = complete(buf);
        }
        self.packets.push(buf);
        true
    }

    fn checksum(&self) -> L4Checksum {
        if self.in_place {
            L4Checksum::Pseudo
        } else {
            L4Checksum::Full
        }
    }

    fn send_in_place(&mut self, segment: u16, head: &[u8], payload: &[IoSlice<'_>]) -> bool {
        if !self.in_place || self.limit.is_some_and(|limit| self.packets.len() >= limit) {
            return false;
        }
        self.placed += 1;
        let mut frame = head.to_vec();
        for slice in payload {
            frame.extend_from_slice(slice);
        }
        if segment > 0 {
            self.segmented += 1;
            self.packets.extend(segments(&frame, usize::from(segment)));
        } else {
            self.packets.push(complete(frame));
        }
        true
    }

    fn segment_limit(&self) -> usize {
        self.segment_limit
    }

    fn send_segmented(
        &mut self,
        segment: u16,
        build: &mut dyn FnMut(&mut [u8]) -> Option<usize>,
    ) -> bool {
        let mut buf = vec![0u8; 65_535];
        if let Some(n) = build(&mut buf) {
            self.segmented += 1;
            self.packets
                .extend(segments(&buf[..n], usize::from(segment)));
        }
        true
    }
}

/// What a device with TCP segmentation offload makes of a frame.
fn segments(frame: &[u8], segment: usize) -> Vec<Vec<u8>> {
    let Ok(Parsed::Packet(view)) = parse_packet(frame) else {
        panic!("stack emitted a bad frame");
    };
    let ip_len = frame.len() - view.l4.len();
    let tcp_len = usize::from(view.l4[12] >> 4) * 4;
    let payload = &view.l4[tcp_len..];
    let seq = u32::from_be_bytes(view.l4[4..8].try_into().unwrap());
    let chunks = payload.len().div_ceil(segment);
    payload
        .chunks(segment)
        .enumerate()
        .map(|(i, chunk)| {
            let mut out = [&frame[..ip_len + tcp_len], chunk].concat();
            let total = out.len();
            if view.src.is_ipv4() {
                out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
                out[10..12].fill(0);
                let sum = finish(sum_bytes(0, &out[..ip_len]));
                out[10..12].copy_from_slice(&sum.to_be_bytes());
            } else {
                out[4..6].copy_from_slice(&((total - ip_len) as u16).to_be_bytes());
            }
            let tcp = &mut out[ip_len..];
            tcp[4..8].copy_from_slice(&seq.wrapping_add((i * segment) as u32).to_be_bytes());
            if i + 1 < chunks {
                tcp[13] &= !(FLAG_FIN | FLAG_PSH);
            }
            tcp[16..18].fill(0);
            let pseudo = pseudo_header(view.src, view.dst, PROTO_TCP, tcp.len());
            let sum = finish(sum_bytes(pseudo, tcp));
            tcp[16..18].copy_from_slice(&sum.to_be_bytes());
            out
        })
        .collect()
}

fn complete(mut packet: Vec<u8>) -> Vec<u8> {
    let Ok(Parsed::Packet(view)) = parse_packet(&packet) else {
        panic!("stack emitted a bad packet");
    };
    let (src, dst, l4_start) = (view.src, view.dst, packet.len() - view.l4.len());
    let tcp = &mut packet[l4_start..];
    tcp[16..18].fill(0);
    let sum = finish(sum_bytes(
        pseudo_header(src, dst, PROTO_TCP, tcp.len()),
        tcp,
    ));
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    packet
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Two stacks wired back to back, with per-direction loss and reordering.
struct Link {
    client: TcpStack,
    server: TcpStack,
    to_server: Wire,
    to_client: Wire,
    rng: XorShift,
    loss_per_mille: u64,
    reorder_per_mille: u64,
    held: Vec<(bool, Vec<u8>)>,
    accepted: Vec<NetStream>,
    delivered: Vec<(bool, Vec<u8>)>,
    /// Hands the server each step's segments as one batch, as the TUN driver does.
    batched: bool,
}

impl Link {
    fn new(loss_per_mille: u64, reorder_per_mille: u64) -> Link {
        Link {
            client: TcpStack::new(StackConfig::default()),
            server: TcpStack::new(StackConfig::default()),
            to_server: Wire::default(),
            to_client: Wire::default(),
            rng: XorShift(0x2545_f491_4f6c_dd1d),
            loss_per_mille,
            reorder_per_mille,
            held: Vec::new(),
            accepted: Vec::new(),
            delivered: Vec::new(),
            batched: false,
        }
    }

    fn deliver_batch(&mut self, packets: &[Vec<u8>]) {
        let mut gather = crate::Gather::default();
        for packet in packets {
            let Ok(Parsed::Packet(view)) = parse_packet(packet) else {
                panic!("stack emitted a bad packet");
            };
            self.delivered.push((true, packet.clone()));
            let result = self.server.input_gathered(
                view.src,
                view.dst,
                view.l4,
                &mut self.to_client,
                |_, _| Admit::Accept(7),
                &mut gather,
            );
            assert!(!matches!(result, TcpInput::Dropped(_)), "{result:?}");
        }
        self.server.flush(&mut gather);
    }

    fn deliver(&mut self, to_server: bool, packet: &[u8]) {
        let Ok(Parsed::Packet(view)) = parse_packet(packet) else {
            panic!("stack emitted a bad packet");
        };
        assert!(crate::wire::tcp_checksum_ok(view.src, view.dst, view.l4));
        self.delivered.push((to_server, packet.to_vec()));
        let (stack, egress) = if to_server {
            (&mut self.server, &mut self.to_client)
        } else {
            (&mut self.client, &mut self.to_server)
        };
        let result = stack.input(view.src, view.dst, view.l4, egress, |_, _| Admit::Accept(7));
        assert!(!matches!(result, TcpInput::Dropped(_)), "{result:?}");
    }

    /// Moves packets once in each direction; returns whether anything moved.
    fn step(&mut self) -> bool {
        self.client.poll(&mut self.to_server);
        self.server.poll(&mut self.to_client);
        while let Some(accepted) = self.server.take_accepted() {
            assert_eq!(accepted.tag, 7);
            self.accepted.push(accepted.stream);
        }
        let mut moved = false;
        for (to_server, wire) in [
            (true, std::mem::take(&mut self.to_server.packets)),
            (false, std::mem::take(&mut self.to_client.packets)),
        ] {
            let mut batch = Vec::new();
            for packet in wire {
                moved = true;
                let roll = self.rng.next() % 1000;
                let is_syn = parse_packet(&packet)
                    .ok()
                    .and_then(|p| match p {
                        Parsed::Packet(view) => parse_tcp(view.l4).ok(),
                        Parsed::Fragment(_) => None,
                    })
                    .is_some_and(|seg| seg.has(crate::wire::FLAG_SYN));
                if roll < self.loss_per_mille && !is_syn {
                    continue;
                }
                if roll < self.loss_per_mille + self.reorder_per_mille {
                    self.held.push((to_server, packet));
                    continue;
                }
                if to_server && self.batched {
                    batch.push(packet);
                } else {
                    self.deliver(to_server, &packet);
                }
            }
            self.deliver_batch(&batch);
        }
        if !moved {
            for (to_server, packet) in std::mem::take(&mut self.held) {
                moved = true;
                self.deliver(to_server, &packet);
            }
        }
        moved
    }
}

fn addrs() -> (SocketAddr, SocketAddr) {
    (
        "10.0.0.2:40000".parse().unwrap(),
        "93.184.216.34:443".parse().unwrap(),
    )
}

async fn drive(link: &mut Link, mut done: impl FnMut(&mut Link) -> bool, secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let moved = link.step();
        tokio::task::yield_now().await;
        if done(link) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "link did not settle"
        );
        if !moved {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// A connection takes only so much ahead of what it sends, so a relay reads while it writes.
async fn send_and_receive(stream: NetStream, data: Vec<u8>) -> Vec<u8> {
    let (mut reader, mut writer) = stream.into_split();
    let write = async move {
        writer.write_all(&data).await.unwrap();
        writer.shutdown().await.unwrap();
    };
    let read = async move {
        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        got
    };
    tokio::join!(write, read).1
}

async fn transfer(loss: u64, reorder: u64, len: usize) {
    transfer_with(Link::new(loss, reorder), len).await;
}

async fn transfer_with(mut link: Link, len: usize) -> Link {
    let (client_addr, server_addr) = addrs();
    let client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let server = link.accepted.pop().unwrap();
    assert_eq!(server.peer_addr(), client_addr);
    assert_eq!(server.local_addr(), server_addr);

    let up = pattern(len, 1);
    let down = pattern(len, 2);
    let up_task = tokio::spawn(send_and_receive(client, up.clone()));
    let down_task = tokio::spawn(send_and_receive(server, down.clone()));
    drive(
        &mut link,
        |_| up_task.is_finished() && down_task.is_finished(),
        60,
    )
    .await;
    assert!(
        down_task.await.unwrap() == up,
        "server received the client's bytes"
    );
    assert!(
        up_task.await.unwrap() == down,
        "client received the server's bytes"
    );
    drive(
        &mut link,
        |l| l.client.is_empty() && l.server.is_empty(),
        10,
    )
    .await;
    link
}

#[tokio::test(flavor = "current_thread")]
async fn frames_the_device_segments_survive_loss_and_reordering() {
    let mut link = Link::new(20, 20);
    link.to_server.segment_limit = 16 << 10;
    link.to_client.segment_limit = 16 << 10;
    transfer_with(link, 1 << 20).await;
}

#[tokio::test(flavor = "current_thread")]
async fn payloads_handed_over_in_place_survive_loss_and_reordering() {
    for segment_limit in [0, 16 << 10] {
        let mut link = Link::new(20, 20);
        for wire in [&mut link.to_server, &mut link.to_client] {
            wire.in_place = true;
            wire.segment_limit = segment_limit;
        }
        let link = transfer_with(link, 1 << 20).await;
        assert!(link.to_server.placed > 0 && link.to_client.placed > 0);
        assert_eq!(link.to_server.segmented > 0, segment_limit > 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_sender_hands_the_device_frames_of_several_segments() {
    let mut link = Link::new(0, 0);
    link.to_server.segment_limit = 64 << 10;
    let (client_addr, server_addr) = addrs();
    let mut client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    client.write_all(&pattern(256 << 10, 3)).await.unwrap();
    let before = link.to_server.packets.len();
    link.client.poll(&mut link.to_server);
    let sizes = payloads(&link.to_server)[before..].to_vec();
    assert_eq!(
        link.to_server.segmented, 1,
        "the initial window goes out as one frame"
    );
    assert_eq!(sizes.len(), 10);
    assert!(sizes.iter().all(|&n| n == sizes[0]), "{sizes:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn bulk_transfer_both_ways_and_close() {
    transfer(0, 0, 3 << 20).await;
}

#[tokio::test(flavor = "current_thread")]
async fn transfer_survives_reordering() {
    transfer(0, 30, 1 << 20).await;
}

#[tokio::test(flavor = "current_thread")]
async fn transfer_survives_loss_and_reordering() {
    transfer(20, 20, 1 << 20).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_lost_segment_resent_while_its_sender_holds_out_of_order_data_fits_the_mtu() {
    let mut link = Link::new(20, 20);
    let mtu = StackConfig::default().tcp.mtu;
    link.to_server.mtu = Some(mtu);
    link.to_client.mtu = Some(mtu);
    transfer_with(link, 1 << 20).await;
}

#[tokio::test(flavor = "current_thread")]
async fn transfer_survives_heavy_loss() {
    transfer(100, 0, 256 << 10).await;
}

#[tokio::test(flavor = "current_thread")]
async fn segments_for_no_connection_get_a_reset() {
    let mut link = Link::new(0, 0);
    let (client_addr, server_addr) = addrs();
    let _client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    link.client.poll(&mut link.to_server);
    let syn = link.to_server.packets.pop().unwrap();
    let Ok(Parsed::Packet(view)) = parse_packet(&syn) else {
        panic!()
    };
    let mut out = Wire::default();
    let result = link
        .server
        .input(view.src, view.dst, view.l4, &mut out, |_, _| Admit::Reject);
    assert_eq!(result, TcpInput::Reset);
    let reply = parse_packet(&out.packets[0]).unwrap();
    let Parsed::Packet(reply) = reply else {
        panic!()
    };
    let seg = parse_tcp(reply.l4).unwrap();
    assert!(seg.has(crate::wire::FLAG_RST));
    link.deliver(false, &out.packets[0]);
    assert!(link.client.is_empty(), "a refused connection is torn down");
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_with_unread_data_resets() {
    let mut link = Link::new(0, 0);
    let (client_addr, server_addr) = addrs();
    let mut client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let server = link.accepted.pop().unwrap();
    client.write_all(b"unread").await.unwrap();
    for _ in 0..20 {
        link.step();
    }
    drop(server);
    for _ in 0..20 {
        link.step();
    }
    let mut buf = [0u8; 8];
    let err = client.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(client.write_all(b"x").await.is_err());
    assert!(link.server.is_empty());
    for _ in 0..5 {
        link.step();
    }
    assert!(link.client.is_empty());
}

#[test]
fn egress_backpressure_resumes_without_loss() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut link = Link::new(0, 0);
        link.to_client.limit = Some(3);
        link.to_server.limit = Some(3);
        let (client_addr, server_addr) = addrs();
        let mut client = link
            .client
            .connect(client_addr, server_addr, Congestion::Cubic)
            .unwrap();
        drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
        let mut server = link.accepted.pop().unwrap();
        let data = pattern(400_000, 9);
        let writer = {
            let data = data.clone();
            tokio::spawn(async move {
                server.write_all(&data).await.unwrap();
                server.shutdown().await.unwrap();
            })
        };
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.unwrap();
            got
        });
        drive(&mut link, |_| reader.is_finished(), 30).await;
        writer.await.unwrap();
        assert!(reader.await.unwrap() == data);
    });
}

#[tokio::test(flavor = "current_thread")]
async fn direct_io_moves_bytes_between_the_stack_and_a_socket() {
    use concord_common::DirectIo;
    use std::future::poll_fn;
    use std::task::Poll;

    let mut link = Link::new(0, 0);
    let (client_addr, server_addr) = addrs();
    let mut client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let mut server = link.accepted.pop().unwrap();
    let (mut near, mut far) = concord_test_support::tcp_pair().await;

    let up = pattern(700_000, 3);
    let down = pattern(900_000, 4);
    let client_task = {
        let up = up.clone();
        tokio::spawn(async move {
            client.write_all(&up).await.unwrap();
            client.shutdown().await.unwrap();
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.unwrap();
            got
        })
    };
    let far_task = {
        let down = down.clone();
        tokio::spawn(async move {
            let (mut reader, mut writer) = far.split();
            let mut got = Vec::new();
            let (read, wrote) = tokio::join!(reader.read_to_end(&mut got), async {
                writer.write_all(&down).await?;
                writer.shutdown().await
            });
            read.unwrap();
            wrote.unwrap();
            got
        })
    };

    let (mut sent, mut received) = (0, 0);
    let (mut up_done, mut down_done) = (false, false);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !(up_done && down_done && client_task.is_finished() && far_task.is_finished()) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "direct relay stalled"
        );
        let moved = link.step();
        let mut progressed = false;
        if !up_done {
            match poll_fn(|cx| Poll::Ready(server.poll_send_to(cx, &near))).await {
                Poll::Ready(Ok(0)) => {
                    up_done = true;
                    near.shutdown().await.unwrap();
                }
                Poll::Ready(Ok(n)) => {
                    sent += n;
                    progressed = true;
                }
                Poll::Ready(Err(err)) => panic!("send: {err}"),
                Poll::Pending => {}
            }
        }
        if !down_done {
            match poll_fn(|cx| Poll::Ready(server.poll_recv_from(cx, &near))).await {
                Poll::Ready(Ok(0)) => {
                    down_done = true;
                    server.shutdown().await.unwrap();
                }
                Poll::Ready(Ok(n)) => {
                    received += n;
                    progressed = true;
                }
                Poll::Ready(Err(err)) => panic!("recv: {err}"),
                Poll::Pending => {}
            }
        }
        tokio::task::yield_now().await;
        if !moved && !progressed {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    assert_eq!((sent, received), (up.len(), down.len()));
    assert!(
        far_task.await.unwrap() == up,
        "the socket got the client's bytes"
    );
    assert!(
        client_task.await.unwrap() == down,
        "the client got the socket's bytes"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_attached_socket_is_served_by_the_stack_until_both_sides_close() {
    attached_until_both_sides_close(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_batch_of_segments_reaches_an_attached_socket_in_order() {
    attached_until_both_sides_close(true).await;
}

async fn attached_until_both_sides_close(batched: bool) {
    use concord_common::DirectIo;
    use std::task::{Context, Poll};

    let mut link = Link::new(10, 10);
    link.batched = batched;
    let (client_addr, server_addr) = addrs();
    let mut client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let mut server = link.accepted.pop().unwrap();
    let (near, mut far) = concord_test_support::tcp_pair().await;
    let mut attached = server
        .attach(near)
        .expect("a fresh connection takes a socket");

    let up = pattern(700_000, 5);
    let down = pattern(900_000, 6);
    let client_task = {
        let up = up.clone();
        tokio::spawn(async move {
            client.write_all(&up).await.unwrap();
            client.shutdown().await.unwrap();
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.unwrap();
            got
        })
    };
    let far_task = {
        let down = down.clone();
        tokio::spawn(async move {
            let (mut reader, mut writer) = far.split();
            let mut got = Vec::new();
            let (read, wrote) = tokio::join!(reader.read_to_end(&mut got), async {
                writer.write_all(&down).await?;
                writer.shutdown().await
            });
            read.unwrap();
            wrote.unwrap();
            got
        })
    };
    let mut outcome = None;
    drive(
        &mut link,
        |_| {
            let waker = futures_util::task::noop_waker();
            if let Poll::Ready(result) = attached.poll_done(&mut Context::from_waker(&waker)) {
                outcome = Some(result.map_err(|err| err.kind()));
            }
            outcome.is_some() && client_task.is_finished() && far_task.is_finished()
        },
        30,
    )
    .await;
    assert_eq!(outcome, Some(Ok(())));
    assert_eq!(attached.moved(), (up.len() as u64, down.len() as u64));
    assert!(
        far_task.await.unwrap() == up,
        "the socket got the client's bytes"
    );
    assert!(
        client_task.await.unwrap() == down,
        "the client got the socket's bytes"
    );
    drop(server);
}

async fn run_for(link: &mut Link, time: Duration) {
    let until = tokio::time::Instant::now() + time;
    while tokio::time::Instant::now() < until {
        link.step();
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn socket_pair(buffer: Option<usize>) -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    if let Some(size) = buffer {
        socket2::SockRef::from(&listener)
            .set_recv_buffer_size(size)
            .unwrap();
    }
    #[allow(clippy::disallowed_methods, reason = "a loopback test pair")]
    let connecting = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
    let (near, (far, _)) = tokio::try_join!(connecting, listener.accept()).unwrap();
    if let Some(size) = buffer {
        socket2::SockRef::from(&near)
            .set_send_buffer_size(size)
            .unwrap();
    }
    (near, far)
}

struct AttachmentTicket(std::sync::Arc<std::sync::atomic::AtomicUsize>);

struct ConnectionOwner(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl crate::FlowOwner for ConnectionOwner {
    fn acquire(&self, _local: SocketAddr, _remote: SocketAddr) -> Option<Box<dyn Send + Sync>> {
        Some(Box::new(AttachmentTicket(std::sync::Arc::clone(&self.0))))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn connection_registration_is_released_on_reset_with_a_live_stream() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let released = Arc::<AtomicUsize>::default();
    let mut link = Link::new(0, 0);
    link.client
        .set_flow_owner(Arc::new(ConnectionOwner(Arc::clone(&released))));
    let (local, remote) = addrs();
    let stream = link
        .client
        .connect(local, remote, Congestion::Cubic)
        .unwrap();
    assert_eq!(released.load(Ordering::Relaxed), 0);
    link.client.poll(&mut link.to_server);
    let syn = link.to_server.packets.pop().unwrap();
    let Parsed::Packet(view) = parse_packet(&syn).unwrap() else {
        panic!("the SYN is an IP packet");
    };
    let mut reset = Wire::default();
    assert_eq!(
        link.server
            .input(view.src, view.dst, view.l4, &mut reset, |_, _| {
                Admit::Reject
            }),
        TcpInput::Reset
    );
    link.deliver(false, &reset.packets.pop().unwrap());
    assert!(link.client.is_empty());
    assert_eq!(released.load(Ordering::Relaxed), 1);
    drop(stream);
    assert_eq!(released.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_a_stack_releases_connection_registrations() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let released = Arc::<AtomicUsize>::default();
    let mut stack = TcpStack::new(StackConfig::default());
    stack.set_flow_owner(Arc::new(ConnectionOwner(Arc::clone(&released))));
    let (local, remote) = addrs();
    let stream = stack.connect(local, remote, Congestion::Cubic).unwrap();
    assert_eq!(released.load(Ordering::Relaxed), 0);
    drop(stack);
    assert_eq!(released.load(Ordering::Relaxed), 1);
    drop(stream);
    assert_eq!(released.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn duplex_half_close_releases_passive_connection_registration() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let released = Arc::<AtomicUsize>::default();
    let mut link = Link::new(0, 0);
    link.server
        .set_flow_owner(Arc::new(ConnectionOwner(Arc::clone(&released))));
    let _link = transfer_with(link, 4096).await;
    assert_eq!(released.load(Ordering::Relaxed), 1);
}

impl Drop for AttachmentTicket {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_owned_attachment_keeps_its_ticket_until_the_engine_closes_the_socket() {
    use concord_common::{DirectIo, OwnedTcp};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut link = Link::new(0, 0);
    let (client_addr, server_addr) = addrs();
    let _client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let mut server = link.accepted.pop().unwrap();
    let (near, mut far) = socket_pair(None).await;
    let dropped = Arc::<AtomicUsize>::default();
    let mut socket = Some(OwnedTcp::new(
        near,
        None,
        Some(Arc::new(AttachmentTicket(dropped.clone()))),
    ));
    let attached = server.attach_owned(&mut socket).unwrap();
    assert!(socket.is_none());
    link.step();
    drop(attached);
    drop(server);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    link.step();
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    assert_eq!(far.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn refusing_an_owned_socket_after_reset_preserves_its_ticket_and_payload() {
    use concord_common::{DirectIo, OwnedTcp};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut link = Link::new(0, 0);
    let (client_addr, server_addr) = addrs();
    let _client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let mut server = link.accepted.pop().unwrap();
    link.server.shutdown();
    let (near, mut far) = socket_pair(None).await;
    let dropped = Arc::<AtomicUsize>::default();
    let mut socket = Some(OwnedTcp::new(
        near,
        None,
        Some(Arc::new(AttachmentTicket(dropped.clone()))),
    ));
    assert!(server.attach_owned(&mut socket).is_none());
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    let mut socket = socket.take().unwrap();
    socket.write_all(b"fallback").await.unwrap();
    socket.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    far.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"fallback");
    drop(socket);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_socket_handed_over_as_the_connection_resets_is_released() {
    use concord_common::DirectIo;
    use std::task::{Context, Poll};

    let mut link = Link::new(0, 0);
    let (client_addr, server_addr) = addrs();
    let client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let mut server = link.accepted.pop().unwrap();
    server.write_all(b"unread").await.unwrap();
    for _ in 0..20 {
        link.step();
    }
    let (near, _far) = socket_pair(None).await;
    let mut attached = server.attach(near).unwrap();
    drop(client);
    link.client.poll(&mut link.to_server);
    hand_over(&mut link, true);
    assert!(link.server.is_empty());
    let waker = futures_util::task::noop_waker();
    let done = attached.poll_done(&mut Context::from_waker(&waker));
    assert!(
        matches!(&done, Poll::Ready(Err(err)) if err.kind() == std::io::ErrorKind::ConnectionReset),
        "{done:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_closed_connection_still_delivers_what_its_socket_had_no_room_for() {
    closed_still_delivers(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_batch_the_socket_takes_in_part_keeps_the_rest_and_its_fin() {
    closed_still_delivers(true).await;
}

async fn closed_still_delivers(batched: bool) {
    use concord_common::DirectIo;
    use std::task::{Context, Poll};

    let mut link = Link::new(0, 0);
    link.batched = batched;
    let (client_addr, server_addr) = addrs();
    let mut client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let mut server = link.accepted.pop().unwrap();
    let (near, mut far) = socket_pair(Some(4096)).await;
    let mut attached = server.attach(near).unwrap();
    let up = pattern(250_000, 7);
    let (sent_tx, mut sent) = tokio::sync::oneshot::channel();
    {
        let up = up.clone();
        tokio::spawn(async move {
            client.write_all(&up).await.unwrap();
            client.shutdown().await.unwrap();
            let _ = sent_tx.send(());
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
        });
    }
    drive(&mut link, |_| sent.try_recv().is_ok(), 10).await;
    run_for(&mut link, Duration::from_millis(300)).await;
    far.shutdown().await.unwrap();
    run_for(&mut link, Duration::from_millis(300)).await;
    let reader = tokio::spawn(async move {
        let mut got = Vec::new();
        far.read_to_end(&mut got).await.unwrap();
        got
    });
    let mut outcome = None;
    drive(
        &mut link,
        |l| {
            let waker = futures_util::task::noop_waker();
            if let Poll::Ready(result) = attached.poll_done(&mut Context::from_waker(&waker)) {
                outcome = Some(result.map_err(|err| err.kind()));
            }
            outcome.is_some() && l.server.is_empty() && reader.is_finished()
        },
        10,
    )
    .await;
    assert_eq!(outcome, Some(Ok(())));
    assert!(reader.await.unwrap() == up, "the socket got every byte");
    assert_eq!(attached.moved(), (up.len() as u64, 0));
    drop(server);
}

fn payloads(wire: &Wire) -> Vec<usize> {
    wire.packets
        .iter()
        .map(|packet| match parse_packet(packet) {
            Ok(Parsed::Packet(view)) => parse_tcp(view.l4).unwrap().payload.len(),
            _ => panic!("stack emitted a bad packet"),
        })
        .collect()
}

fn hand_over(link: &mut Link, to_server: bool) {
    let packets = if to_server {
        std::mem::take(&mut link.to_server.packets)
    } else {
        std::mem::take(&mut link.to_client.packets)
    };
    for packet in packets {
        link.deliver(to_server, &packet);
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_reply_carries_the_ack_and_a_quiet_receiver_acks_late() {
    let mut link = Link::new(0, 0);
    let (client_addr, server_addr) = addrs();
    let mut client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let mut server = link.accepted.pop().unwrap();
    while link.step() {}

    client.write_all(b"ping").await.unwrap();
    link.client.poll(&mut link.to_server);
    hand_over(&mut link, true);
    link.server.poll(&mut link.to_client);
    assert!(
        link.to_client.packets.is_empty(),
        "the ACK waits for a reply"
    );

    let mut got = [0u8; 4];
    server.read_exact(&mut got).await.unwrap();
    server.write_all(b"pong").await.unwrap();
    link.server.poll(&mut link.to_client);
    assert_eq!(
        payloads(&link.to_client),
        [4],
        "one segment carries the reply and the ACK"
    );

    hand_over(&mut link, false);
    link.client.poll(&mut link.to_server);
    assert!(link.to_server.packets.is_empty());
    tokio::time::sleep(Duration::from_millis(11)).await;
    link.client.poll(&mut link.to_server);
    assert_eq!(
        payloads(&link.to_server),
        [0],
        "a quiet receiver still acknowledges"
    );
}

fn syn_to_client(seq: u32) -> Vec<u8> {
    let (client_addr, server_addr) = addrs();
    let header = TcpHeader {
        src: server_addr,
        dst: client_addr,
        seq,
        ack: 0,
        flags: FLAG_SYN,
        window: 65_535,
    };
    let mut buf = vec![0u8; 128];
    let len = emit_tcp(
        &mut buf,
        &header,
        &TcpOptions::default(),
        0,
        L4Checksum::Full,
        |_| Some(()),
    )
    .unwrap();
    buf.truncate(len);
    buf
}

#[tokio::test(flavor = "current_thread")]
async fn a_newer_syn_in_time_wait_respects_a_reassigned_owner() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MayOwn(Arc<AtomicBool>);
    impl crate::FlowOwner for MayOwn {
        fn acquire(&self, _local: SocketAddr, _remote: SocketAddr) -> Option<Box<dyn Send + Sync>> {
            self.0
                .load(Ordering::Relaxed)
                .then(|| Box::new(()) as Box<dyn Send + Sync>)
        }
    }

    let mut link = Link::new(0, 0);
    let owns = Arc::new(AtomicBool::new(true));
    link.client
        .set_flow_owner(Arc::new(MayOwn(Arc::clone(&owns))));
    let (client_addr, server_addr) = addrs();
    let client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let server = link.accepted.pop().unwrap();
    let closed = tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(client);
        writer.shutdown().await.unwrap();
        reader.read_to_end(&mut Vec::new()).await.unwrap();
        (reader, writer)
    });
    let echo = tokio::spawn(send_and_receive(server, Vec::new()));
    drive(
        &mut link,
        |_| closed.is_finished() && echo.is_finished(),
        10,
    )
    .await;
    let _client = closed.await.unwrap();
    link.step();
    assert!(link.client.is_bound(client_addr, server_addr), "TIME_WAIT");

    let fin = link
        .delivered
        .iter()
        .rev()
        .find_map(|(to_server, packet)| {
            let Ok(Parsed::Packet(view)) = parse_packet(packet) else {
                return None;
            };
            let seg = parse_tcp(view.l4).ok()?;
            (!to_server && seg.has(FLAG_FIN)).then_some(seg.seq)
        })
        .unwrap();

    let old = syn_to_client(fin);
    let Ok(Parsed::Packet(view)) = parse_packet(&old) else {
        panic!()
    };
    let result = link
        .client
        .input(view.src, view.dst, view.l4, &mut link.to_server, |_, _| {
            Admit::Accept(7)
        });
    assert_eq!(result, TcpInput::Handled, "an old SYN does not reopen it");

    let new = syn_to_client(fin.wrapping_add(1_000));
    let Ok(Parsed::Packet(view)) = parse_packet(&new) else {
        panic!()
    };
    let before = link.to_server.packets.len();
    let result = link
        .client
        .input(view.src, view.dst, view.l4, &mut link.to_server, |_, _| {
            // This callback runs after TIME_WAIT removal and before owner acquisition.
            owns.store(false, Ordering::Relaxed);
            Admit::Accept(7)
        });
    assert_eq!(result, TcpInput::Refused);
    assert_eq!(link.client.len(), 0);
    assert!(!link.client.is_bound(client_addr, server_addr));
    link.client.poll(&mut link.to_server);
    assert_eq!(
        link.to_server.packets.len(),
        before,
        "no SYN-ACK or reset from the losing stack"
    );
    assert_eq!(
        link.client
            .connect(client_addr, server_addr, Congestion::Cubic)
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::AddrInUse
    );
    assert_eq!(link.client.len(), 0);
    owns.store(true, Ordering::Relaxed);
    let result = link
        .client
        .input(view.src, view.dst, view.l4, &mut link.to_server, |_, _| {
            Admit::Accept(7)
        });
    assert_eq!(result, TcpInput::Opened);
    assert_eq!(link.client.len(), 1);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_window_that_reopens_ends_the_probe_backoff() {
    let mut link = Link::new(0, 0);
    let (client_addr, server_addr) = addrs();
    let client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let mut server = link.accepted.pop().unwrap();
    let writer = tokio::spawn(async move {
        let mut client = client;
        let _ = client.write_all(&pattern(1 << 20, 1)).await;
        client
    });
    run_for(&mut link, Duration::from_secs(4)).await;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1 << 16];
        while server.read(&mut buf).await.is_ok_and(|n| n > 0) {}
    });

    let mut lost = 0;
    let start = tokio::time::Instant::now();
    while start.elapsed() < Duration::from_millis(1500) {
        link.client.poll(&mut link.to_server);
        link.server.poll(&mut link.to_client);
        hand_over(&mut link, false);
        if lost == 0 && payloads(&link.to_server).iter().all(|&n| n == 0) {
            hand_over(&mut link, true);
        } else if payloads(&link.to_server).iter().any(|&n| n > 0) {
            lost += 1;
            link.to_server.packets.clear();
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    drop(writer);
    assert!(
        lost >= 3,
        "after the first burst, the loss probe and the timeout both resend: {lost}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_fin_batched_with_payload_reaches_the_socket_after_it() {
    use concord_common::DirectIo;

    let mut link = Link::new(0, 0);
    link.batched = true;
    let (client_addr, server_addr) = addrs();
    let mut client = link
        .client
        .connect(client_addr, server_addr, Congestion::Cubic)
        .unwrap();
    drive(&mut link, |l| !l.accepted.is_empty(), 10).await;
    let mut server = link.accepted.pop().unwrap();
    let (near, mut far) = socket_pair(None).await;
    let _attached = server.attach(near).unwrap();
    link.server.poll(&mut link.to_client);
    let up = pattern(3000, 9);
    client.write_all(&up).await.unwrap();
    client.shutdown().await.unwrap();
    link.client.poll(&mut link.to_server);
    let batch = std::mem::take(&mut link.to_server.packets);
    let fin = batch
        .iter()
        .filter_map(|packet| match parse_packet(packet) {
            Ok(Parsed::Packet(view)) => parse_tcp(view.l4).ok(),
            _ => None,
        })
        .any(|seg| seg.has(crate::wire::FLAG_FIN));
    assert!(fin, "the client's last segments carry the FIN");
    link.deliver_batch(&batch);
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), far.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert!(got == up, "the socket got the payload before its EOF");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn a_gather_holds_no_more_than_its_socket_can_take() {
    let (near, _far) = socket_pair(Some(32 * 1024)).await;
    let room = concord_platform::send_space(&near).unwrap();
    let near = crate::attach::Socket::Tokio(near.into());
    let frame = vec![0u8; 4096];
    let mut gather = crate::Gather::default();
    let mut held = 0;
    while held <= room && gather.push(&frame, &near) {
        held += frame.len();
    }
    assert!(held > frame.len(), "a gather takes what fits");
    assert!(held <= room, "held {held} past the socket's room {room}");
}

#[tokio::test(flavor = "current_thread")]
async fn flows_waiting_for_egress_room_share_it() {
    const FLOWS: usize = 4;
    let mut link = Link::new(0, 0);
    link.batched = true;
    link.to_client.limit = Some(8);
    let server_addr = addrs().1;
    let mut clients = Vec::new();
    for flow in 0..FLOWS {
        let client_addr = SocketAddr::new(addrs().0.ip(), 40_000 + flow as u16);
        let stream = link
            .client
            .connect(client_addr, server_addr, Congestion::Cubic)
            .unwrap();
        clients.push(stream);
    }
    drive(&mut link, |l| l.accepted.len() == FLOWS, 10).await;
    let received: std::sync::Arc<Vec<std::sync::atomic::AtomicUsize>> = std::sync::Arc::new(
        (0..FLOWS)
            .map(|_| std::sync::atomic::AtomicUsize::new(0))
            .collect(),
    );
    let mut tasks = Vec::new();
    for (flow, mut client) in clients.into_iter().enumerate() {
        let received = std::sync::Arc::clone(&received);
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            while let Ok(n) = client.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                received[flow].fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }
    for mut server in link.accepted.drain(..) {
        tasks.push(tokio::spawn(async move {
            let chunk = vec![7u8; 16_384];
            while server.write_all(&chunk).await.is_ok() {}
        }));
    }
    for _ in 0..4_000 {
        link.step();
        tokio::task::yield_now().await;
    }
    let got: Vec<usize> = received
        .iter()
        .map(|bytes| bytes.load(std::sync::atomic::Ordering::Relaxed))
        .collect();
    for task in tasks {
        task.abort();
    }
    let (least, most) = (
        got.iter().copied().min().unwrap(),
        got.iter().copied().max().unwrap(),
    );
    assert!(least * 2 > most, "bytes per flow {got:?}");
}
