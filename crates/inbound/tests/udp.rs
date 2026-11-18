#![allow(
    clippy::disallowed_methods,
    reason = "test clients bind loopback sockets directly"
)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use concord_common::sync::lock;
use concord_common::{Address, InboundKind, Network};
use concord_inbound::{ListenSpec, ListenerKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

async fn associate(addr: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut control = connect(addr).await;
    control.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(read_exact(&mut control, 2).await, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let reply = read_exact(&mut control, 10).await;
    assert_eq!(reply.get(..4), Some(&[5, 0, 0, 1][..]));
    let ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    (control, SocketAddr::new(ip.into(), port))
}

async fn client_socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

async fn recv(socket: &UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("timed out")
        .unwrap();
    buf.truncate(len);
    buf
}

fn datagram(header: &[u8], payload: &[u8]) -> Vec<u8> {
    [header, payload].concat()
}

#[tokio::test]
async fn a_datagram_round_trips_through_udp_associate_on_the_mixed_port() {
    let run = start(mixed(), Fake::echo()).await;
    let tcp = run.addr(ListenerKind::Mixed).await;
    let (_control, relay) = associate(tcp).await;
    assert_eq!(relay, tcp);

    let client = client_socket().await;
    let header = [0, 0, 0, 1, 8, 8, 4, 4, 0, 53];
    client
        .send_to(&datagram(&header, b"query"), relay)
        .await
        .unwrap();
    assert_eq!(recv(&client).await, datagram(&header, b"query"));

    let (meta, payload) = lock(&run.fake.datagrams)[0].clone();
    assert_eq!(payload, b"query");
    assert_eq!(meta.network, Network::Udp);
    assert_eq!(meta.inbound.kind, InboundKind::Socks5);
    assert_eq!(&*meta.inbound.name, "DEFAULT-SOCKS");
    assert_eq!(meta.src, client.local_addr().unwrap());
    assert_eq!(meta.dst, Address::new("8.8.4.4", 53));
    assert_eq!(meta.inbound.addr.map(|addr| addr.port()), Some(tcp.port()));
}

#[tokio::test]
async fn domain_and_ipv6_destinations_come_back_with_the_same_header() {
    let spec = ListenSpec {
        socks_port: Some(0),
        ..Default::default()
    };
    let run = start(spec, Fake::echo()).await;
    let (_control, relay) = associate(run.addr(ListenerKind::Socks).await).await;
    let client = client_socket().await;

    let domain = [0, 0, 0, 3, 7, b'a', b'.', b't', b'e', b's', b't', 1, 187];
    client
        .send_to(&datagram(&domain, b"d"), relay)
        .await
        .unwrap();
    assert_eq!(recv(&client).await, datagram(&domain, b"d"));

    let mut v6 = vec![0, 0, 0, 4];
    v6.extend_from_slice(
        &"2001:db8::7"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    v6.extend_from_slice(&[0, 80]);
    client.send_to(&datagram(&v6, b"six"), relay).await.unwrap();
    assert_eq!(recv(&client).await, datagram(&v6, b"six"));
}

#[tokio::test]
async fn fragmented_and_reserved_datagrams_are_dropped_and_the_next_one_still_works() {
    let run = start(mixed(), Fake::echo()).await;
    let (_control, relay) = associate(run.addr(ListenerKind::Mixed).await).await;
    let client = client_socket().await;
    client
        .send_to(&datagram(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 9], b"frag"), relay)
        .await
        .unwrap();
    client
        .send_to(&datagram(&[0, 1, 0, 1, 1, 2, 3, 4, 0, 9], b"rsv"), relay)
        .await
        .unwrap();
    client.send_to(&[0, 0, 0], relay).await.unwrap();
    let good = [0, 0, 0, 1, 1, 2, 3, 4, 0, 9];
    client
        .send_to(&datagram(&good, b"good"), relay)
        .await
        .unwrap();
    assert_eq!(recv(&client).await, datagram(&good, b"good"));
    assert_eq!(run.fake.datagram_count(), 1);
}

#[tokio::test]
async fn datagrams_before_an_association_and_after_it_ends_are_dropped() {
    let run = start(mixed(), Fake::echo()).await;
    let tcp = run.addr(ListenerKind::Mixed).await;
    let client = client_socket().await;
    let header = [0, 0, 0, 1, 1, 2, 3, 4, 0, 9];

    client
        .send_to(&datagram(&header, b"early"), tcp)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(run.fake.datagram_count(), 0);

    let (control, relay) = associate(tcp).await;
    client
        .send_to(&datagram(&header, b"live"), relay)
        .await
        .unwrap();
    assert_eq!(recv(&client).await, datagram(&header, b"live"));

    drop(control);
    tokio::time::sleep(Duration::from_millis(100)).await;
    client
        .send_to(&datagram(&header, b"late"), relay)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(run.fake.datagram_count(), 1);
}

#[tokio::test]
async fn the_control_connection_stays_open_and_discards_what_it_receives() {
    let run = start(mixed(), Fake::echo()).await;
    let (mut control, _) = associate(run.addr(ListenerKind::Mixed).await).await;
    control.write_all(b"noise").await.unwrap();
    let mut buf = [0u8; 8];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), control.read(&mut buf))
            .await
            .is_err()
    );
    assert_eq!(run.fake.flow_count(), 0);
}

#[tokio::test]
async fn an_authenticated_association_tags_its_datagrams_with_the_user() {
    let spec = ListenSpec {
        mixed_port: Some(0),
        authentication: vec![("alice".into(), "secret".into())],
        ..Default::default()
    };
    let run = start(spec, Fake::echo()).await;
    let tcp = run.addr(ListenerKind::Mixed).await;
    let mut control = connect(tcp).await;
    control.write_all(&[5, 1, 2]).await.unwrap();
    read_exact(&mut control, 2).await;
    let mut auth = vec![1, 5];
    auth.extend_from_slice(b"alice");
    auth.push(6);
    auth.extend_from_slice(b"secret");
    control.write_all(&auth).await.unwrap();
    read_exact(&mut control, 2).await;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    read_exact(&mut control, 10).await;

    let client = client_socket().await;
    let header = [0, 0, 0, 1, 1, 2, 3, 4, 0, 9];
    client
        .send_to(&datagram(&header, b"hi"), tcp)
        .await
        .unwrap();
    recv(&client).await;
    let (meta, _) = lock(&run.fake.datagrams)[0].clone();
    assert_eq!(meta.inbound.user.as_deref(), Some("alice"));
}

/// Keeps every reply it is given, as the tunnel's UDP sessions do.
#[derive(Default)]
struct Sessions(std::sync::Mutex<Vec<std::sync::Arc<dyn concord_common::UdpReply>>>);

impl concord_common::FlowHandler for Sessions {
    fn handle_tcp(&self, _: concord_common::FlowMeta, _: concord_common::BoxStream) {}

    fn handle_udp(
        &self,
        _: concord_common::UdpFlow<'_>,
        _: concord_common::UdpPayload<'_>,
        reply: &std::sync::Arc<dyn concord_common::UdpReply>,
    ) {
        lock(&self.0).push(reply.clone());
    }
}

#[tokio::test]
async fn a_session_that_outlives_its_listener_does_not_hold_the_udp_port() {
    let sessions = std::sync::Arc::new(Sessions::default());
    let listeners = concord_inbound::Listeners::new();
    assert!(
        open(&listeners, &mixed(), sessions.clone())
            .await
            .is_empty()
    );
    let tcp = listeners.bound().await[0].addr;
    let (_control, relay) = associate(tcp).await;
    let client = client_socket().await;
    client
        .send_to(&datagram(&[0, 0, 0, 1, 1, 2, 3, 4, 0, 9], b"hi"), relay)
        .await
        .unwrap();
    wait_for(|| !lock(&sessions.0).is_empty()).await;

    listeners.stop_all().await;

    std::net::UdpSocket::bind(tcp).expect("the stopped listener still holds its UDP port");
}
