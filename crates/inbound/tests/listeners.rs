#![allow(
    clippy::disallowed_methods,
    reason = "test clients dial loopback directly"
)]

mod common;

use std::io;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use concord_common::sync::lock;
use concord_common::{Address, InboundKind};
use concord_inbound::{Cidr, ListenSpec, ListenerKind, Listeners, TproxyDatagram, Transparent};
use concord_test_support::free_port;
use socket2::Socket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

async fn refused(addr: SocketAddr) -> bool {
    TcpStream::connect(addr).await.is_err()
}

#[tokio::test]
async fn an_unchanged_port_keeps_its_listener_and_its_connections() {
    let port = free_port();
    let spec = ListenSpec {
        mixed_port: Some(port),
        ..Default::default()
    };
    let run = start(spec.clone(), Fake::echo()).await;
    let addr = run.addr(ListenerKind::Mixed).await;
    let mut live = socks5_session(addr, "keep.test", 80).await;

    assert!(reconcile(&run, &spec).await.is_empty());
    assert_eq!(run.addr(ListenerKind::Mixed).await, addr);
    live.write_all(b"still").await.unwrap();
    assert_eq!(read_exact(&mut live, 5).await, b"still");

    let other = ListenSpec {
        http_port: Some(0),
        ..spec
    };
    assert!(reconcile(&run, &other).await.is_empty());
    assert_eq!(run.addr(ListenerKind::Mixed).await, addr);
    live.write_all(b"again").await.unwrap();
    assert_eq!(read_exact(&mut live, 5).await, b"again");
}

#[tokio::test]
async fn a_changed_port_is_rebound_and_live_connections_survive() {
    let (first, second) = (free_port(), free_port());
    let spec = ListenSpec {
        mixed_port: Some(first),
        ..Default::default()
    };
    let run = start(spec.clone(), Fake::echo()).await;
    let old = run.addr(ListenerKind::Mixed).await;
    let mut live = socks5_session(old, "live.test", 80).await;

    let moved = ListenSpec {
        mixed_port: Some(second),
        ..spec
    };
    assert!(reconcile(&run, &moved).await.is_empty());
    let new = run.addr(ListenerKind::Mixed).await;
    assert_eq!(new.port(), second);
    assert!(refused(old).await);
    drop(socks5_session(new, "new.test", 80).await);

    live.write_all(b"alive").await.unwrap();
    assert_eq!(read_exact(&mut live, 5).await, b"alive");
}

#[tokio::test]
async fn removing_a_port_or_stopping_closes_the_listener() {
    let run = start(
        ListenSpec {
            mixed_port: Some(0),
            http_port: Some(0),
            ..Default::default()
        },
        Fake::echo(),
    )
    .await;
    let mixed = run.addr(ListenerKind::Mixed).await;
    let http = run.addr(ListenerKind::Http).await;

    assert!(
        reconcile(
            &run,
            &ListenSpec {
                http_port: Some(0),
                ..Default::default()
            }
        )
        .await
        .is_empty()
    );
    assert!(refused(mixed).await);
    assert!(!refused(http).await);

    run.listeners.stop_all().await;
    assert!(refused(http).await);
    assert!(run.listeners.bound().await.is_empty());
}

#[tokio::test]
async fn a_bind_conflict_is_reported_and_the_other_ports_stay_up() {
    let taken = StdListener::bind("127.0.0.1:0").unwrap();
    let taken_port = taken.local_addr().unwrap().port();
    let listeners = Listeners::new();
    let spec = ListenSpec {
        mixed_port: Some(0),
        http_port: Some(taken_port),
        socks_port: Some(0),
        ..Default::default()
    };
    let fake = Fake::echo();
    let errors = open(&listeners, &spec, fake.clone()).await;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].kind, ListenerKind::Http);
    assert_eq!(errors[0].source.kind(), io::ErrorKind::AddrInUse);
    assert!(errors[0].to_string().starts_with("Start HTTP server error"));

    let kinds: Vec<_> = listeners.bound().await.iter().map(|b| b.kind).collect();
    assert_eq!(kinds, [ListenerKind::Mixed, ListenerKind::Socks]);

    drop(taken);
    assert!(open(&listeners, &spec, fake).await.is_empty());
    assert_eq!(listeners.bound().await.len(), 3);
}

#[tokio::test]
async fn a_lan_address_that_is_not_an_ip_is_an_error_for_every_listener() {
    let listeners = Listeners::new();
    let spec = ListenSpec {
        mixed_port: Some(0),
        http_port: Some(0),
        allow_lan: true,
        bind_address: "not-an-ip".into(),
        ..Default::default()
    };
    let errors = listeners.reconcile(&spec, Fake::echo()).await;
    assert_eq!(errors.len(), 2);
    assert!(listeners.bound().await.is_empty());
}

#[tokio::test]
async fn the_lan_lists_gate_accepted_connections() {
    let mut spec = mixed();
    spec.lan_disallowed_ips = vec!["127.0.0.0/8".parse::<Cidr>().unwrap()];
    let run = start(spec, Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Mixed).await).await;
    let _ = stream.write_all(&[5, 1, 0]).await;
    assert!(read_to_close(&mut stream).await.is_empty());
    assert_eq!(run.fake.flow_count(), 0);

    let mut open = mixed();
    open.mixed_port = Some(run.addr(ListenerKind::Mixed).await.port());
    open.lan_allowed_ips = vec!["10.0.0.0/8".parse::<Cidr>().unwrap()];
    assert!(reconcile(&run, &open).await.is_empty());
    let mut stream = connect(run.addr(ListenerKind::Mixed).await).await;
    let _ = stream.write_all(&[5, 1, 0]).await;
    assert!(read_to_close(&mut stream).await.is_empty());

    open.lan_allowed_ips = vec!["127.0.0.0/8".parse::<Cidr>().unwrap()];
    assert!(reconcile(&run, &open).await.is_empty());
    drop(socks5_session(run.addr(ListenerKind::Mixed).await, "ok.test", 80).await);
}

#[tokio::test]
async fn auth_and_the_handler_follow_a_reconcile_that_keeps_the_socket() {
    let port = free_port();
    let spec = ListenSpec {
        mixed_port: Some(port),
        ..Default::default()
    };
    let first = Fake::echo();
    let run = start(spec.clone(), first.clone()).await;
    let addr = run.addr(ListenerKind::Mixed).await;
    drop(socks5_session(addr, "one.test", 80).await);
    assert_eq!(first.flow_count(), 1);

    let second = Fake::echo();
    let guarded = ListenSpec {
        authentication: vec![("u".into(), "p".into())],
        ..spec
    };
    assert!(
        run.listeners
            .reconcile(&guarded, second.clone())
            .await
            .is_empty()
    );
    let mut stream = connect(addr).await;
    stream.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(read_exact(&mut stream, 2).await, [5, 2]);

    let open = ListenSpec {
        mixed_port: Some(port),
        ..Default::default()
    };
    assert!(
        run.listeners
            .reconcile(&open, second.clone())
            .await
            .is_empty()
    );
    drop(socks5_session(addr, "two.test", 80).await);
    wait_for(|| second.flow_count() == 1).await;
    assert_eq!(first.flow_count(), 1);
}

#[tokio::test]
async fn a_source_under_skip_auth_prefixes_connects_without_credentials() {
    let spec = ListenSpec {
        mixed_port: Some(0),
        authentication: vec![("u".into(), "p".into())],
        skip_auth: vec!["127.0.0.0/8".parse::<Cidr>().unwrap()],
        ..Default::default()
    };
    let fake = Fake::echo();
    let run = start(spec, fake.clone()).await;
    drop(socks5_session(run.addr(ListenerKind::Mixed).await, "ok.test", 80).await);
    wait_for(|| fake.flow_count() == 1).await;
}

#[tokio::test]
async fn redir_and_tproxy_without_platform_support_are_reported() {
    let listeners = Listeners::new();
    let spec = ListenSpec {
        redir_port: Some(0),
        tproxy_port: Some(0),
        mixed_port: Some(0),
        ..Default::default()
    };
    let errors = listeners.reconcile(&spec, Fake::echo()).await;
    let kinds: Vec<_> = errors.iter().map(|error| error.kind).collect();
    assert_eq!(kinds, [ListenerKind::Redir, ListenerKind::TProxy]);
    assert_eq!(errors[0].source.kind(), io::ErrorKind::Unsupported);
    assert_eq!(listeners.bound().await.len(), 1);
}

struct FixedOrigin(SocketAddr);

impl Transparent for FixedOrigin {
    fn original_dst(&self, _: &TcpStream) -> io::Result<SocketAddr> {
        Ok(self.0)
    }

    fn make_transparent(&self, _: &Socket, _: bool) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn redir_reports_the_destination_the_platform_recovers() {
    let original: SocketAddr = "203.0.113.5:8443".parse().unwrap();
    let listeners = Listeners::with_transparent(Arc::new(FixedOrigin(original)));
    let fake = Fake::echo();
    let spec = ListenSpec {
        redir_port: Some(0),
        ..Default::default()
    };
    assert!(listeners.reconcile(&spec, fake.clone()).await.is_empty());
    let addr = listeners.bound().await[0].addr;
    let mut stream = connect(addr).await;
    stream.write_all(b"x").await.unwrap();
    assert_eq!(read_exact(&mut stream, 1).await, b"x");
    let meta = fake.flow(0);
    assert_eq!(meta.inbound.kind, InboundKind::Redir);
    assert_eq!(&*meta.inbound.name, "DEFAULT-REDIR");
    assert_eq!(meta.dst, Address::from(original));
    assert_eq!(meta.inbound.addr, Some(addr));
}

#[tokio::test]
async fn tproxy_takes_the_accepted_local_address_as_the_destination() {
    let listeners =
        Listeners::with_transparent(Arc::new(FixedOrigin("0.0.0.0:1".parse().unwrap())));
    let fake = Fake::echo();
    let spec = ListenSpec {
        tproxy_port: Some(0),
        ..Default::default()
    };
    assert!(listeners.reconcile(&spec, fake.clone()).await.is_empty());
    let addr = listeners.bound().await[0].addr;
    let mut stream = connect(addr).await;
    stream.write_all(b"x").await.unwrap();
    assert_eq!(read_exact(&mut stream, 1).await, b"x");
    let meta = fake.flow(0);
    assert_eq!(meta.inbound.kind, InboundKind::TProxy);
    assert_eq!(meta.dst, Address::from(addr));
    assert_eq!(meta.inbound.addr, Some(addr));
}

#[tokio::test]
async fn the_native_redir_listener_binds() {
    let listeners = Listeners::native();
    let spec = ListenSpec {
        redir_port: Some(0),
        ..Default::default()
    };
    assert!(listeners.reconcile(&spec, Fake::echo()).await.is_empty());
    assert_eq!(listeners.bound().await[0].kind, ListenerKind::Redir);
}

struct NoOrigin;

impl Transparent for NoOrigin {
    fn original_dst(&self, _: &TcpStream) -> io::Result<SocketAddr> {
        Err(io::ErrorKind::NotFound.into())
    }

    fn make_transparent(&self, _: &Socket, _: bool) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn redir_drops_a_connection_whose_destination_cannot_be_recovered() {
    let listeners = Listeners::with_transparent(Arc::new(NoOrigin));
    let fake = Fake::echo();
    let spec = ListenSpec {
        redir_port: Some(0),
        ..Default::default()
    };
    assert!(listeners.reconcile(&spec, fake.clone()).await.is_empty());
    let addr = listeners.bound().await[0].addr;
    let mut stream = connect(addr).await;
    let _ = stream.write_all(b"x").await;
    assert!(read_to_close(&mut stream).await.is_empty());
    assert_eq!(fake.flow_count(), 0);
}

struct Interposed {
    dst: SocketAddr,
    answered_as: Mutex<Vec<(SocketAddr, SocketAddr)>>,
}

impl Interposed {
    fn new(dst: &str) -> Arc<Self> {
        Arc::new(Interposed {
            dst: dst.parse().unwrap(),
            answered_as: Mutex::new(Vec::new()),
        })
    }
}

impl Transparent for Interposed {
    fn original_dst(&self, _: &TcpStream) -> io::Result<SocketAddr> {
        Ok(self.dst)
    }

    fn make_transparent(&self, _: &Socket, _: bool) -> io::Result<()> {
        Ok(())
    }

    fn prepare_udp(&self, _: &Socket, _: bool) -> io::Result<()> {
        Ok(())
    }

    fn recv_udp(&self, socket: &UdpSocket, buf: &mut [u8]) -> io::Result<TproxyDatagram> {
        let (len, src) = socket.try_recv_from(buf)?;
        Ok(TproxyDatagram {
            len,
            src,
            dst: self.dst,
            dscp: 0,
        })
    }

    fn reply_socket(&self, from: SocketAddr, to: SocketAddr) -> io::Result<std::net::UdpSocket> {
        lock(&self.answered_as).push((from, to));
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(to)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
}

async fn answer_from(kind: ListenerKind) {
    let transparent = Interposed::new("203.0.113.9:5353");
    let listeners = Listeners::with_transparent(transparent.clone());
    let fake = Fake::echo();
    let mut spec = ListenSpec::default();
    match kind {
        ListenerKind::Redir => spec.redir_port = Some(0),
        _ => spec.tproxy_port = Some(0),
    }
    assert!(listeners.reconcile(&spec, fake.clone()).await.is_empty());
    let port = listeners.bound().await[0].addr;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"ping", port).await.unwrap();
    let mut buf = [0u8; 64];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("no answer")
        .unwrap();
    assert_eq!(&buf[..len], b"ping");

    let (meta, payload) = lock(&fake.datagrams)[0].clone();
    assert_eq!(payload, b"ping");
    assert_eq!(meta.network, concord_common::Network::Udp);
    assert_eq!(meta.inbound.kind, InboundKind::TProxy);
    assert_eq!(&*meta.inbound.name, "DEFAULT-TPROXY");
    assert_eq!(meta.src, client.local_addr().unwrap());
    assert_eq!(meta.dst, Address::from(transparent.dst));
    assert_eq!(
        lock(&transparent.answered_as).as_slice(),
        [(transparent.dst, client.local_addr().unwrap())]
    );

    client.send_to(b"again", port).await.unwrap();
    wait_for(|| fake.datagram_count() == 2).await;
    assert_eq!(lock(&transparent.answered_as).len(), 1);
}

#[tokio::test]
async fn tproxy_udp_hands_over_the_original_destination_and_answers_as_it() {
    answer_from(ListenerKind::TProxy).await;
}

#[tokio::test]
async fn tproxy_closes_the_sockets_it_answered_from_when_the_session_ends() {
    let transparent = Interposed::new("203.0.113.9:5353");
    let listeners = Listeners::with_transparent(transparent.clone());
    let fake = Fake::echo();
    let spec = ListenSpec {
        tproxy_port: Some(0),
        ..Default::default()
    };
    assert!(listeners.reconcile(&spec, fake.clone()).await.is_empty());
    let port = listeners.bound().await[0].addr;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 64];
    for round in 1..=2 {
        client.send_to(b"ping", port).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("no answer")
            .unwrap();
        assert_eq!(lock(&transparent.answered_as).len(), round);
        let reply = lock(&fake.replies).last().unwrap().clone();
        reply.session_ended();
    }
}

#[tokio::test]
async fn a_redirect_port_answers_udp_as_tproxy_does() {
    answer_from(ListenerKind::Redir).await;
}

#[tokio::test]
async fn a_udp_listener_that_cannot_start_leaves_the_tcp_one_running() {
    let listeners =
        Listeners::with_transparent(Arc::new(FixedOrigin("203.0.113.5:8443".parse().unwrap())));
    let spec = ListenSpec {
        redir_port: Some(0),
        ..Default::default()
    };
    assert!(listeners.reconcile(&spec, Fake::echo()).await.is_empty());
    let addr = listeners.bound().await[0].addr;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"x", addr).await.unwrap();
    let mut buf = [0u8; 8];
    let answer = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
    assert!(
        !matches!(answer, Ok(Ok(_))),
        "a datagram came back: {answer:?}"
    );
}

async fn closed_within(stream: &mut TcpStream, limit: Duration) -> bool {
    let mut rest = Vec::new();
    tokio::time::timeout(limit, stream.read_to_end(&mut rest))
        .await
        .is_ok()
}

#[tokio::test]
async fn a_client_that_stalls_before_its_request_is_closed() {
    let run = start(mixed(), Fake::echo()).await;
    let addr = run.addr(ListenerKind::Mixed).await;
    let mut silent = connect(addr).await;
    let mut greeting = connect(addr).await;
    greeting.write_all(&[5]).await.unwrap();
    let mut partial = connect(addr).await;
    partial
        .write_all(b"GET http://a.test/ HTTP/1.1\r\n")
        .await
        .unwrap();
    // The server must have accepted and armed its timers before the clock jumps.
    tokio::time::sleep(Duration::from_millis(200)).await;
    tokio::time::pause();
    for stream in [&mut silent, &mut greeting, &mut partial] {
        assert!(closed_within(stream, Duration::from_secs(60)).await);
    }
    assert_eq!(run.fake.flow_count(), 0);
}
