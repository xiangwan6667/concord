use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use concord_common::dns_relay::{answer_datagram, serve_stream};
use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, DialCx, HostResolver, Outbound, OutboundInfo, OutboundKind, PacketBuf,
    PacketSession, Tasks,
};
use tokio::sync::mpsc;

/// mihomo `resolver.SafeDnsPacketSize` (`component/resolver/relay.go:18`): a longer datagram is
/// taken and dropped.
const SAFE_PACKET: usize = 2048;
/// mihomo's `dnsPacketConn` answer channel (`adapter/outbound/dns.go:42`).
const ANSWER_QUEUE: usize = 1;
/// One length-prefixed DNS message, so the server side never waits on a whole answer.
const PIPE_CAPACITY: usize = 2 + u16::MAX as usize;
/// mihomo's placeholder for a name the client did not resolve (`adapter/outbound/dns.go:50`).
const UNRESOLVED: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// mihomo's `dns` outbound: connections and datagrams are answered by the core's own DNS, as
/// its DNS server would answer them.
pub(crate) struct Dns {
    info: OutboundInfo,
    tasks: Tasks,
}

impl Dns {
    pub(crate) fn new(name: &str, tasks: Tasks) -> Self {
        Dns {
            info: crate::direct::info(name, OutboundKind::Dns),
            tasks,
        }
    }
}

fn not_served() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the resolver does not answer DNS messages",
    )
}

#[async_trait]
impl Outbound for Dns {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, _dst: &Address) -> io::Result<BoxStream> {
        let resolver = cx.env.resolver.clone();
        if resolver.dns_server().is_none() {
            return Err(not_served());
        }
        let (near, far) = tokio::io::duplex(PIPE_CAPACITY);
        self.tasks.spawn(async move {
            if let Some(server) = resolver.dns_server() {
                serve_stream(far, server, None).await;
            }
        });
        Ok(Box::new(near))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if cx.env.resolver.dns_server().is_none() {
            return Err(not_served());
        }
        let (answers, queue) = mpsc::channel(ANSWER_QUEUE);
        Ok(Arc::new(DnsSession {
            resolver: cx.env.resolver.clone(),
            answers,
            queue: Mutex::new(queue),
            tasks: self.tasks.clone(),
        }))
    }

    async fn resolve_udp(&self, _cx: &DialCx<'_>, _host: &str) -> Option<io::Result<IpAddr>> {
        Some(Ok(IpAddr::V4(UNRESOLVED)))
    }
}

/// Each datagram is answered on its own task, so a slow name does not hold back the next; the
/// answers wait one at a time for the reader, as mihomo's `dnsPacketConn` does.
struct DnsSession {
    resolver: Arc<dyn HostResolver>,
    answers: mpsc::Sender<(Vec<u8>, Address)>,
    queue: Mutex<mpsc::Receiver<(Vec<u8>, Address)>>,
    tasks: Tasks,
}

impl PacketSession for DnsSession {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.answers.is_closed() {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        if pkt.len() > SAFE_PACKET {
            return Poll::Ready(Ok(()));
        }
        let query = pkt.as_slice().to_vec();
        let (resolver, answers, dst) = (self.resolver.clone(), self.answers.clone(), dst.clone());
        self.tasks.spawn(async move {
            let Some(server) = resolver.dns_server() else {
                return;
            };
            let answer = tokio::select! {
                () = answers.closed() => return,
                answer = answer_datagram(server, &query) => answer,
            };
            if let Some(answer) = answer {
                let _ = answers.send((answer, dst)).await;
            }
        });
        Poll::Ready(Ok(()))
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        match lock(&self.queue).poll_recv(cx) {
            Poll::Ready(Some((answer, from))) => {
                buf.clear();
                buf.extend_from_slice(&answer);
                Poll::Ready(Ok(from))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&self) {
        lock(&self.queue).close();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use concord_common::dns_relay::DnsHijack;
    use concord_common::{DialEnv, Initiator, IpVersion, LookupIps, recv_packet, send_packet};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::testing::test_env;

    /// Answers with the query reversed; a query starting 0xff is held until the test ends, and
    /// a datagram answer is cut to its first four bytes so the two paths can be told apart.
    struct Reverse;

    #[async_trait]
    impl DnsHijack for Reverse {
        async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
            let mut full = self.answer_stream(query).await?;
            full.truncate(4);
            Some(full)
        }

        async fn answer_stream(&self, query: &[u8]) -> Option<Vec<u8>> {
            if query.first() == Some(&0xff) {
                std::future::pending::<()>().await;
            }
            Some(query.iter().rev().copied().collect())
        }
    }

    #[async_trait]
    impl HostResolver for Reverse {
        async fn lookup(&self, _: &str, _: IpVersion, _: Initiator) -> io::Result<LookupIps> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn dns_server(&self) -> Option<&dyn DnsHijack> {
            Some(self)
        }
    }

    fn served_env() -> DialEnv {
        DialEnv {
            resolver: Arc::new(Reverse),
            ..test_env()
        }
    }

    #[tokio::test]
    async fn a_connection_carries_length_prefixed_queries_to_the_resolver() {
        let env = served_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let dns = Dns::new("dns-out", Default::default());
        let mut stream = dns
            .connect(&cx, &Address::new("8.8.8.8", 53))
            .await
            .unwrap();
        for query in [&b"\x00\x01abc"[..], &b"\x00\x02hello"[..]] {
            let mut frame = (query.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(query);
            stream.write_all(&frame).await.unwrap();
            let mut prefix = [0u8; 2];
            stream.read_exact(&mut prefix).await.unwrap();
            assert_eq!(usize::from(u16::from_be_bytes(prefix)), query.len());
            let mut answer = vec![0u8; query.len()];
            stream.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, query.iter().rev().copied().collect::<Vec<_>>());
        }
        stream.shutdown().await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn a_datagram_is_answered_from_the_address_it_was_sent_to() {
        let env = served_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let dns = Dns::new("dns-out", Default::default());
        let to = Address::new("1.1.1.1", 53);
        let session = dns.associate(&cx, &to).await.unwrap();
        let mut packet = PacketBuf::from_slice(b"\x00\x07query");
        send_packet(session.as_ref(), &mut packet, &to)
            .await
            .unwrap();
        let mut buf = PacketBuf::take();
        let from = std::future::poll_fn(|cx| session.poll_recv(cx, &mut buf))
            .await
            .unwrap();
        assert_eq!(from, to);
        assert_eq!(buf.as_slice(), b"yreu");
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_datagram_does_not_hold_back_the_next() {
        let env = served_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let session = Dns::new("dns-out", Default::default())
            .associate(&cx, &Address::new("1.1.1.1", 53))
            .await
            .unwrap();
        let to = Address::new("1.1.1.1", 53);
        for query in [&b"\xff\x01slow"[..], &b"\x00\x02fast"[..]] {
            let mut packet = PacketBuf::from_slice(query);
            send_packet(session.as_ref(), &mut packet, &to)
                .await
                .unwrap();
        }
        let first = tokio::time::timeout(Duration::from_secs(1), recv_packet(session.as_ref()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.0.as_slice(), b"tsaf");
    }

    #[tokio::test]
    async fn an_oversized_datagram_is_taken_and_dropped() {
        let env = served_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let to = Address::new("1.1.1.1", 53);
        let session = Dns::new("dns-out", Default::default())
            .associate(&cx, &to)
            .await
            .unwrap();
        let mut big = PacketBuf::from_slice(&[1u8; SAFE_PACKET + 1]);
        send_packet(session.as_ref(), &mut big, &to).await.unwrap();
        let mut small = PacketBuf::from_slice(b"\x00\x03abcd");
        send_packet(session.as_ref(), &mut small, &to)
            .await
            .unwrap();
        let (answer, _) = recv_packet(session.as_ref()).await.unwrap();
        assert_eq!(answer.as_slice(), b"dcba");
    }

    #[tokio::test]
    async fn a_closed_session_refuses_datagrams() {
        let env = served_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let to = Address::new("1.1.1.1", 53);
        let session = Dns::new("dns-out", Default::default())
            .associate(&cx, &to)
            .await
            .unwrap();
        session.close();
        let mut packet = PacketBuf::from_slice(b"\x00\x01q");
        assert!(
            send_packet(session.as_ref(), &mut packet, &to)
                .await
                .is_err()
        );
        assert!(recv_packet(session.as_ref()).await.is_err());
    }

    #[tokio::test]
    async fn an_unresolved_name_gets_the_placeholder_address() {
        let env = served_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let ip = Dns::new("dns-out", Default::default())
            .resolve_udp(&cx, "dns.test")
            .await;
        assert_eq!(ip.unwrap().unwrap(), IpAddr::V4(UNRESOLVED));
    }

    #[tokio::test]
    async fn without_a_dns_server_dials_fail() {
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let dns = Dns::new("dns-out", Default::default());
        let to = Address::new("1.1.1.1", 53);
        assert!(dns.connect(&cx, &to).await.is_err());
        assert!(dns.associate(&cx, &to).await.is_err());
    }
}
