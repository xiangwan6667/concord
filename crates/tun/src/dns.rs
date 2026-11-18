use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub use concord_common::dns_relay::DnsHijack;
use concord_common::{Address, UdpReply, dns_relay};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::options::Prefix;

const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
#[error("invalid dns-hijack entry {entry:?}")]
pub struct DnsRuleError {
    pub entry: String,
}

/// The destinations whose DNS is answered by the core. The scheme is read and ignored, as
/// mihomo does: both UDP and TCP are hijacked for any listed address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsMatcher {
    rules: Vec<SocketAddr>,
}

impl DnsMatcher {
    pub fn parse<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<Self, DnsRuleError> {
        let mut rules = Vec::new();
        for entry in entries {
            let bare = entry.split_once("://").map_or(entry, |(_, rest)| rest);
            let normalized = bare.replacen("any", "0.0.0.0", 1);
            let addr = normalized.trim().parse().map_err(|_| DnsRuleError {
                entry: entry.to_owned(),
            })?;
            rules.push(addr);
        }
        Ok(DnsMatcher { rules })
    }

    /// Adds the address after each interface address, where the Go listener also answers.
    pub fn with_interface_addresses(mut self, addresses: &[Prefix]) -> Self {
        for prefix in addresses {
            if let Some(next) = prefix.next_host() {
                self.rules.push(SocketAddr::new(next, 53));
            }
        }
        self
    }

    pub fn with_servers(mut self, servers: &[IpAddr]) -> Self {
        self.rules
            .extend(servers.iter().map(|ip| SocketAddr::new(*ip, 53)));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn matches(&self, dst: SocketAddr) -> bool {
        self.rules
            .iter()
            .any(|rule| *rule == dst || (rule.ip().is_unspecified() && dst.port() == 53))
    }
}

pub(crate) async fn answer_udp(
    hijack: Arc<dyn DnsHijack>,
    reply: Arc<dyn UdpReply>,
    to: SocketAddr,
    query: Vec<u8>,
) {
    let Some(answer) = dns_relay::answer_datagram(hijack.as_ref(), &query).await else {
        return;
    };
    let from = Address::Socket(to);
    let _ = poll_fn(|cx| reply.poll_write_back(cx, &answer, &from)).await;
}

pub(crate) async fn serve_tcp<S>(stream: S, hijack: Arc<dyn DnsHijack>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    dns_relay::serve_stream(stream, hijack.as_ref(), Some(READ_TIMEOUT)).await;
}

#[cfg(test)]
mod tests {
    use std::io;

    use async_trait::async_trait;
    use concord_common::dns_relay::servfail;
    use concord_common::sync::lock;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    struct Echo;

    #[async_trait]
    impl DnsHijack for Echo {
        async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
            (query.first() != Some(&0xff)).then(|| query.iter().rev().copied().collect())
        }
    }

    struct Stalled;

    #[async_trait]
    impl DnsHijack for Stalled {
        async fn answer(&self, _query: &[u8]) -> Option<Vec<u8>> {
            std::future::pending().await
        }
    }

    struct Captured(std::sync::Mutex<Vec<Vec<u8>>>);

    impl UdpReply for Captured {
        fn poll_write_back(
            &self,
            _cx: &mut std::task::Context<'_>,
            payload: &[u8],
            _from: &Address,
        ) -> std::task::Poll<io::Result<()>> {
            lock(&self.0).push(payload.to_vec());
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn query(id: u16, flags: u8) -> Vec<u8> {
        let mut out = id.to_be_bytes().to_vec();
        out.extend_from_slice(&[flags, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(b"\x01a\x04test\x00\x00\x01\x00\x01");
        out
    }

    fn matcher(entries: &[&str]) -> DnsMatcher {
        DnsMatcher::parse(entries.iter().copied()).unwrap()
    }

    #[test]
    fn any_matches_port_53_on_every_destination() {
        let m = matcher(&["any:53"]);
        assert!(m.matches("8.8.8.8:53".parse().unwrap()));
        assert!(m.matches("[2001:db8::1]:53".parse().unwrap()));
        assert!(!m.matches("8.8.8.8:5353".parse().unwrap()));
    }

    #[test]
    fn schemes_are_read_and_ignored() {
        for entry in ["udp://1.1.1.1:53", "tcp://1.1.1.1:53", "1.1.1.1:53"] {
            let m = matcher(&[entry]);
            assert!(m.matches("1.1.1.1:53".parse().unwrap()), "{entry}");
            assert!(!m.matches("1.0.0.1:53".parse().unwrap()), "{entry}");
        }
        assert!(matcher(&["udp://any:53"]).matches("9.9.9.9:53".parse().unwrap()));
        assert!(matcher(&["[::]:53"]).matches("[::1]:53".parse().unwrap()));
    }

    #[test]
    fn an_unspecified_rule_matches_53_whatever_its_own_port() {
        assert!(matcher(&["any:5353"]).matches("8.8.8.8:53".parse().unwrap()));
    }

    #[test]
    fn bad_entries_are_errors() {
        assert!(DnsMatcher::parse(["nonsense"]).is_err());
        assert!(DnsMatcher::parse(["1.1.1.1"]).is_err());
    }

    #[test]
    fn interface_next_address_is_added() {
        let m = DnsMatcher::default()
            .with_interface_addresses(&[Prefix::parse("198.18.0.1/30").unwrap()]);
        assert!(m.matches("198.18.0.2:53".parse().unwrap()));
        assert!(!m.matches("198.18.0.2:54".parse().unwrap()));
        let m = DnsMatcher::default().with_servers(&["10.0.0.9".parse().unwrap()]);
        assert!(m.matches("10.0.0.9:53".parse().unwrap()));
    }

    #[tokio::test]
    async fn tcp_queries_are_length_prefixed_and_pipelined() {
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(serve_tcp(server, Arc::new(Echo)));
        for query in [&b"abc"[..], &b"hello"[..]] {
            let mut frame = (query.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(query);
            client.write_all(&frame).await.unwrap();
            let mut prefix = [0u8; 2];
            client.read_exact(&mut prefix).await.unwrap();
            let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
            client.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, query.iter().rev().copied().collect::<Vec<_>>());
        }
        client.write_all(&[0, 1, 0xff]).await.unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_udp_query_gets_servfail() {
        let reply = Arc::new(Captured(Default::default()));
        let q = query(7, 0x01);
        answer_udp(
            Arc::new(Stalled),
            reply.clone(),
            "10.0.0.1:53".parse().unwrap(),
            q.clone(),
        )
        .await;
        let sent = lock(&reply.0);
        assert_eq!(sent.as_slice(), &[servfail(&q).unwrap()]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_or_timed_out_tcp_query_gets_servfail_and_the_stream_stays_open() {
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(serve_tcp(server, Arc::new(Stalled)));
        for id in [1u16, 2] {
            let q = query(id, 0x01);
            let mut frame = (q.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&q);
            client.write_all(&frame).await.unwrap();
            let mut prefix = [0u8; 2];
            client.read_exact(&mut prefix).await.unwrap();
            let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
            client.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, servfail(&q).unwrap());
        }
        drop(client);
        task.await.unwrap();
    }
}
