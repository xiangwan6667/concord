//! The core answering raw DNS messages itself: TUN `dns-hijack` and the `dns` outbound, both
//! mihomo's `resolver.RelayDnsConn` and `RelayDnsPacket` (`component/resolver/relay.go`).

use std::io;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

pub const RELAY_TIMEOUT: Duration = Duration::from_secs(5);

/// The engine's resolver. `None` is answered with SERVFAIL, as mihomo does when its resolver fails.
#[async_trait]
pub trait DnsHijack: Send + Sync + 'static {
    async fn answer(&self, query: &[u8]) -> Option<Vec<u8>>;

    /// A stream carries the whole answer where a datagram is cut to the client's size.
    async fn answer_stream(&self, query: &[u8]) -> Option<Vec<u8>> {
        self.answer(query).await
    }
}

/// The answer to one datagram, or `None` when the bytes carry no question to fail.
pub async fn answer_datagram(hijack: &dyn DnsHijack, query: &[u8]) -> Option<Vec<u8>> {
    let answered = timeout(RELAY_TIMEOUT, hijack.answer(query)).await;
    answered.ok().flatten().or_else(|| servfail(query))
}

/// Answers length-prefixed queries in order until the client closes, a read waits past
/// `read_timeout`, or a query cannot be answered at all.
pub async fn serve_stream<S>(mut stream: S, hijack: &dyn DnsHijack, read_timeout: Option<Duration>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = relay_stream(&mut stream, hijack, read_timeout).await;
    let _ = stream.shutdown().await;
}

async fn read_exact<S>(stream: &mut S, buf: &mut [u8], limit: Option<Duration>) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    match limit {
        Some(limit) => timeout(limit, stream.read_exact(buf))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
            .map(drop),
        None => stream.read_exact(buf).await.map(drop),
    }
}

async fn relay_stream<S>(
    stream: &mut S,
    hijack: &dyn DnsHijack,
    read_timeout: Option<Duration>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut query = Vec::new();
    loop {
        let mut prefix = [0u8; 2];
        read_exact(stream, &mut prefix, read_timeout).await?;
        query.resize(usize::from(u16::from_be_bytes(prefix)), 0);
        read_exact(stream, &mut query, read_timeout).await?;
        let answered = timeout(RELAY_TIMEOUT, hijack.answer_stream(&query)).await;
        let answer = answered
            .ok()
            .flatten()
            .or_else(|| servfail(&query))
            .ok_or(io::ErrorKind::InvalidData)?;
        let framed_len = u16::try_from(answer.len()).map_err(|_| io::ErrorKind::InvalidData)?;
        let mut out = Vec::with_capacity(answer.len() + 2);
        out.extend_from_slice(&framed_len.to_be_bytes());
        out.extend_from_slice(&answer);
        stream.write_all(&out).await?;
    }
}

const HEADER_LEN: usize = 12;

fn question_end(query: &[u8]) -> Option<usize> {
    let mut at = HEADER_LEN;
    loop {
        let len = usize::from(*query.get(at)?);
        match len {
            0 => break,
            l if l & 0xc0 == 0xc0 => {
                at += 1;
                break;
            }
            l if l & 0xc0 != 0 => return None,
            l => at += l + 1,
        }
    }
    let end = at + 5;
    (end <= query.len()).then_some(end)
}

/// SERVFAIL echoing the id and the first question, or `None` for bytes that carry no question.
pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    const QR: u8 = 0x80;
    const RECURSION_DESIRED: u8 = 0x01;
    const OPCODE: u8 = 0x78;
    const RECURSION_AVAILABLE: u8 = 0x80;
    const SERVER_FAILURE: u8 = 2;
    if query.get(4..6)? == [0, 0] {
        return None;
    }
    let end = question_end(query)?;
    let mut out = query.get(..end)?.to_vec();
    *out.get_mut(2)? = QR | (query.get(2)? & (OPCODE | RECURSION_DESIRED));
    *out.get_mut(3)? = RECURSION_AVAILABLE | SERVER_FAILURE;
    out.get_mut(4..12)?
        .copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

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

    fn query(id: u16, flags: u8) -> Vec<u8> {
        let mut out = id.to_be_bytes().to_vec();
        out.extend_from_slice(&[flags, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(b"\x01a\x04test\x00\x00\x01\x00\x01");
        out
    }

    async fn exchange(client: &mut tokio::io::DuplexStream, query: &[u8]) -> Vec<u8> {
        let mut frame = (query.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(query);
        client.write_all(&frame).await.unwrap();
        let mut prefix = [0u8; 2];
        client.read_exact(&mut prefix).await.unwrap();
        let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        client.read_exact(&mut answer).await.unwrap();
        answer
    }

    #[test]
    fn servfail_echoes_the_id_and_the_question() {
        let q = query(0xbeef, 0x01);
        let r = servfail(&q).unwrap();
        assert_eq!(&r[..2], &[0xbe, 0xef]);
        assert_eq!(&r[2..4], &[0x81, 0x82]);
        assert_eq!(&r[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&r[12..], &q[12..]);
    }

    #[test]
    fn servfail_skips_what_has_no_question() {
        assert!(servfail(&[1, 2, 3]).is_none());
        assert!(servfail(&query(1, 0)[..16]).is_none());
        let mut empty = query(1, 0);
        empty[5] = 0;
        assert!(servfail(&empty).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_datagram_gets_servfail() {
        let q = query(7, 0x01);
        assert_eq!(answer_datagram(&Stalled, &q).await, servfail(&q));
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_read_timeout_an_idle_stream_stays_open() {
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move { serve_stream(server, &Echo, None).await });
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert_eq!(exchange(&mut client, b"abc").await, b"cba");
        drop(client);
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_timeout_closes_an_idle_stream() {
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(server, &Echo, Some(Duration::from_secs(10))).await;
        });
        task.await.unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }
}
