use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{CoreError, LookupIps};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout};

use super::config::{DnsServer, DnsTransport};
use crate::stack::{Congestion, Stack};

const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const SECOND_ANSWER_GRACE: Duration = Duration::from_millis(100);
const MAX_CACHE: usize = 4096;

struct Cached {
    until: Instant,
    ips: LookupIps,
}

/// Name lookups for `remote-dns-resolve`: the query itself travels through the tunnel.
pub(crate) struct RemoteDns {
    servers: Vec<DnsServer>,
    ipv6: bool,
    cache: Mutex<HashMap<String, Cached>>,
}

fn query(host: &str, rtype: RecordType) -> io::Result<(u16, Vec<u8>)> {
    let mut text = host.to_string();
    if !text.ends_with('.') {
        text.push('.');
    }
    let name = Name::from_utf8(&text)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, rtype));
    let id = message.metadata.id;
    let wire = message
        .to_vec()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok((id, wire))
}

struct Answer {
    ips: Vec<IpAddr>,
    ttl: u32,
    truncated: bool,
}

fn parse(wire: &[u8], id: u16) -> Option<Answer> {
    let message = Message::from_vec(wire).ok()?;
    if message.metadata.id != id {
        return None;
    }
    let mut answer = Answer {
        ips: Vec::new(),
        ttl: u32::MAX,
        truncated: message.metadata.truncation,
    };
    for record in &message.answers {
        let ip = match &record.data {
            RData::A(a) => IpAddr::V4(a.0),
            RData::AAAA(a) => IpAddr::V6(a.0),
            _ => continue,
        };
        answer.ips.push(ip);
        answer.ttl = answer.ttl.min(record.ttl);
    }
    Some(answer)
}

async fn establish(conn: &mut crate::stack::TcpConn) -> io::Result<()> {
    poll_fn(|cx| conn.poll_established(cx)).await
}

async fn over_tcp(
    stack: &Arc<Stack>,
    server: &DnsServer,
    host: &str,
    rtype: RecordType,
    congestion: Congestion,
) -> io::Result<Answer> {
    let (id, wire) = query(host, rtype)?;
    let mut conn = stack.connect_tcp(server.addr, congestion)?;
    establish(&mut conn).await?;
    over_stream(&mut conn, id, &wire).await
}

async fn over_stream(
    conn: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    id: u16,
    wire: &[u8],
) -> io::Result<Answer> {
    let len = u16::try_from(wire.len()).map_err(|_| io::Error::other("query too long"))?;
    let mut framed = len.to_be_bytes().to_vec();
    framed.extend_from_slice(wire);
    conn.write_all(&framed).await?;
    let mut size = [0u8; 2];
    conn.read_exact(&mut size).await?;
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(size))];
    conn.read_exact(&mut reply).await?;
    parse(&reply, id).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}

async fn over_udp(
    stack: &Arc<Stack>,
    server: &DnsServer,
    host: &str,
    types: &[RecordType],
) -> io::Result<Vec<(RecordType, Answer)>> {
    let port = stack.bind_udp()?;
    let mut pending = Vec::new();
    for rtype in types {
        let (id, wire) = query(host, *rtype)?;
        poll_fn(|cx| port.poll_send_to(cx, &wire, server.addr)).await?;
        pending.push((id, *rtype));
    }
    let mut done = Vec::new();
    let mut buf = vec![0u8; 4096];
    while !pending.is_empty() {
        let receive = poll_fn(|cx| port.poll_recv_from(cx, &mut buf));
        let (n, _from) = if done.is_empty() {
            receive.await?
        } else {
            match timeout(SECOND_ANSWER_GRACE, receive).await {
                Ok(received) => received?,
                Err(_) => break,
            }
        };
        let Some(reply) = buf.get(..n) else { continue };
        let found = pending
            .iter()
            .position(|(id, _)| parse(reply, *id).is_some());
        if let Some(index) = found {
            let (id, rtype) = pending.swap_remove(index);
            if let Some(answer) = parse(reply, id) {
                done.push((rtype, answer));
            }
        }
    }
    Ok(done)
}

impl RemoteDns {
    pub(crate) fn new(servers: Vec<DnsServer>, ipv6: bool) -> Self {
        RemoteDns {
            servers,
            ipv6,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, host: &str) -> Option<LookupIps> {
        let cache = lock(&self.cache);
        cache
            .get(host)
            .filter(|entry| entry.until > Instant::now())
            .map(|entry| entry.ips.clone())
    }

    fn store(&self, host: &str, ips: &LookupIps, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let ttl = Duration::from_secs(u64::from(ttl));
        let mut cache = lock(&self.cache);
        if cache.len() >= MAX_CACHE {
            let now = Instant::now();
            cache.retain(|_, entry| entry.until > now);
            if cache.len() >= MAX_CACHE {
                cache.clear();
            }
        }
        cache.insert(
            host.to_string(),
            Cached {
                until: Instant::now() + ttl,
                ips: ips.clone(),
            },
        );
    }

    async fn ask(
        &self,
        stack: &Arc<Stack>,
        server: &DnsServer,
        host: &str,
        congestion: Congestion,
    ) -> io::Result<(LookupIps, u32)> {
        let types: &[RecordType] = if self.ipv6 {
            &[RecordType::A, RecordType::AAAA]
        } else {
            &[RecordType::A]
        };
        let mut answers = match server.transport {
            DnsTransport::Udp => over_udp(stack, server, host, types).await?,
            DnsTransport::Tcp => {
                let mut out = Vec::new();
                for rtype in types {
                    out.push((
                        *rtype,
                        over_tcp(stack, server, host, *rtype, congestion).await?,
                    ));
                }
                out
            }
        };
        for (rtype, answer) in &mut answers {
            if answer.truncated && server.transport == DnsTransport::Udp {
                *answer = over_tcp(stack, server, host, *rtype, congestion).await?;
            }
        }
        let mut ips = LookupIps::default();
        let mut ttl = u32::MAX;
        for (_, answer) in answers {
            ttl = ttl.min(answer.ttl);
            for ip in answer.ips {
                if ip.is_ipv4() {
                    ips.v4.push(ip);
                } else {
                    ips.v6.push(ip);
                }
            }
        }
        Ok((ips, ttl))
    }

    pub(crate) async fn lookup_tcp<F, Fut>(&self, host: &str, connect: F) -> io::Result<LookupIps>
    where
        F: Fn(SocketAddr) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = io::Result<concord_common::BoxStream>> + Send,
    {
        let key = host.to_ascii_lowercase();
        if let Some(hit) = self.cached(&key) {
            return Ok(hit);
        }
        let mut asks: FuturesUnordered<_> = self
            .servers
            .iter()
            .map(|server| {
                let connect = &connect;
                async move {
                    let types: &[RecordType] = if self.ipv6 {
                        &[RecordType::A, RecordType::AAAA]
                    } else {
                        &[RecordType::A]
                    };
                    let mut ips = LookupIps::default();
                    let mut ttl = u32::MAX;
                    for rtype in types {
                        let (id, wire) = query(host, *rtype)?;
                        let mut stream = connect(server.addr).await?;
                        let answer = over_stream(&mut stream, id, &wire).await?;
                        ttl = ttl.min(answer.ttl);
                        for ip in answer.ips {
                            if ip.is_ipv4() {
                                ips.v4.push(ip);
                            } else {
                                ips.v6.push(ip);
                            }
                        }
                    }
                    Ok::<_, io::Error>((ips, ttl))
                }
            })
            .collect();
        let race = async {
            let mut last = CoreError::IpNotFound(host.to_string()).into();
            while let Some(result) = asks.next().await {
                match result {
                    Ok((ips, ttl)) if !ips.is_empty() => return Ok((ips, ttl)),
                    Ok(_) => {}
                    Err(err) => last = err,
                }
            }
            Err::<_, io::Error>(last)
        };
        let (ips, ttl) = timeout(QUERY_TIMEOUT, race)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        self.store(&key, &ips, ttl);
        Ok(ips)
    }

    pub(crate) async fn lookup(
        &self,
        stack: &Arc<Stack>,
        host: &str,
        congestion: Congestion,
    ) -> io::Result<LookupIps> {
        let key = host.to_ascii_lowercase();
        if let Some(hit) = self.cached(&key) {
            return Ok(hit);
        }
        let mut asks: FuturesUnordered<_> = self
            .servers
            .iter()
            .map(|server| self.ask(stack, server, host, congestion))
            .collect();
        let race = async {
            let mut last = io::Error::from(io::ErrorKind::TimedOut);
            while let Some(result) = asks.next().await {
                match result {
                    Ok((ips, ttl)) if !ips.is_empty() => return Ok((ips, ttl)),
                    Ok(_) => last = CoreError::IpNotFound(host.to_string()).into(),
                    Err(err) => last = err,
                }
            }
            Err(last)
        };
        let (ips, ttl) = timeout(QUERY_TIMEOUT, race)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        self.store(&key, &ips, ttl);
        Ok(ips)
    }
}
