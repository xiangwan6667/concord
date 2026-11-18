use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::mpsc;
use std::task::{Context, Poll};

use concord_common::Initiator;
use futures_util::poll;
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader, DuplexStream, ReadBuf};
use tokio::sync::oneshot;

use super::*;
use crate::client::EXCHANGE_TIMEOUT;
use crate::dialer::{Shared, Via};
use crate::msg::{answer_ips, build_query};
use crate::tests::support::{Sink, answer_with, deps};

struct PauseAfterResponse<R> {
    inner: R,
    remaining: usize,
    saw_idle_read: bool,
    gate: Option<(oneshot::Sender<()>, mpsc::Receiver<()>)>,
}

impl<R: AsyncRead + Unpin> AsyncRead for PauseAfterResponse<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.remaining == 0 {
            // Hyper checks for more input before forwarding the final frame and again
            // before polling the request queue. Pause on the second read.
            if self.saw_idle_read
                && let Some((paused, resume)) = self.gate.take()
            {
                let _ = paused.send(());
                let _ = resume.recv_timeout(EXCHANGE_TIMEOUT);
            }
            self.saw_idle_read = true;
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.remaining = self.remaining.saturating_sub(buf.filled().len() - before);
        result
    }
}

fn response(query: &Message, ip: Ipv4Addr) -> Vec<u8> {
    let mut reply = answer_with(ip)(query).unwrap();
    reply.metadata.id = 0;
    let body = encode(&reply).unwrap();
    let mut wire = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend(body);
    wire
}

async fn answer_request(stream: &mut BufReader<DuplexStream>, response: &[u8]) -> io::Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if stream.read_until(b'\n', &mut line).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if line == b"\r\n" {
            return stream.write_all(response).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn immediate_http1_reuse_waits_for_the_same_connection() {
    let first = build_query("first.test", RecordType::A).unwrap();
    let second = build_query("second.test", RecordType::A).unwrap();
    let ip = Ipv4Addr::new(10, 0, 2, 1);
    let wire = response(&first, ip);
    let (local, peer) = tokio::io::duplex(1024);
    let (read, write) = tokio::io::split(local);
    let (paused, at_idle_read) = oneshot::channel();
    let (release, resume) = mpsc::channel();
    let read = PauseAfterResponse {
        inner: read,
        remaining: wire.len(),
        saw_idle_read: false,
        gate: Some((paused, resume)),
    };
    let (sender, connection) = http1::handshake(TokioIo::new(tokio::io::join(read, write)))
        .await
        .unwrap();
    let (spare_socket, _spare_peer) = tokio::io::duplex(64);
    let (spare, _spare_connection) = http1::handshake(TokioIo::new(spare_socket)).await.unwrap();
    tokio::spawn(connection);
    let deps = deps(&Arc::new(Sink::default()));
    let connector = Arc::new(Connector::new(
        Arc::new(Shared {
            sockets: deps.sockets,
            dialer: deps.dialer,
            sock_opts: deps.sock_opts,
            trust: deps.trust,
            ipv6: deps.ipv6,
        }),
        Via::Named("unavailable".to_string()),
        None,
    ));
    let client = DohClient {
        target: DohTarget {
            secure: false,
            host: "localhost".to_string(),
            port: 80,
            path: "/dns-query".to_string(),
        },
        connector,
        tls: None,
        h2: Mutex::new(None),
        h1: Mutex::new(vec![spare, sender]),
        resets: crate::resets::Resets::new(),
    };

    let cx = Cx {
        initiator: Initiator::App,
    };
    let mut peer = BufReader::new(peer);
    let (first, ()) = tokio::try_join!(
        client.exchange(&first, cx),
        answer_request(&mut peer, &wire)
    )
    .unwrap();
    assert_eq!(answer_ips(&first), [IpAddr::V4(ip)]);

    tokio::time::timeout(EXCHANGE_TIMEOUT, at_idle_read)
        .await
        .unwrap()
        .unwrap();
    assert!(!lock(&client.h1).last().unwrap().is_ready());
    let next = client.exchange(&second, cx);
    tokio::pin!(next);
    let waiting = poll!(&mut next);
    assert!(
        waiting.is_pending(),
        "reuse attempted a fresh dial: {waiting:?}"
    );
    release.send(()).unwrap();
    let wire = response(&second, ip);
    let (reply, ()) = tokio::try_join!(next, answer_request(&mut peer, &wire)).unwrap();
    assert_eq!(answer_ips(&reply), [IpAddr::V4(ip)]);
    assert_eq!(lock(&client.h1).len(), 2);
}
