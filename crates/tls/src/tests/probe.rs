//! M0 probe for XTLS Vision: can the stream leave the record layer between two
//! records without losing or repeating a byte?

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use concord_common::Stream;
use concord_common::sync::lock;
use rustls_pki_types::ServerName;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::sync::oneshot;

use super::support::{Ca, Leaf, ServerSpec, server_config};
use crate::fingerprints::ClientFingerprint;
use crate::policy::CertPolicy;
use crate::{TlsConn, TlsConnector, TlsOptions};

#[derive(Debug)]
struct Tap {
    inner: DuplexStream,
    read: Arc<AtomicUsize>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.read
            .fetch_add(buf.filled().len() - before, Ordering::SeqCst);
        poll
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &poll {
            lock(&self.written).extend_from_slice(&data[..*n]);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Stream for Tap {}

fn payloads() -> [Vec<u8>; 3] {
    [vec![0xa1; 100], vec![0xb2; 3000], vec![0xc3; 50]]
}

struct Probe {
    client: Tap,
    consumed: Arc<AtomicUsize>,
    wire: Arc<Mutex<Vec<u8>>>,
    ready: oneshot::Receiver<()>,
}

fn start_server(leaf: &Leaf) -> Probe {
    let (client_end, server_end) = duplex(1 << 20);
    let consumed = Arc::new(AtomicUsize::new(0));
    let wire = Arc::new(Mutex::new(Vec::new()));
    let (ready_tx, ready) = oneshot::channel();
    let server_tap = Tap {
        inner: server_end,
        read: Arc::new(AtomicUsize::new(0)),
        written: wire.clone(),
    };
    let config = server_config(
        leaf,
        &ServerSpec {
            tls13_only: true,
            ..ServerSpec::default()
        },
    );
    tokio::spawn(async move {
        let mut stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(server_tap)
            .await
            .unwrap();
        for payload in payloads() {
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
        }
        let _ = ready_tx.send(());
        stream.shutdown().await.unwrap();
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink).await;
    });
    Probe {
        client: Tap {
            inner: client_end,
            read: consumed.clone(),
            written: Arc::new(Mutex::new(Vec::new())),
        },
        consumed,
        wire,
        ready,
    }
}

fn records(wire: &[u8]) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 5 <= wire.len() {
        let len = usize::from(u16::from_be_bytes([wire[at + 3], wire[at + 4]]));
        out.push((wire[at], at + 5 + len));
        at += 5 + len;
    }
    assert_eq!(at, wire.len(), "wire ends inside a record");
    out
}

async fn connect(fp: Option<ClientFingerprint>, leaf: &Leaf, ca: &Ca, tap: Tap) -> TlsConn {
    let connector = TlsConnector::new(
        TlsOptions {
            server_name: Some("probe.test".into()),
            client_fingerprint: fp,
            ..TlsOptions::default()
        },
        ca.trust(),
    )
    .unwrap();
    let _ = leaf;
    connector.connect(Box::new(tap), "").await.unwrap()
}

async fn read_raw_rest(conn: &mut TlsConn) -> Vec<u8> {
    let mut rest = Vec::new();
    conn.raw_mut().read_to_end(&mut rest).await.unwrap();
    rest
}

fn assert_clean_continuation(wire: &[u8], consumed: usize, rest: &[u8]) {
    assert_eq!(
        rest,
        &wire[consumed..],
        "bytes lost or repeated across the switch"
    );
    let boundaries: Vec<usize> = records(wire).iter().map(|(_, end)| *end).collect();
    assert!(
        boundaries.contains(&consumed),
        "TLS stopped inside a record"
    );
    let tail = records(rest);
    assert_eq!(
        tail.len(),
        3,
        "expected two data records and the close alert"
    );
    assert_eq!(tail[0].0, 23);
    assert_eq!(tail[0].1, 5 + 3000 + 1 + 16);
    assert_eq!(tail[1].1 - tail[0].1, 5 + 50 + 1 + 16);
    assert_eq!(tail[2].0, 23);
}

async fn switch_after_a_whole_record(fp: Option<ClientFingerprint>) {
    let ca = Ca::new();
    let leaf = ca.leaf(&["probe.test"]);
    let probe = start_server(&leaf);
    let consumed = probe.consumed.clone();
    let mut conn = connect(fp, &leaf, &ca, probe.client).await;
    probe.ready.await.unwrap();

    let [a, _, _] = payloads();
    let mut got = vec![0u8; a.len()];
    conn.read_exact(&mut got).await.unwrap();
    assert_eq!(got, a);
    assert!(!conn.has_pending_plaintext(), "{fp:?}");
    assert!(conn.at_record_boundary(), "{fp:?}");

    let taken = consumed.load(Ordering::SeqCst);
    let rest = read_raw_rest(&mut conn).await;
    let wire = lock(&probe.wire).clone();
    assert_clean_continuation(&wire, taken, &rest);
}

async fn switch_in_the_middle_of_a_record(fp: Option<ClientFingerprint>) {
    let ca = Ca::new();
    let leaf = ca.leaf(&["probe.test"]);
    let probe = start_server(&leaf);
    let consumed = probe.consumed.clone();
    let mut conn = connect(fp, &leaf, &ca, probe.client).await;
    probe.ready.await.unwrap();

    let [a, _, _] = payloads();
    let mut head = vec![0u8; 40];
    conn.read_exact(&mut head).await.unwrap();
    assert_eq!(head, a[..40]);
    assert!(conn.has_pending_plaintext(), "{fp:?}");
    assert!(conn.at_record_boundary(), "{fp:?}");

    let mut tail = Vec::new();
    conn.drain_plaintext(&mut tail);
    assert_eq!(tail, a[40..], "{fp:?}");
    assert!(!conn.has_pending_plaintext());

    let taken = consumed.load(Ordering::SeqCst);
    let rest = read_raw_rest(&mut conn).await;
    let wire = lock(&probe.wire).clone();
    assert_clean_continuation(&wire, taken, &rest);
}

#[tokio::test]
async fn rustls_switches_to_raw_on_a_record_boundary() {
    switch_after_a_whole_record(None).await;
    switch_in_the_middle_of_a_record(None).await;
}

#[tokio::test]
async fn boring_switches_to_raw_on_a_record_boundary() {
    switch_after_a_whole_record(Some(ClientFingerprint::Chrome)).await;
    switch_in_the_middle_of_a_record(Some(ClientFingerprint::Chrome)).await;
}

#[tokio::test]
async fn raw_writes_reach_the_wire_unchanged() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["probe.test"]);
    for fp in [None, Some(ClientFingerprint::Chrome)] {
        let probe = start_server(&leaf);
        let written = probe.client.written.clone();
        let mut conn = connect(fp, &leaf, &ca, probe.client).await;
        probe.ready.await.unwrap();
        conn.write_all(b"inside").await.unwrap();
        conn.flush().await.unwrap();
        let before = lock(&written).len();
        conn.raw_mut().write_all(b"not a record").await.unwrap();
        conn.raw_mut().flush().await.unwrap();
        let wire = lock(&written).clone();
        assert!(before > 0 && wire.len() == before + 12, "{fp:?}");
        assert_eq!(&wire[before..], b"not a record");
    }
}

#[tokio::test]
async fn rustls_alone_reads_past_the_record_and_boring_does_not() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["probe.test"]);
    let name = ServerName::try_from("probe.test").unwrap();

    let probe = start_server(&leaf);
    let consumed = probe.consumed.clone();
    let config = crate::rustls_backend::client_config(
        Arc::new(CertPolicy::new(&TlsOptions::default(), ca.trust()).unwrap()),
        Vec::new(),
        None,
        false,
        None,
    )
    .unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(config)
        .connect(name.clone(), probe.client)
        .await
        .unwrap();
    probe.ready.await.unwrap();
    let [a, ..] = payloads();
    let mut got = vec![0u8; a.len()];
    stream.read_exact(&mut got).await.unwrap();
    let wire = lock(&probe.wire).clone();
    let boundaries: Vec<usize> = records(&wire).iter().map(|(_, end)| *end).collect();
    assert!(
        !boundaries.contains(&consumed.load(Ordering::SeqCst))
            || consumed.load(Ordering::SeqCst) == wire.len(),
        "plain rustls unexpectedly stopped on a boundary short of the end"
    );
    assert_eq!(
        consumed.load(Ordering::SeqCst),
        wire.len(),
        "rustls buffers the rest of the wire"
    );

    let probe = start_server(&leaf);
    let consumed = probe.consumed.clone();
    let spec = ClientFingerprint::Chrome.spec().unwrap();
    let boring = crate::boring_backend::BoringConnector::new(
        spec,
        Arc::new(CertPolicy::new(&TlsOptions::default(), ca.trust()).unwrap()),
        &[],
        None,
        None,
    )
    .unwrap();
    let mut stream = boring.connect_over(name, probe.client).await.unwrap();
    probe.ready.await.unwrap();
    let mut got = vec![0u8; a.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, a);
    let wire = lock(&probe.wire).clone();
    let boundaries: Vec<usize> = records(&wire).iter().map(|(_, end)| *end).collect();
    let taken = consumed.load(Ordering::SeqCst);
    assert!(
        boundaries.contains(&taken),
        "BoringSSL read past a record boundary"
    );
    assert!(taken < wire.len(), "BoringSSL took the whole wire");
}
