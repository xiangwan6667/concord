use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use concord_common::sync::lock;
use h3::quic::{
    BidiStream, Connection, ConnectionErrorIncoming, OpenStreams, RecvStream, SendStream,
    StreamErrorIncoming, StreamId, WriteBuf,
};

struct Recv {
    chunks: VecDeque<Bytes>,
    fetched: Arc<AtomicUsize>,
}

impl RecvStream for Recv {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let chunk = self.chunks.pop_front();
        if let Some(chunk) = &chunk {
            self.fetched.fetch_add(chunk.len(), Ordering::Relaxed);
        }
        Poll::Ready(Ok(chunk))
    }
    fn stop_sending(&mut self, _: u64) {}
    fn recv_id(&self) -> StreamId {
        StreamId::try_from(0).unwrap()
    }
}

struct Sink(u64);

impl SendStream<Bytes> for Sink {
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(Ok(()))
    }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        drop(data.into());
        Ok(())
    }
    fn poll_finish(&mut self, _: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(Ok(()))
    }
    fn reset(&mut self, _: u64) {}
    fn send_id(&self) -> StreamId {
        StreamId::try_from(self.0).unwrap()
    }
}

struct Bidi(Sink, Recv);

impl RecvStream for Bidi {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.1.poll_data(cx)
    }
    fn stop_sending(&mut self, code: u64) {
        self.1.stop_sending(code);
    }
    fn recv_id(&self) -> StreamId {
        self.1.recv_id()
    }
}

impl SendStream<Bytes> for Bidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.0.poll_ready(cx)
    }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.0.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.0.poll_finish(cx)
    }
    fn reset(&mut self, code: u64) {
        self.0.reset(code);
    }
    fn send_id(&self) -> StreamId {
        self.0.send_id()
    }
}

impl BidiStream<Bytes> for Bidi {
    type SendStream = Sink;
    type RecvStream = Recv;
    fn split(self) -> (Sink, Recv) {
        (self.0, self.1)
    }
}

#[derive(Clone)]
struct Memory {
    response: Arc<Mutex<Option<Recv>>>,
    uni: Arc<AtomicU64>,
}

impl OpenStreams<Bytes> for Memory {
    type BidiStream = Bidi;
    type SendStream = Sink;
    fn poll_open_bidi(&mut self, _: &mut Context<'_>) -> Poll<Result<Bidi, StreamErrorIncoming>> {
        Poll::Ready(Ok(Bidi(Sink(0), lock(&self.response).take().unwrap())))
    }
    fn poll_open_send(&mut self, _: &mut Context<'_>) -> Poll<Result<Sink, StreamErrorIncoming>> {
        Poll::Ready(Ok(Sink(self.uni.fetch_add(4, Ordering::Relaxed))))
    }
    fn close(&mut self, _: h3::error::Code, _: &[u8]) {}
}

impl Connection<Bytes> for Memory {
    type RecvStream = Recv;
    type OpenStreams = Self;
    fn poll_accept_recv(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Recv, ConnectionErrorIncoming>> {
        Poll::Pending
    }
    fn poll_accept_bidi(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Bidi, ConnectionErrorIncoming>> {
        Poll::Pending
    }
    fn opener(&self) -> Self {
        self.clone()
    }
}

async fn response(
    wire: Vec<u8>,
    quantum: usize,
) -> (
    h3::client::RequestStream<Bidi, Bytes>,
    Arc<AtomicUsize>,
    (
        h3::client::Connection<Memory, Bytes>,
        h3::client::SendRequest<Memory, Bytes>,
    ),
) {
    let fetched = Arc::new(AtomicUsize::new(0));
    let chunks = wire.chunks(quantum).map(Bytes::copy_from_slice).collect();
    let memory = Memory {
        response: Arc::new(Mutex::new(Some(Recv {
            chunks,
            fetched: fetched.clone(),
        }))),
        uni: Arc::new(AtomicU64::new(2)),
    };
    let (driver, mut sender) = h3::client::builder()
        .send_grease(false)
        .build(memory)
        .await
        .unwrap();
    let request = http::Request::builder()
        .uri("https://localhost/")
        .body(())
        .unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), 200);
    (stream, fetched, (driver, sender))
}

async fn bounded_read_ahead(header: &[u8], payload: usize, quantum: usize) {
    // RFC 9204 static table index 25: :status=200, with a zero dynamic-table prefix.
    let mut wire = vec![1, 3, 0, 0, 0xd9];
    for _ in 0..1024 {
        wire.extend_from_slice(header);
        wire.extend(std::iter::repeat_n(42, payload));
    }
    let (mut stream, fetched, _driver) = response(wire, quantum).await;
    let mut delivered = 0;
    while delivered < 64 * payload {
        let mut data = stream.recv_data().await.unwrap().unwrap();
        let bytes = data.copy_to_bytes(data.remaining());
        assert!(!bytes.is_empty());
        assert!(bytes.iter().all(|b| *b == 42));
        delivered += bytes.len();
    }
    let needed = 5 + delivered + delivered.div_ceil(payload) * header.len();
    let fetched = fetched.load(Ordering::Relaxed);
    println!(
        "payload={payload}, quantum={quantum}, delivered={delivered}, fetched={fetched}, limit={}",
        needed + quantum
    );
    assert!(
        fetched <= needed + quantum,
        "read {} bytes for {delivered} delivered bytes; transport reads outran the consumer",
        fetched
    );
}

#[tokio::test]
async fn h3_small_data_frames_do_not_accumulate_unconsumed_transport_chunks() {
    bounded_read_ahead(&[0, 16], 16, 32).await;
}

#[tokio::test]
async fn h3_fragmented_data_frames_drain_buffered_bytes_before_reading_more() {
    bounded_read_ahead(&[0, 0x40, 0x80], 128, 31).await;
}

#[tokio::test]
async fn h3_truncated_data_payload_is_rejected_after_buffered_bytes() {
    for available in [0, 10] {
        let mut wire = vec![1, 3, 0, 0, 0xd9, 0, 16];
        wire.extend(std::iter::repeat_n(42, available));
        let (mut stream, _, _driver) = response(wire, 4).await;
        loop {
            match stream.recv_data().await {
                Err(_) => break,
                Ok(Some(_)) => {}
                Ok(None) => panic!("truncated DATA frame was accepted as clean EOF"),
            }
        }
    }
}

#[tokio::test]
async fn h3_truncated_frame_header_is_rejected_after_buffered_bytes() {
    let (mut stream, _, _driver) = response(vec![1, 3, 0, 0, 0xd9, 0], 2).await;
    assert!(stream.recv_data().await.is_err());
}

#[tokio::test]
async fn h3_fragmented_data_reaches_clean_eof_after_the_payload() {
    let (mut stream, _, _driver) = response(vec![1, 3, 0, 0, 0xd9, 0, 3, 1, 2, 3], 2).await;
    let mut delivered = Vec::new();
    while let Some(mut data) = stream.recv_data().await.unwrap() {
        delivered.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    }
    assert_eq!(delivered, [1, 2, 3]);
}
