#![allow(
    clippy::unwrap_used,
    reason = "tests assert controlled reconnect completion"
)]

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Wake;

fn inner_record(length: u16) -> Vec<u8> {
    let mut record = vec![23, 3, 3];
    record.extend_from_slice(&length.to_be_bytes());
    record.resize(5 + usize::from(length), 42);
    record
}

#[tokio::test(start_paused = true)]
async fn fragmented_raw_records_keep_boundaries_and_the_original_deadline() {
    let pool = Pool::new(
        30,
        Padding::parse(b"stop=0").unwrap(),
        concord_common::Tasks::default(),
    );
    let (client, mut peer) = tokio::io::duplex(16 * 1024);
    let mut stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool, 0);
    stream.recycling = true;
    stream.raw_write = true;
    stream.inner_tls13 = true;

    let record = inner_record(2048);
    stream.queue_batch(record.get(..3).unwrap()).unwrap();
    assert!(stream.outgoing.is_empty());
    let mut rest = record.get(3..).unwrap().to_vec();
    rest.extend_from_slice(&record);
    stream.queue_batch(&rest).unwrap();
    let mut announcement = Vec::new();
    frame(&mut announcement, 5, &record).unwrap();
    frame(&mut announcement, 6, &(record.len() as u32).to_be_bytes()).unwrap();
    assert_eq!(stream.outgoing, announcement);
    assert_eq!(stream.raw_outgoing, record);
    stream.outgoing.clear();
    stream.record_ends.clear();
    stream.raw_outgoing.clear();

    let record = inner_record(5000);
    let (start, rest) = record.split_at(10);
    let (middle, end) = rest.split_at(10);
    stream.write_all(start).await.unwrap();
    tokio::time::advance(Duration::from_millis(12)).await;
    stream.write_all(middle).await.unwrap();
    tokio::time::advance(Duration::from_millis(9)).await;
    let mut next = [0; 1];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        Pin::new(&mut stream)
            .poll_read(&mut cx, &mut ReadBuf::new(&mut next))
            .is_pending()
    );
    assert_eq!(peer.read_u8().await.unwrap(), 5);
    assert_eq!(peer.read_u16().await.unwrap(), 20);
    let mut prefix = vec![0; 20];
    peer.read_exact(&mut prefix).await.unwrap();
    assert_eq!(prefix, record.get(..20).unwrap());

    stream.write_all(end).await.unwrap();
    assert_eq!(peer.read_u8().await.unwrap(), 5);
    assert_eq!(usize::from(peer.read_u16().await.unwrap()), end.len());
    let mut body = vec![0; end.len()];
    peer.read_exact(&mut body).await.unwrap();
    assert_eq!(body, end);
}

#[tokio::test]
async fn unused_prefix_and_packet_count_follow_the_reused_lane() {
    let pool = Pool::new(
        30,
        Padding::parse(b"stop=2\n1=128-128").unwrap(),
        concord_common::Tasks::default(),
    );
    let (client, mut peer) = tokio::io::duplex(1024);
    let mut lane = IdleLane::new(Box::new(client), None);
    lane.prefix = b"auth settings".to_vec();
    let first = MiuStream::new(lane, pool.clone(), 0).with_open(vec![4, 0, 0], false);
    drop(first);
    let (_, lane) = pool.take();
    let mut stream = MiuStream::new(lane.unwrap(), pool.clone(), 0).with_open(vec![4, 0, 0], false);
    stream.flush().await.unwrap();
    let mut bytes = vec![0; b"auth settings".len() + 128];
    peer.read_exact(&mut bytes).await.unwrap();
    assert!(bytes.starts_with(b"auth settings\x04\0\0"));
    stream.shutdown().await.unwrap();
    assert_eq!(peer.read_u8().await.unwrap(), 7);
    assert_eq!(peer.read_u16().await.unwrap(), 0);
    peer.write_all(&[7, 0, 0]).await.unwrap();
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    drop(stream);
    let (_, lane) = pool.take();
    let mut stream = MiuStream::new(lane.unwrap(), pool, 0).with_open(vec![4, 0, 0], false);
    stream.flush().await.unwrap();
    let mut open = [0; 3];
    peer.read_exact(&mut open).await.unwrap();
    assert_eq!(open, [4, 0, 0]);
    assert_eq!(stream.inner.as_ref().unwrap().packet, 2);
}

#[derive(Default)]
struct Signal(AtomicBool);

impl Wake for Signal {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn reconnect_completion_wakes_both_io_directions() {
    for read_last in [false, true] {
        let pool = Pool::new(
            30,
            Padding::parse(b"stop=0").unwrap(),
            concord_common::Tasks::default(),
        );
        let (client, _peer) = tokio::io::duplex(1024);
        let mut stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool, 0);
        stream.recycling = true;
        let (complete, pending) = tokio::sync::oneshot::channel::<()>();
        stream.reconnecting = Some(Box::pin(async move {
            pending.await.map_err(io::Error::other)?;
            Err(io::ErrorKind::ConnectionAborted.into())
        }));
        let reader = Arc::new(Signal::default());
        let writer = Arc::new(Signal::default());
        let read_waker = Waker::from(reader.clone());
        let write_waker = Waker::from(writer.clone());
        let mut read_cx = Context::from_waker(&read_waker);
        let mut write_cx = Context::from_waker(&write_waker);
        let mut output = [0];
        if read_last {
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut write_cx, b"x")
                    .is_pending()
            );
            assert!(
                Pin::new(&mut stream)
                    .poll_read(&mut read_cx, &mut ReadBuf::new(&mut output))
                    .is_pending()
            );
        } else {
            assert!(
                Pin::new(&mut stream)
                    .poll_read(&mut read_cx, &mut ReadBuf::new(&mut output))
                    .is_pending()
            );
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut write_cx, b"x")
                    .is_pending()
            );
        }
        complete.send(()).unwrap();
        assert!(
            reader.0.load(Ordering::SeqCst),
            "reader must be woken when the writer stops polling"
        );
        assert!(
            writer.0.load(Ordering::SeqCst),
            "writer must be woken when the reader stops polling"
        );
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut read_cx, &mut ReadBuf::new(&mut output)),
            Poll::Ready(Err(_)),
        ));
    }
}

#[tokio::test]
async fn reconnect_completion_wakes_flush_and_shutdown_waiters() {
    for shutdown in [false, true] {
        let pool = Pool::new(
            30,
            Padding::parse(b"stop=0").unwrap(),
            concord_common::Tasks::default(),
        );
        let (client, _peer) = tokio::io::duplex(1024);
        let mut stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool, 0);
        stream.recycling = true;
        let (complete, pending) = tokio::sync::oneshot::channel::<()>();
        stream.reconnecting = Some(Box::pin(async move {
            pending.await.map_err(io::Error::other)?;
            Err(io::ErrorKind::ConnectionAborted.into())
        }));
        let writer = Arc::new(Signal::default());
        let write_waker = Waker::from(writer.clone());
        let mut write_cx = Context::from_waker(&write_waker);
        let result = if shutdown {
            Pin::new(&mut stream).poll_shutdown(&mut write_cx)
        } else {
            Pin::new(&mut stream).poll_flush(&mut write_cx)
        };
        assert!(result.is_pending());
        let mut output = [0];
        let mut read_cx = Context::from_waker(Waker::noop());
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut read_cx, &mut ReadBuf::new(&mut output))
                .is_pending()
        );
        complete.send(()).unwrap();
        assert!(writer.0.load(Ordering::SeqCst));
        let result = if shutdown {
            Pin::new(&mut stream).poll_shutdown(&mut write_cx)
        } else {
            Pin::new(&mut stream).poll_flush(&mut write_cx)
        };
        assert!(matches!(result, Poll::Ready(Err(_))));
    }
}
