#![allow(
    clippy::unwrap_used,
    reason = "tests assert controlled reconnect completion"
)]

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Wake;

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
