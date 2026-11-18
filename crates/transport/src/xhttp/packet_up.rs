use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::task::AtomicWaker;
use tokio::io::AsyncWrite;
use tokio::sync::Notify;

use super::config::Range;
use super::request::RequestFactory;
use super::transport::Lease;

#[derive(Default)]
struct State {
    buf: Vec<u8>,
    failure: Option<(io::ErrorKind, String)>,
    closed: bool,
    posting: bool,
}

struct Shared {
    state: Mutex<State>,
    data: Notify,
    space: AtomicWaker,
    max_bytes: usize,
}

fn lock(shared: &Shared) -> MutexGuard<'_, State> {
    concord_common::sync::lock(&shared.state)
}

/// The uplink of `packet-up`: bytes pile up for at least the minimum interval and
/// leave as numbered POSTs of at most `max_bytes`.
pub(crate) struct PacketUp {
    shared: Arc<Shared>,
}

impl PacketUp {
    pub fn start(
        factory: Arc<RequestFactory>,
        transport: Lease,
        session: String,
        max_bytes: usize,
        interval: Range,
        tasks: &concord_common::Tasks,
    ) -> PacketUp {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            data: Notify::new(),
            space: AtomicWaker::new(),
            max_bytes,
        });
        tasks.spawn(upload_loop(
            shared.clone(),
            factory,
            transport,
            session,
            interval,
        ));
        PacketUp { shared }
    }
}

async fn upload_loop(
    shared: Arc<Shared>,
    factory: Arc<RequestFactory>,
    transport: Lease,
    session: String,
    interval: Range,
) {
    let mut seq: u64 = 0;
    loop {
        loop {
            {
                let state = lock(&shared);
                if !state.buf.is_empty() {
                    break;
                }
                if state.closed {
                    return;
                }
            }
            shared.data.notified().await;
        }
        tokio::time::sleep(Duration::from_millis(interval.rand() as u64)).await;
        let payload = {
            let mut state = lock(&shared);
            state.posting = true;
            std::mem::take(&mut state.buf)
        };
        shared.space.wake();
        let outcome = match factory.packet_request(&session, seq, &payload) {
            Ok((request, body)) => match transport.fixed(&request, body).await {
                Ok(200) => Ok(()),
                Ok(status) => Err((
                    io::ErrorKind::Other,
                    format!("xhttp packet-up bad status: {status}"),
                )),
                Err(err) => Err((err.kind(), err.to_string())),
            },
            Err(err) => Err((err.kind(), err.to_string())),
        };
        seq += 1;
        let mut state = lock(&shared);
        state.posting = false;
        if let Err(failure) = outcome {
            state.failure = Some(failure);
            state.buf.clear();
            drop(state);
            shared.space.wake();
            return;
        }
        drop(state);
        shared.space.wake();
    }
}

impl AsyncWrite for PacketUp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let shared = &self.shared;
        shared.space.register(cx.waker());
        let mut state = lock(shared);
        if let Some((kind, message)) = &state.failure {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if state.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = shared.max_bytes.saturating_sub(state.buf.len());
        if room == 0 {
            return Poll::Pending;
        }
        let take = data.len().min(room);
        let Some(chunk) = data.get(..take) else {
            return Poll::Ready(Ok(0));
        };
        state.buf.extend_from_slice(chunk);
        drop(state);
        shared.data.notify_one();
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        shared.space.register(cx.waker());
        let mut state = lock(shared);
        if let Some((kind, message)) = &state.failure {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        state.closed = true;
        if state.buf.is_empty() && !state.posting {
            return Poll::Ready(Ok(()));
        }
        drop(state);
        shared.data.notify_one();
        Poll::Pending
    }
}

impl Drop for PacketUp {
    fn drop(&mut self) {
        lock(&self.shared).closed = true;
        self.shared.data.notify_one();
    }
}
