use std::collections::VecDeque;
use std::io;
use std::sync::Mutex;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::task::AtomicWaker;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use concord_common::sync::lock;
use concord_common::{BoxWrite, Tasks};

#[derive(Default)]
struct State {
    chunks: VecDeque<Bytes>,
    fin: bool,
    error: Option<(io::ErrorKind, String)>,
    read_closed: bool,
}

/// Data a session task has received for one stream, until the stream reads it.
#[derive(Default)]
pub(super) struct Inbox {
    state: Mutex<State>,
    waker: AtomicWaker,
}

impl Inbox {
    /// False when the read side has closed and the data was dropped.
    pub fn push(&self, data: Bytes) -> bool {
        let mut state = lock(&self.state);
        let kept = !state.read_closed;
        if kept {
            state.chunks.push_back(data);
        }
        drop(state);
        self.waker.wake();
        kept
    }

    pub fn fin(&self) {
        lock(&self.state).fin = true;
        self.waker.wake();
    }

    pub fn fail(&self, kind: io::ErrorKind, message: &str) {
        lock(&self.state).error = Some((kind, message.to_owned()));
        self.waker.wake();
    }

    /// Drops what is buffered and returns how many bytes that was.
    pub fn close_read(&self) -> usize {
        let mut state = lock(&self.state);
        state.read_closed = true;
        let dropped = state.chunks.iter().map(Bytes::len).sum();
        state.chunks.clear();
        drop(state);
        self.waker.wake();
        dropped
    }

    /// `Ready(Ok(0))` is the end of the stream.
    pub fn poll_read(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<usize>> {
        self.waker.register(cx.waker());
        let mut state = lock(&self.state);
        if let Some(front) = state.chunks.front_mut() {
            let take = front.len().min(buf.remaining());
            buf.put_slice(front.split_to(take).as_ref());
            if front.is_empty() {
                state.chunks.pop_front();
            }
            return Poll::Ready(Ok(take));
        }
        if let Some((kind, message)) = &state.error {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if state.fin || state.read_closed {
            return Poll::Ready(Ok(0));
        }
        Poll::Pending
    }
}

/// Queues a frame from a context that cannot wait for room.
pub(super) fn send_detached(tasks: &Tasks, tx: &mpsc::Sender<Vec<u8>>, frame: Vec<u8>) {
    if let Err(mpsc::error::TrySendError::Full(frame)) = tx.try_send(frame) {
        let tx = tx.clone();
        tasks.spawn_detached(async move {
            let _ = tx.send(frame).await;
        });
    }
}

pub(super) async fn write_frames(
    mut io: BoxWrite,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    while let Some(frame) = rx.recv().await {
        write_one(&mut io, &frame).await?;
    }
    Ok(())
}

async fn write_one<W: AsyncWrite + Unpin>(io: &mut W, frame: &[u8]) -> io::Result<()> {
    io.write_all(frame).await?;
    io.flush().await
}
