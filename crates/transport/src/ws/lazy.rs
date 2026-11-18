use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use concord_common::sync::lock;
use concord_common::{BoxRead, BoxStream, BoxWrite, Stream, Tasks};
use futures_util::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

use super::{WsOptions, connect};

struct Parts {
    io: BoxStream,
    opts: WsOptions,
    host: String,
    tasks: Tasks,
}

#[derive(Default)]
struct Slot {
    result: Option<io::Result<BoxStream>>,
    read: Option<BoxRead>,
    write: Option<BoxWrite>,
    failed: Option<(io::ErrorKind, String)>,
}

impl Slot {
    fn settle(&mut self) {
        match self.result.take() {
            Some(Ok(io)) => {
                let (read, write) = Box::new(io).into_split();
                self.read = Some(read);
                self.write = Some(write);
            }
            Some(Err(err)) => self.failed = Some((err.kind(), err.to_string())),
            None => {}
        }
    }
}

#[derive(Default)]
struct Shared {
    slot: Mutex<Slot>,
    read: AtomicWaker,
    write: AtomicWaker,
}

impl Shared {
    fn slot(&self) -> std::sync::MutexGuard<'_, Slot> {
        lock(&self.slot)
    }
}

struct Abort(JoinHandle<()>);

impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum State {
    Idle(Option<Parts>),
    Connecting { _abort: Abort },
    Ready(BoxStream),
    Failed(io::ErrorKind, String),
}

/// Holds the handshake back until the first write, so up to `max` bytes of it can
/// ride in the upgrade request as early data. The handshake runs on its own task
/// and wakes the read and write sides separately.
pub(crate) struct LazyWs {
    state: State,
    max: usize,
    shared: Arc<Shared>,
}

#[derive(Clone, Copy)]
enum Side {
    Read,
    Write,
}

impl LazyWs {
    pub fn new(io: BoxStream, opts: WsOptions, host: String, max: usize, tasks: Tasks) -> Self {
        LazyWs {
            state: State::Idle(Some(Parts {
                io,
                opts,
                host,
                tasks,
            })),
            max,
            shared: Arc::new(Shared::default()),
        }
    }

    fn poll_connect(&mut self, cx: &mut Context<'_>, side: Side) -> Poll<io::Result<()>> {
        if matches!(self.state, State::Connecting { .. }) {
            match side {
                Side::Read => self.shared.read.register(cx.waker()),
                Side::Write => self.shared.write.register(cx.waker()),
            }
            let finished = self.shared.slot().result.take();
            match finished {
                None => return Poll::Pending,
                Some(Ok(io)) => self.state = State::Ready(io),
                Some(Err(err)) => self.state = State::Failed(err.kind(), err.to_string()),
            }
        }
        match &self.state {
            State::Failed(kind, message) => {
                Poll::Ready(Err(io::Error::new(*kind, message.clone())))
            }
            _ => Poll::Ready(Ok(())),
        }
    }

    fn start(&mut self, early: Vec<u8>) {
        let State::Idle(parts) = &mut self.state else {
            return;
        };
        let Some(Parts {
            io,
            opts,
            host,
            tasks,
        }) = parts.take()
        else {
            return;
        };
        let shared = self.shared.clone();
        let task = tasks.spawn(async move {
            let outcome = connect(io, &opts, &host, Some(&early)).await;
            shared.slot().result = Some(outcome);
            shared.read.wake();
            shared.write.wake();
        });
        self.state = State::Connecting {
            _abort: Abort(task),
        };
        self.shared.read.wake();
    }
}

impl AsyncRead for LazyWs {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, State::Idle(_)) {
            this.shared.read.register(cx.waker());
            return Poll::Pending;
        }
        ready!(this.poll_connect(cx, Side::Read))?;
        match &mut this.state {
            State::Ready(io) => Pin::new(io).poll_read(cx, buf),
            _ => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
}

impl AsyncWrite for LazyWs {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if matches!(this.state, State::Idle(_)) {
            let take = data.len().min(this.max);
            let Some(early) = data.get(..take).filter(|e| !e.is_empty()) else {
                return Poll::Ready(Ok(0));
            };
            this.start(early.to_vec());
            return Poll::Ready(Ok(take));
        }
        ready!(this.poll_connect(cx, Side::Write))?;
        match &mut this.state {
            State::Ready(io) => Pin::new(io).poll_write(cx, data),
            _ => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, State::Idle(_)) {
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_connect(cx, Side::Write))?;
        match &mut this.state {
            State::Ready(io) => Pin::new(io).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, State::Idle(_)) {
            this.state = State::Failed(
                io::ErrorKind::BrokenPipe,
                "closed before the handshake".into(),
            );
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_connect(cx, Side::Write))?;
        match &mut this.state {
            State::Ready(io) => Pin::new(io).poll_shutdown(cx),
            _ => Poll::Ready(Ok(())),
        }
    }
}

struct Guard(Mutex<Option<Abort>>);

fn failure(kind: io::ErrorKind, message: &str) -> io::Error {
    io::Error::new(kind, message.to_owned())
}

enum ReadState {
    Waiting,
    Ready(BoxRead),
    Failed(io::ErrorKind, String),
}

struct LazyRead {
    state: ReadState,
    shared: Arc<Shared>,
    _guard: Arc<Guard>,
}

impl AsyncRead for LazyRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let ReadState::Waiting = this.state {
            this.shared.read.register(cx.waker());
            let mut slot = this.shared.slot();
            slot.settle();
            if let Some(read) = slot.read.take() {
                this.state = ReadState::Ready(read);
            } else if let Some((kind, message)) = slot.failed.clone() {
                this.state = ReadState::Failed(kind, message);
            } else {
                return Poll::Pending;
            }
        }
        match &mut this.state {
            ReadState::Ready(io) => Pin::new(io).poll_read(cx, buf),
            ReadState::Failed(kind, message) => Poll::Ready(Err(failure(*kind, message))),
            ReadState::Waiting => Poll::Pending,
        }
    }
}

enum WriteState {
    Idle(Option<Parts>),
    Connecting,
    Ready(BoxWrite),
    Failed(io::ErrorKind, String),
}

struct LazyWrite {
    state: WriteState,
    max: usize,
    shared: Arc<Shared>,
    guard: Arc<Guard>,
}

impl LazyWrite {
    fn start(&mut self, early: Vec<u8>) {
        let WriteState::Idle(parts) = &mut self.state else {
            return;
        };
        let Some(Parts {
            io,
            opts,
            host,
            tasks,
        }) = parts.take()
        else {
            return;
        };
        let shared = self.shared.clone();
        let task = tasks.spawn(async move {
            let outcome = connect(io, &opts, &host, Some(&early)).await;
            shared.slot().result = Some(outcome);
            shared.read.wake();
            shared.write.wake();
        });
        *lock(&self.guard.0) = Some(Abort(task));
        self.state = WriteState::Connecting;
        self.shared.read.wake();
    }

    /// The handshake starts only on a write, so without one the read half has nothing to wait for.
    fn close_before_handshake(&mut self) {
        let message = "closed before the handshake";
        self.state = WriteState::Failed(io::ErrorKind::BrokenPipe, message.into());
        self.shared.slot().failed = Some((io::ErrorKind::BrokenPipe, message.into()));
        self.shared.read.wake();
    }

    fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let WriteState::Connecting = self.state {
            self.shared.write.register(cx.waker());
            let mut slot = self.shared.slot();
            slot.settle();
            if let Some(write) = slot.write.take() {
                self.state = WriteState::Ready(write);
            } else if let Some((kind, message)) = slot.failed.clone() {
                self.state = WriteState::Failed(kind, message);
            } else {
                return Poll::Pending;
            }
        }
        match &self.state {
            WriteState::Failed(kind, message) => Poll::Ready(Err(failure(*kind, message))),
            _ => Poll::Ready(Ok(())),
        }
    }
}

impl Drop for LazyWrite {
    fn drop(&mut self) {
        if matches!(self.state, WriteState::Idle(_)) {
            self.close_before_handshake();
        }
    }
}

impl AsyncWrite for LazyWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if matches!(this.state, WriteState::Idle(_)) {
            let take = data.len().min(this.max);
            let Some(early) = data.get(..take).filter(|e| !e.is_empty()) else {
                return Poll::Ready(Ok(0));
            };
            this.start(early.to_vec());
            return Poll::Ready(Ok(take));
        }
        ready!(this.poll_connect(cx))?;
        match &mut this.state {
            WriteState::Ready(io) => Pin::new(io).poll_write(cx, data),
            _ => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, WriteState::Idle(_)) {
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_connect(cx))?;
        match &mut this.state {
            WriteState::Ready(io) => Pin::new(io).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, WriteState::Idle(_)) {
            this.close_before_handshake();
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_connect(cx))?;
        match &mut this.state {
            WriteState::Ready(io) => Pin::new(io).poll_shutdown(cx),
            _ => Poll::Ready(Ok(())),
        }
    }
}

impl Stream for LazyWs {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let LazyWs { state, max, shared } = *self;
        let guard = Arc::new(Guard(Mutex::new(None)));
        let (read, write) = match state {
            State::Idle(parts) => (ReadState::Waiting, WriteState::Idle(parts)),
            State::Connecting { _abort } => {
                *lock(&guard.0) = Some(_abort);
                (ReadState::Waiting, WriteState::Connecting)
            }
            State::Ready(io) => {
                let (read, write) = io.into_split();
                (ReadState::Ready(read), WriteState::Ready(write))
            }
            State::Failed(kind, message) => (
                ReadState::Failed(kind, message.clone()),
                WriteState::Failed(kind, message),
            ),
        };
        (
            Box::new(LazyRead {
                state: read,
                shared: shared.clone(),
                _guard: guard.clone(),
            }),
            Box::new(LazyWrite {
                state: write,
                max,
                shared,
                guard,
            }),
        )
    }
}
