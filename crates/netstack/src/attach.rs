//! A connection whose bytes the stack moves to and from an outbound socket itself, so no
//! relay task sits between them.

use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Wake, Waker};

use concord_common::sync::lock;
use concord_common::{Attached, OwnedTcp};
use concord_platform::{TRY_SEND_VECTORED, try_send_vectored};
use futures_util::task::AtomicWaker;
use tokio::net::TcpStream;

use crate::buffer::ChunkPool;
use crate::readiness::{SocketOwner, SocketReady};
use crate::stream::{Shared, SharedState};
use crate::tcp::{Tcb, Wakes};

const SLICES: usize = 8;

fn try_write(socket: &Socket, parts: &[IoSlice<'_>]) -> io::Result<usize> {
    match socket {
        Socket::Owned { stream, ready, .. } => ready.try_write(|| {
            if TRY_SEND_VECTORED {
                try_send_vectored(stream.as_ref(), parts)
            } else {
                (&**stream).write_vectored(parts)
            }
        }),
        Socket::Tokio(socket) => {
            if TRY_SEND_VECTORED {
                try_send_vectored(socket.stream(), parts)
            } else {
                socket.try_write_vectored(parts)
            }
        }
    }
}

pub(crate) enum Socket {
    Tokio(OwnedTcp),
    Owned {
        stream: Arc<std::net::TcpStream>,
        ready: Arc<SocketReady>,
        _registration: Box<dyn Send + Sync>,
        _guard: Option<Arc<dyn Send + Sync>>,
    },
}

impl Socket {
    fn register(socket: OwnedTcp, owner: Option<&dyn SocketOwner>) -> io::Result<Self> {
        if let Some(owner) = owner {
            let (stream, guard) = socket.into_std()?;
            let stream = Arc::new(stream);
            let ready = Arc::new(SocketReady::default());
            let registration = owner.register(Arc::clone(&stream), Arc::clone(&ready))?;
            return Ok(Self::Owned {
                stream,
                ready,
                _registration: registration,
                _guard: guard,
            });
        }
        // Moved to this runtime's reactor, the socket has no readiness yet; only a write that
        // skips readiness can use it at once.
        let socket = if TRY_SEND_VECTORED {
            let duplicate = socket2::SockRef::from(socket.stream()).try_clone()?;
            socket.share_guard(TcpStream::from_std(duplicate.into())?)
        } else {
            socket
        };
        Ok(Self::Tokio(socket))
    }

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Tokio(socket) => socket.poll_read_ready(cx),
            Self::Owned { ready, .. } => ready.poll_read_ready(cx),
        }
    }

    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Tokio(socket) => socket.poll_write_ready(cx),
            Self::Owned { ready, .. } => ready.poll_write_ready(cx),
        }
    }

    fn try_read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        match self {
            Self::Tokio(socket) => socket.try_read_vectored(bufs),
            Self::Owned { stream, ready, .. } => ready.try_read(|| (&**stream).read_vectored(bufs)),
        }
    }

    fn try_write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Self::Tokio(socket) => socket.try_write_vectored(bufs),
            Self::Owned { .. } => try_write(self, bufs),
        }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Self::Tokio(socket) => {
                socket2::SockRef::from(socket.stream()).shutdown(Shutdown::Write)
            }
            Self::Owned { stream, .. } => stream.shutdown(Shutdown::Write),
        }
    }

    fn send_space(&self) -> Option<usize> {
        match self {
            Self::Tokio(socket) => concord_platform::send_space(socket.stream()),
            Self::Owned { stream, .. } => concord_platform::send_space(stream.as_ref()),
        }
    }
}

#[derive(Default)]
pub(crate) struct Link {
    up: AtomicU64,
    down: AtomicU64,
    cancelled: AtomicBool,
    done: Mutex<Option<Result<(), io::ErrorKind>>>,
    waker: AtomicWaker,
}

impl Link {
    fn close(&self, state: &mut SharedState, result: Result<(), io::ErrorKind>) {
        let passed = std::mem::take(&mut state.passed);
        self.up.fetch_add(passed, Ordering::Relaxed);
        self.finish(result);
    }

    pub fn finish(&self, result: Result<(), io::ErrorKind>) {
        lock(&self.done).get_or_insert(result);
        self.waker.wake();
    }

    fn is_done(&self) -> bool {
        lock(&self.done).is_some()
    }
}

struct SocketWake(Weak<Shared>);

impl Wake for SocketWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(shared) = self.0.upgrade() {
            shared.notify();
        }
    }
}

/// The engine's side: the socket and what has happened to it.
pub(crate) struct Attachment {
    socket: Arc<Socket>,
    waker: Waker,
    link: Arc<Link>,
    write_shut: bool,
    read_eof: bool,
    limited: bool,
    write_blocked: bool,
}

pub(crate) struct PendingAttachment {
    socket: OwnedTcp,
    waker: Waker,
    link: Arc<Link>,
}

impl PendingAttachment {
    pub fn new(socket: OwnedTcp, shared: &Arc<Shared>) -> (Self, Arc<Link>) {
        let link = Arc::new(Link::default());
        let attachment = Self {
            socket,
            waker: Waker::from(Arc::new(SocketWake(Arc::downgrade(shared)))),
            link: Arc::clone(&link),
        };
        (attachment, link)
    }

    pub fn close(&self, state: &mut SharedState, result: Result<(), io::ErrorKind>) {
        self.link.close(state, result);
    }

    pub fn activate(self, owner: Option<&dyn SocketOwner>) -> io::Result<Attachment> {
        let socket = match Socket::register(self.socket, owner) {
            Ok(socket) => socket,
            Err(error) => {
                self.link.finish(Err(error.kind()));
                return Err(error);
            }
        };
        Ok(Attachment {
            socket: Arc::new(socket),
            waker: self.waker,
            link: self.link,
            write_shut: false,
            read_eof: false,
            limited: false,
            write_blocked: false,
        })
    }
}

impl Attachment {
    pub fn socket(&self) -> Arc<Socket> {
        Arc::clone(&self.socket)
    }

    pub fn limited(&self) -> bool {
        self.limited
    }

    pub fn cancelled(&self) -> bool {
        self.link.cancelled.load(Ordering::Acquire)
    }

    pub fn finish(&self, result: Result<(), io::ErrorKind>) {
        self.link.finish(result);
    }

    /// Ends the attachment when its connection goes, counting bytes passed straight through.
    pub fn close(&self, state: &mut SharedState, result: Result<(), io::ErrorKind>) {
        self.link.close(state, result);
    }

    /// Moves what both sides allow; true once both directions have closed or the
    /// connection failed, after which the attachment is dropped.
    pub fn pump(
        &mut self,
        tcb: &mut Tcb,
        state: &mut SharedState,
        pool: &ChunkPool,
        wakes: &mut Wakes,
    ) -> bool {
        let passed = std::mem::take(&mut state.passed);
        self.link.up.fetch_add(passed, Ordering::Relaxed);
        let finished = self.pump_inner(tcb, state, pool, wakes);
        if finished {
            state.passthrough = None;
        }
        finished
    }

    fn pump_inner(
        &mut self,
        tcb: &mut Tcb,
        state: &mut SharedState,
        pool: &ChunkPool,
        wakes: &mut Wakes,
    ) -> bool {
        if let Some(kind) = state.error {
            self.link.finish(Err(kind));
            return true;
        }
        if let Err(err) = self
            .upload(tcb, state, pool)
            .and_then(|()| self.download(state, pool))
        {
            tcb.abort(state, wakes, err.kind());
            self.link.finish(Err(err.kind()));
            return true;
        }
        if self.write_shut && self.read_eof {
            self.link.finish(Ok(()));
            return true;
        }
        false
    }

    fn upload(
        &mut self,
        tcb: &mut Tcb,
        state: &mut SharedState,
        pool: &ChunkPool,
    ) -> io::Result<()> {
        let mut cx = Context::from_waker(&self.waker);
        let mut wrote = false;
        while !state.recv.is_empty() {
            if self.write_blocked {
                match self.socket.poll_write_ready(&mut cx) {
                    Poll::Pending => break,
                    Poll::Ready(result) => result?,
                }
            }
            // All that is queued in one write: a write cut short of it leaves a tail the socket
            // sends as its own short TSO packet while the link is the bottleneck.
            let mut slices = [IoSlice::new(&[]); GATHER_SLICES];
            let count = state.recv.front_slices(&mut slices);
            let slices = slices.get(..count).unwrap_or_default();
            let result = try_write(&self.socket, slices).or_else(|error| {
                if error.kind() == io::ErrorKind::WouldBlock
                    && matches!(*self.socket, Socket::Tokio(_))
                {
                    // Clear the cached readiness tick with a real nonblocking operation.
                    self.socket.try_write_vectored(slices)
                } else {
                    Err(error)
                }
            });
            match result {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => {
                    self.write_blocked = false;
                    state.recv.consume(pool, written);
                    self.link.up.fetch_add(written as u64, Ordering::Relaxed);
                    wrote = true;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => self.write_blocked = true,
                Err(err) => return Err(err),
            }
        }
        if wrote && tcb.window_update_due(state) {
            tcb.request_ack();
        }
        if state.recv.is_empty() && state.recv_eof && !self.write_shut {
            self.write_shut = true;
            self.socket.shutdown_write()?;
        }
        Ok(())
    }

    fn download(&mut self, state: &mut SharedState, pool: &ChunkPool) -> io::Result<()> {
        let mut cx = Context::from_waker(&self.waker);
        self.limited = false;
        while !self.read_eof && !state.write_closed {
            let room = state.send_room();
            if room == 0 {
                self.limited = state.send.len() < state.send_cap;
                break;
            }
            match self.socket.poll_read_ready(&mut cx) {
                Poll::Pending => break,
                Poll::Ready(result) => result?,
            }
            let mut slices: [IoSliceMut<'_>; SLICES] =
                std::array::from_fn(|_| IoSliceMut::new(&mut []));
            let count = state.send.spare_slices(pool, room, &mut slices);
            let result = self
                .socket
                .try_read_vectored(slices.get_mut(..count).unwrap_or_default());
            match result {
                Ok(0) => {
                    state.send.trim(pool);
                    self.read_eof = true;
                    state.write_closed = true;
                }
                Ok(read) => {
                    state.send.commit(pool, read);
                    self.link.down.fetch_add(read as u64, Ordering::Relaxed);
                }
                Err(err) => {
                    state.send.trim(pool);
                    if err.kind() != io::ErrorKind::WouldBlock {
                        return Err(err);
                    }
                }
            }
        }
        Ok(())
    }
}

/// The relay's side. Dropping it before the connection finished aborts the connection.
pub(crate) struct Handle {
    pub link: Arc<Link>,
    pub shared: Arc<Shared>,
}

impl Attached for Handle {
    fn moved(&self) -> (u64, u64) {
        (
            self.link.up.load(Ordering::Relaxed),
            self.link.down.load(Ordering::Relaxed),
        )
    }

    fn poll_done(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.link.waker.register(cx.waker());
        match *lock(&self.link.done) {
            Some(Ok(())) => Poll::Ready(Ok(())),
            Some(Err(kind)) => Poll::Ready(Err(io::Error::from(kind))),
            None => Poll::Pending,
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.link.is_done() {
            self.link.cancelled.store(true, Ordering::Release);
            self.shared.notify();
        }
    }
}

const GATHER_SLICES: usize = 64;

/// In-order payload of one connection, borrowed from the host's receive buffers, that goes to
/// its attached socket in one vectored write when the host's batch of reads ends.
pub struct Gather<'a> {
    owner: Option<Arc<Shared>>,
    slices: [IoSlice<'a>; GATHER_SLICES],
    count: usize,
    bytes: usize,
    room: Option<usize>,
}

impl Default for Gather<'_> {
    fn default() -> Self {
        Gather {
            owner: None,
            slices: [IoSlice::new(&[]); GATHER_SLICES],
            count: 0,
            bytes: 0,
            room: None,
        }
    }
}

impl<'a> Gather<'a> {
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub(crate) fn owned_by(&self, shared: &Arc<Shared>) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, shared))
    }

    pub(crate) fn bind(&mut self, shared: &Arc<Shared>) {
        self.owner = Some(Arc::clone(shared));
    }

    pub(crate) fn take_owner(&mut self) -> Option<Arc<Shared>> {
        self.owner.take()
    }

    /// Queues `data` behind what is gathered; false when it is full or `socket` could not
    /// take it, since bytes beyond that are queued anyway and holding their frames buys nothing.
    pub(crate) fn push(&mut self, data: &'a [u8], socket: &Socket) -> bool {
        if self.count == 1 && self.room.is_none() {
            self.room = Some(socket.send_space().unwrap_or(usize::MAX));
        }
        if self.bytes + data.len() > self.room.unwrap_or(usize::MAX) {
            return false;
        }
        match self.slices.get_mut(self.count) {
            Some(slot) => {
                *slot = IoSlice::new(data);
                self.count += 1;
                self.bytes += data.len();
                true
            }
            None => false,
        }
    }

    /// Writes what is gathered to the attached socket and queues what it did not take in
    /// `recv`. True when something was queued.
    pub(crate) fn write(&mut self, state: &mut SharedState, pool: &ChunkPool) -> bool {
        let gathered = self.slices.get(..self.count).unwrap_or_default();
        self.count = 0;
        self.bytes = 0;
        self.room = None;
        if gathered.is_empty() {
            return false;
        }
        let mut written = match &state.passthrough {
            Some(socket) if state.recv.is_empty() => try_write(socket, gathered).unwrap_or(0),
            _ => 0,
        };
        state.passed += written as u64;
        let mut queued = false;
        for slice in gathered {
            let skip = written.min(slice.len());
            written -= skip;
            if let Some(rest) = slice.get(skip..).filter(|rest| !rest.is_empty()) {
                state.recv.push(pool, rest);
                queued = true;
            }
        }
        queued
    }
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used, reason = "test setup and assertions")]
mod reactor_tests {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    struct Ticket(Arc<AtomicUsize>);

    impl Drop for Ticket {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "loopback descriptors for reactor migration"
    )]
    fn attachment_uses_the_accepting_reactor_and_retains_its_ticket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let original = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        original.set_nonblocking(true).unwrap();
        let first = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let second = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let released = Arc::new(AtomicUsize::new(0));
        let socket = {
            let _owner = first.enter();
            OwnedTcp::new(
                TcpStream::from_std(original).unwrap(),
                None,
                Some(Arc::new(Ticket(Arc::clone(&released)))),
            )
        };
        let pending = PendingAttachment {
            socket,
            waker: Waker::noop().clone(),
            link: Arc::default(),
        };
        let attachment = {
            let _owner = second.enter();
            pending.activate(None).unwrap()
        };
        drop(first);
        assert_eq!(released.load(Ordering::Relaxed), 0);
        peer.write_all(b"data").unwrap();
        second.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                let mut bytes = [0; 4];
                let mut received = 0;
                loop {
                    std::future::poll_fn(|cx| attachment.socket.poll_read_ready(cx))
                        .await
                        .unwrap();
                    let mut buffers = [IoSliceMut::new(bytes.get_mut(received..).unwrap())];
                    match attachment.socket.try_read_vectored(&mut buffers) {
                        Ok(read) if read > 0 => {
                            received += read;
                            if received == bytes.len() {
                                assert_eq!(&bytes, b"data");
                                break;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        result => panic!("unexpected read: {result:?}"),
                    }
                }
            })
            .await
            .unwrap();
        });
        drop(attachment);
        assert_eq!(released.load(Ordering::Relaxed), 1);
    }

    struct Registered {
        _socket: Arc<std::net::TcpStream>,
        released: Arc<AtomicUsize>,
    }

    impl Drop for Registered {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct Owner(Arc<AtomicUsize>);

    impl SocketOwner for Owner {
        fn register(
            &self,
            socket: Arc<std::net::TcpStream>,
            ready: Arc<SocketReady>,
        ) -> io::Result<Box<dyn Send + Sync>> {
            ready.set(true, true);
            Ok(Box::new(Registered {
                _socket: socket,
                released: Arc::clone(&self.0),
            }))
        }
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "loopback descriptors for owned registration"
    )]
    fn attachment_transfers_registration_without_losing_the_socket_guard() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let original = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        original.set_nonblocking(true).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let tickets = Arc::new(AtomicUsize::new(0));
        let registrations = Arc::new(AtomicUsize::new(0));
        let socket = {
            let _entered = runtime.enter();
            OwnedTcp::new(
                TcpStream::from_std(original).unwrap(),
                None,
                Some(Arc::new(Ticket(Arc::clone(&tickets)))),
            )
        };
        let pending = PendingAttachment {
            socket,
            waker: Waker::noop().clone(),
            link: Arc::default(),
        };
        let attachment = pending
            .activate(Some(&Owner(Arc::clone(&registrations))))
            .unwrap();
        drop(runtime);
        peer.write_all(b"data").unwrap();
        let mut bytes = [0; 4];
        assert_eq!(
            attachment
                .socket
                .try_read_vectored(&mut [IoSliceMut::new(&mut bytes)])
                .unwrap(),
            4
        );
        assert_eq!(&bytes, b"data");
        attachment.socket.shutdown_write().unwrap();
        assert_eq!(peer.read(&mut bytes).unwrap(), 0);
        assert_eq!(tickets.load(Ordering::Relaxed), 0);
        assert_eq!(registrations.load(Ordering::Relaxed), 0);
        drop(attachment);
        assert_eq!(tickets.load(Ordering::Relaxed), 1);
        assert_eq!(registrations.load(Ordering::Relaxed), 1);
    }
}
