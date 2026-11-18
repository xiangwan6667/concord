use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use concord_common::sync::lock;
use concord_netstack::{SocketOwner, SocketReady};
use concord_platform::SocketObserver;
use mio::unix::SourceFd;
use mio::{Events, Interest, Token};
use tokio::io::unix::AsyncFd;

type Source = Arc<dyn AsRawFd + Send + Sync>;

struct Entry {
    source: Source,
    ready: Weak<SocketReady>,
    local: bool,
    socket: bool,
    /// Watched for reads only, as sing-tun registers a UDP flow's socket
    /// (`stack_go_splice.go:617`, `stack_go_io_linux.go:230`). A socket registered for writes
    /// reports every freed send buffer to whoever waits on the poller.
    read_only: bool,
}

fn interest(read_only: bool) -> Interest {
    if read_only {
        Interest::READABLE
    } else {
        Interest::READABLE | Interest::WRITABLE
    }
}

#[derive(Default)]
struct State {
    local: bool,
    sockets: usize,
    /// Waits on the queue poller that woke the owner since it was last busy.
    waits: usize,
    entries: HashMap<usize, Entry>,
}

struct Inner {
    poll: Mutex<mio::Poll>,
    registry: mio::Registry,
    state: Mutex<State>,
    next: AtomicUsize,
}

struct PollFd(Arc<Inner>);

impl AsRawFd for PollFd {
    fn as_raw_fd(&self) -> RawFd {
        lock(&self.0.poll).as_raw_fd()
    }
}

pub(crate) struct Reactor {
    inner: Arc<Inner>,
    parent: Mutex<Option<AsyncFd<PollFd>>>,
    events: Mutex<Events>,
}

struct Lease {
    owner: Arc<Inner>,
    token: usize,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = lock(&self.owner.state);
        if let Some(entry) = state.entries.remove(&self.token) {
            state.sockets -= usize::from(entry.socket);
            if entry.local {
                let fd = entry.source.as_raw_fd();
                let _ = self.owner.registry.deregister(&mut SourceFd(&fd));
            }
            if let Some(ready) = entry.ready.upgrade() {
                ready.set_native(None);
            }
        }
    }
}

impl Reactor {
    pub fn new() -> io::Result<Self> {
        let poll = mio::Poll::new()?;
        let registry = poll.registry().try_clone()?;
        let inner = Arc::new(Inner {
            poll: Mutex::new(poll),
            registry,
            state: Mutex::new(State::default()),
            next: AtomicUsize::new(0),
        });
        // Validate both registrations before routes are installed; the first native poll disarms this one.
        let parent = Self::register_parent(&inner)?;
        Ok(Self {
            inner,
            parent: Mutex::new(Some(parent)),
            // Tokio uses this capacity for its own I/O driver.
            events: Mutex::new(Events::with_capacity(1024)),
        })
    }

    fn native(source: &Source, read_only: bool) -> io::Result<SocketObserver> {
        let interest = if read_only {
            tokio::io::Interest::READABLE
        } else {
            tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE
        };
        SocketObserver::register(Arc::clone(source), interest)
    }

    #[allow(
        unsafe_code,
        reason = "registering the owned Linux poll descriptor with Tokio"
    )]
    fn register_parent(inner: &Arc<Inner>) -> io::Result<AsyncFd<PollFd>> {
        // SAFETY: PollFd owns the poller through Arc; its descriptor stays open and unchanged while registered.
        unsafe {
            AsyncFd::register_with_interest(
                PollFd(Arc::clone(inner)),
                tokio::io::Interest::READABLE,
            )
        }
        .map_err(|error| error.into_parts().1)
    }

    pub fn register<T: AsRawFd + Send + Sync + 'static>(
        &self,
        source: Arc<T>,
        ready: Arc<SocketReady>,
    ) -> io::Result<Box<dyn Send + Sync>> {
        self.register_source(source, ready, false)
    }

    fn register_source<T: AsRawFd + Send + Sync + 'static>(
        &self,
        source: Arc<T>,
        ready: Arc<SocketReady>,
        socket: bool,
    ) -> io::Result<Box<dyn Send + Sync>> {
        Ok(Box::new(self.lease(source, ready, socket, false)?))
    }

    fn lease<T: AsRawFd + Send + Sync + 'static>(
        &self,
        source: Arc<T>,
        ready: Arc<SocketReady>,
        socket: bool,
        read_only: bool,
    ) -> io::Result<Lease> {
        let source: Source = source;
        let mut state = lock(&self.inner.state);
        let token = self.inner.next.fetch_add(1, Ordering::Relaxed);
        if state.local {
            let fd = source.as_raw_fd();
            self.inner
                .registry
                .register(&mut SourceFd(&fd), Token(token), interest(read_only))?;
        } else {
            ready.set_native(Some(Self::native(&source, read_only)?));
        }
        let local = state.local;
        state.sockets += usize::from(socket);
        state.entries.insert(
            token,
            Entry {
                source,
                ready: Arc::downgrade(&ready),
                local,
                socket,
                read_only,
            },
        );
        Ok(Lease {
            owner: Arc::clone(&self.inner),
            token,
        })
    }

    /// Busy work activates the owner. While sockets are attached, a true I/O wait parks on the
    /// queue poller instead of migrating every descriptor back to Tokio, until waiting there
    /// has cost what the migration would. A wait that wakes the owner costs four system calls
    /// more than a descriptor registered with Tokio: two empty polls of the queue poller and
    /// the poller's registration with Tokio and its removal. Moving one descriptor to Tokio
    /// and back costs four as well, a registration and a removal on each side. So after as
    /// many waits as there are descriptors the queue has paid for the round trip it avoided,
    /// and leaving then costs at most twice what the best choice would have (the rent-or-buy
    /// bound), whatever the traffic does next.
    pub fn set_busy(&self, busy: bool) -> io::Result<bool> {
        let mut state = lock(&self.inner.state);
        if busy {
            state.waits = 0;
        }
        let stays = state.sockets != 0 && state.waits < state.entries.len();
        let local = busy || (state.local && stays);
        if state.local == local {
            drop(state);
            if !local {
                drop(lock(&self.parent).take());
            }
            return Ok(false);
        }
        for (token, entry) in &mut state.entries {
            let Some(ready) = entry.ready.upgrade() else {
                continue;
            };
            let fd = entry.source.as_raw_fd();
            if local {
                self.inner.registry.register(
                    &mut SourceFd(&fd),
                    Token(*token),
                    interest(entry.read_only),
                )?;
                entry.local = true;
                ready.set_native(None);
            } else {
                // Register the new observer before removing the old one, so an edge between
                // the two cannot be lost. The driver re-polls to install its native waiters.
                let native = Self::native(&entry.source, entry.read_only)?;
                self.inner.registry.deregister(&mut SourceFd(&fd))?;
                entry.local = false;
                ready.set_native(Some(native));
            }
        }
        state.local = local;
        drop(state);
        if !local {
            drop(lock(&self.parent).take());
        }
        Ok(true)
    }

    fn drain(&self) -> io::Result<bool> {
        let mut events = lock(&self.events);
        loop {
            match lock(&self.inner.poll).poll(&mut events, Some(Duration::ZERO)) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            break;
        }
        if events.is_empty() {
            return Ok(false);
        }
        for event in events.iter() {
            let ready = lock(&self.inner.state)
                .entries
                .get(&event.token().0)
                .and_then(|entry| entry.ready.upgrade());
            if let Some(ready) = ready {
                ready.set(
                    event.is_readable() || event.is_read_closed() || event.is_error(),
                    event.is_writable() || event.is_write_closed() || event.is_error(),
                );
            }
        }
        Ok(true)
    }

    pub fn poll(&self, cx: &mut Context<'_>, parking: bool) -> Poll<io::Result<()>> {
        if !lock(&self.inner.state).local {
            return Poll::Pending;
        }
        let mut parent = lock(&self.parent);
        if parent.is_none() {
            if self.drain()? {
                return Poll::Ready(Ok(()));
            }
            if !parking {
                return Poll::Pending;
            }
            *parent = Some(Self::register_parent(&self.inner)?);
        }
        // Keep a pending kernel wait across application notifications. A consumed I/O event
        // disarms it while the owner drains; the driver's final park installs the next wait.
        loop {
            let outcome = {
                let Some(poll) = parent.as_ref() else {
                    return Poll::Ready(Err(io::Error::other(
                        "queue wait registration is missing",
                    )));
                };
                let mut guard = match poll.poll_read_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result?,
                };
                guard.try_io(|_| {
                    if self.drain()? {
                        Ok(())
                    } else {
                        Err(io::ErrorKind::WouldBlock.into())
                    }
                })
            };
            match outcome {
                Ok(result) => {
                    drop(parent.take());
                    lock(&self.inner.state).waits += 1;
                    return Poll::Ready(result);
                }
                Err(_) => continue,
            }
        }
    }
}

/// A UDP socket's read readiness on the queue poller, registered while this lives.
struct Watched {
    ready: Arc<SocketReady>,
    _lease: Lease,
}

impl concord_common::SocketWatch for Watched {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ready.poll_read_ready(cx)
    }

    fn try_read(&self, read: &mut dyn FnMut() -> io::Result<usize>) -> io::Result<usize> {
        self.ready.try_read(read)
    }
}

impl concord_common::SocketWatcher for Reactor {
    fn watch(
        &self,
        socket: Arc<std::net::UdpSocket>,
    ) -> io::Result<Arc<dyn concord_common::SocketWatch>> {
        let ready = Arc::new(SocketReady::default());
        let lease = self.lease(socket, Arc::clone(&ready), true, true)?;
        // Assume readable, as a fresh registration does: the first WouldBlock corrects it.
        ready.set(true, false);
        Ok(Arc::new(Watched {
            ready,
            _lease: lease,
        }))
    }
}

impl SocketOwner for Reactor {
    fn register(
        &self,
        socket: Arc<std::net::TcpStream>,
        ready: Arc<SocketReady>,
    ) -> io::Result<Box<dyn Send + Sync>> {
        self.register_source(socket, ready, true)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test setup and assertions")]
mod tests {
    use std::future::poll_fn;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::task::Poll;
    use std::time::Duration;

    use super::*;

    async fn receive<S>(reactor: &Reactor, ready: &SocketReady, near: &S, expected: &[u8])
    where
        for<'a> &'a S: Read,
    {
        let mut socket = near;
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                if let Poll::Ready(Err(error)) = reactor.poll(cx, false) {
                    return Poll::Ready(Err(error));
                }
                loop {
                    match ready.poll_read_ready(cx) {
                        Poll::Ready(result) => result?,
                        Poll::Pending => {
                            if let Poll::Ready(result) = reactor.poll(cx, true) {
                                result?;
                                cx.waker().wake_by_ref();
                            }
                            return Poll::Pending;
                        }
                    }
                    let mut bytes = [0; 16];
                    match ready.try_read(|| socket.read(&mut bytes)) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        result => {
                            let n = result?;
                            assert_eq!(bytes.get(..n).unwrap(), expected);
                            return Poll::Ready(Ok::<(), io::Error>(()));
                        }
                    }
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_queue_drives_io_on_the_existing_runtime() {
        let reactor = Reactor::new().unwrap();
        let (near, mut far) = UnixStream::pair().unwrap();
        near.set_nonblocking(true).unwrap();
        let near = Arc::new(near);
        let ready = Arc::new(SocketReady::default());
        let _lease = reactor
            .register(Arc::clone(&near), Arc::clone(&ready))
            .unwrap();
        far.write_all(b"data").unwrap();
        receive(&reactor, &ready, near.as_ref(), b"data").await;
        assert_eq!(
            tokio::runtime::Handle::current().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(
        clippy::disallowed_methods,
        reason = "loopback descriptors for queue ownership"
    )]
    async fn an_attached_socket_parks_on_its_owner_until_the_registration_finishes() {
        let reactor = Reactor::new().unwrap();
        let (device, mut device_peer) = UnixStream::pair().unwrap();
        device.set_nonblocking(true).unwrap();
        let device = Arc::new(device);
        let device_ready = Arc::new(SocketReady::default());
        let _device_lease = reactor
            .register(Arc::clone(&device), Arc::clone(&device_ready))
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        let socket = Arc::new(socket);
        let ready = Arc::new(SocketReady::default());
        let lease =
            SocketOwner::register(&reactor, Arc::clone(&socket), Arc::clone(&ready)).unwrap();
        assert!(!reactor.set_busy(false).unwrap());
        assert!(!lock(&reactor.inner.state).local);
        assert!(reactor.set_busy(true).unwrap());
        assert!(!reactor.set_busy(false).unwrap());
        assert!(lock(&reactor.inner.state).local);

        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| match reactor.poll(cx, true) {
                Poll::Pending => Poll::Ready(Ok::<(), io::Error>(())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(lock(&reactor.parent).is_some());
        assert!(!reactor.set_busy(true).unwrap());
        assert!(lock(&reactor.parent).is_some());
        peer.write_all(b"after-park").unwrap();
        receive(&reactor, &ready, socket.as_ref(), b"after-park").await;
        drop(peer);
        receive(&reactor, &ready, socket.as_ref(), b"").await;

        drop(lease);
        assert_eq!(lock(&reactor.inner.state).sockets, 0);
        assert!(reactor.set_busy(false).unwrap());
        assert!(!lock(&reactor.inner.state).local);
        assert!(lock(&reactor.parent).is_none());
        device_peer.write_all(b"native").unwrap();
        receive(&reactor, &device_ready, device.as_ref(), b"native").await;
    }

    #[tokio::test]
    async fn closing_a_peer_surfaces_read_eof_and_drops_registration() {
        let reactor = Reactor::new().unwrap();
        let (near, far) = UnixStream::pair().unwrap();
        near.set_nonblocking(true).unwrap();
        let near = Arc::new(near);
        let ready = Arc::new(SocketReady::default());
        assert!(reactor.set_busy(true).unwrap());
        let lease = reactor
            .register(Arc::clone(&near), Arc::clone(&ready))
            .unwrap();
        drop(far);
        receive(&reactor, &ready, near.as_ref(), b"").await;
        drop(lease);
        assert!(lock(&reactor.inner.state).entries.is_empty());
    }

    #[tokio::test]
    async fn cancelling_queue_work_releases_its_registration_and_source() {
        let reactor = Arc::new(Reactor::new().unwrap());
        let (near, _far) = UnixStream::pair().unwrap();
        near.set_nonblocking(true).unwrap();
        let near = Arc::new(near);
        let weak = Arc::downgrade(&near);
        let owner = Arc::clone(&reactor);
        let (started, received) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let ready = Arc::new(SocketReady::default());
            let _lease = owner.register(near, Arc::clone(&ready)).unwrap();
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        received.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(weak.upgrade().is_none());
        assert!(lock(&reactor.inner.state).entries.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn draining_uses_local_io_and_parking_restores_native_wakes() {
        let reactor = Reactor::new().unwrap();
        let (near, mut far) = UnixStream::pair().unwrap();
        near.set_nonblocking(true).unwrap();
        let near = Arc::new(near);
        let ready = Arc::new(SocketReady::default());
        let _lease = reactor
            .register(Arc::clone(&near), Arc::clone(&ready))
            .unwrap();
        assert!(!reactor.set_busy(false).unwrap());
        far.write_all(b"first").unwrap();
        receive(&reactor, &ready, near.as_ref(), b"first").await;
        assert!(reactor.set_busy(true).unwrap());
        assert!(!reactor.set_busy(true).unwrap());
        far.write_all(b"local").unwrap();
        receive(&reactor, &ready, near.as_ref(), b"local").await;
        let mut empty = [0; 1];
        assert_eq!(
            ready
                .try_read(|| (&*near).read(&mut empty))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(reactor.set_busy(false).unwrap());
        assert!(!reactor.set_busy(false).unwrap());
        let (signal, waiting) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            waiting.await.unwrap();
            far.write_all(b"again").unwrap();
            far
        });
        let mut signal = Some(signal);
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| match ready.poll_read_ready(cx) {
                Poll::Pending => {
                    if let Some(signal) = signal.take() {
                        signal.send(()).unwrap();
                    }
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready(result),
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let _far = writer.await.unwrap();
        receive(&reactor, &ready, near.as_ref(), b"again").await;
        assert!(!lock(&reactor.inner.state).local);
        assert!(
            lock(&reactor.inner.state)
                .entries
                .values()
                .all(|entry| !entry.local)
        );
    }

    #[tokio::test]
    async fn queue_preparation_failure_prevents_starting_the_stack() {
        use std::sync::atomic::AtomicBool;
        struct Failing(Arc<AtomicBool>);
        impl Drop for Failing {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        impl crate::Device for Failing {
            fn poll_recv(
                &self,
                _: &mut std::task::Context<'_>,
                _: &mut [u8],
            ) -> std::task::Poll<io::Result<usize>> {
                panic!("failed queue ran");
            }
            fn poll_send(
                &self,
                _: &mut std::task::Context<'_>,
                _: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                panic!("failed queue ran");
            }
            fn prepare(self) -> io::Result<Self> {
                Err(io::ErrorKind::Unsupported.into())
            }
        }
        struct Idle;
        impl crate::FlowSink for Idle {
            fn tcp(&self, _: concord_common::FlowKey, _: concord_common::BoxStream) {}
            fn udp(
                &self,
                _: concord_common::FlowKey,
                _: &[u8],
                _: &Arc<dyn concord_common::UdpReply>,
            ) {
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let result = crate::NetStack::new(crate::StackOptions::default()).prepare(
            Failing(Arc::clone(&dropped)),
            Arc::new(Idle),
            tokio_util::sync::CancellationToken::new(),
        );
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Unsupported);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "loopback descriptors for queue ownership"
    )]
    fn udp_pair() -> (Arc<std::net::UdpSocket>, std::net::UdpSocket) {
        let near = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        near.set_nonblocking(true).unwrap();
        let far = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        far.connect(near.local_addr().unwrap()).unwrap();
        (Arc::new(near), far)
    }

    async fn receive_datagram(
        reactor: &Reactor,
        watch: &dyn concord_common::SocketWatch,
        socket: &std::net::UdpSocket,
        expected: &[u8],
    ) {
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                if let Poll::Ready(Err(error)) = reactor.poll(cx, false) {
                    return Poll::Ready(Err(error));
                }
                loop {
                    match watch.poll_read_ready(cx) {
                        Poll::Ready(result) => result?,
                        Poll::Pending => {
                            if let Poll::Ready(result) = reactor.poll(cx, true) {
                                result?;
                                cx.waker().wake_by_ref();
                            }
                            return Poll::Pending;
                        }
                    }
                    let mut bytes = [0; 16];
                    let received = watch.try_read(&mut || socket.recv(&mut bytes));
                    match received {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        result => {
                            let n = result?;
                            assert_eq!(bytes.get(..n).unwrap(), expected);
                            return Poll::Ready(Ok::<(), io::Error>(()));
                        }
                    }
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_watched_socket_is_registered_for_reads_only_and_hears_data() {
        use concord_common::SocketWatcher;

        let reactor = Reactor::new().unwrap();
        assert!(reactor.set_busy(true).unwrap());
        let (near, far) = udp_pair();

        let watch = reactor.watch(Arc::clone(&near)).unwrap();

        {
            let state = lock(&reactor.inner.state);
            assert_eq!(state.sockets, 1);
            assert!(state.entries.values().all(|entry| entry.read_only));
        }
        far.send(b"data").unwrap();
        receive_datagram(&reactor, &*watch, &near, b"data").await;
        far.send(b"more").unwrap();
        receive_datagram(&reactor, &*watch, &near, b"more").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn data_that_arrives_before_the_queue_turns_busy_is_heard_after() {
        use concord_common::SocketWatcher;

        let reactor = Reactor::new().unwrap();
        let (near, far) = udp_pair();
        let watch = reactor.watch(Arc::clone(&near)).unwrap();
        assert!(!lock(&reactor.inner.state).local);

        far.send(b"early").unwrap();
        assert!(reactor.set_busy(true).unwrap());

        receive_datagram(&reactor, &*watch, &near, b"early").await;
        reactor.set_busy(false).unwrap();
        far.send(b"late").unwrap();
        receive_datagram(&reactor, &*watch, &near, b"late").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reader_parked_on_the_queue_is_woken_when_its_socket_moves_to_tokio() {
        struct Woken(std::sync::atomic::AtomicBool);
        impl std::task::Wake for Woken {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }

        let reactor = Reactor::new().unwrap();
        let (near, mut far) = UnixStream::pair().unwrap();
        near.set_nonblocking(true).unwrap();
        let near = Arc::new(near);
        let ready = Arc::new(SocketReady::default());
        let _lease = reactor
            .register(Arc::clone(&near), Arc::clone(&ready))
            .unwrap();
        assert!(reactor.set_busy(true).unwrap());
        let woken = Arc::new(Woken(std::sync::atomic::AtomicBool::new(false)));
        let waker = std::task::Waker::from(Arc::clone(&woken));
        assert!(
            ready
                .poll_read_ready(&mut Context::from_waker(&waker))
                .is_pending()
        );

        assert!(reactor.set_busy(false).unwrap());
        far.write_all(b"reply").unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !woken.0.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the reader parked on the queue poller was never woken");
        receive(&reactor, &ready, near.as_ref(), b"reply").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_quiet_queue_returns_to_tokio_once_waiting_has_cost_the_move() {
        use concord_common::SocketWatcher;

        let reactor = Reactor::new().unwrap();
        let (near, far) = udp_pair();
        let watch = reactor.watch(Arc::clone(&near)).unwrap();
        let idle: Vec<_> = (0..3)
            .map(|_| reactor.watch(udp_pair().0).unwrap())
            .collect();
        assert!(reactor.set_busy(true).unwrap());
        assert!(!reactor.set_busy(false).unwrap());
        assert!(
            lock(&reactor.inner.state).local,
            "no wait has been paid yet"
        );

        let mut waited = 0;
        let left = loop {
            let parked = poll_fn(|cx| match reactor.poll(cx, true) {
                Poll::Pending => Poll::Ready(Ok::<(), io::Error>(())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            });
            tokio::time::timeout(Duration::from_secs(2), parked)
                .await
                .unwrap()
                .unwrap();
            far.send(b"quiet").unwrap();
            tokio::time::timeout(
                Duration::from_secs(2),
                poll_fn(|cx| reactor.poll(cx, false)),
            )
            .await
            .unwrap()
            .unwrap();
            waited += 1;
            assert_eq!(near.recv(&mut [0; 16]).unwrap(), 5);
            if reactor.set_busy(false).unwrap() {
                break waited;
            }
            assert!(waited < 16, "the queue never left its poller");
        };
        assert_eq!(
            left,
            1 + idle.len(),
            "four descriptors are worth four waits"
        );
        assert!(!lock(&reactor.inner.state).local);

        assert!(reactor.set_busy(true).unwrap());
        assert_eq!(
            lock(&reactor.inner.state).waits,
            0,
            "busy work starts the count again"
        );
        far.send(b"busy").unwrap();
        receive_datagram(&reactor, &*watch, &near, b"busy").await;
    }

    #[tokio::test]
    async fn dropping_a_watch_removes_the_registration_and_releases_the_socket() {
        use concord_common::SocketWatcher;

        let reactor = Reactor::new().unwrap();
        assert!(reactor.set_busy(true).unwrap());
        let (near, _far) = udp_pair();
        let socket = Arc::downgrade(&near);
        let watch = reactor.watch(near).unwrap();
        assert!(socket.upgrade().is_some());

        drop(watch);

        let state = lock(&reactor.inner.state);
        assert!(state.entries.is_empty());
        assert_eq!(state.sockets, 0);
        assert!(socket.upgrade().is_none());
    }

    #[tokio::test]
    async fn a_watch_outlives_its_poller() {
        use concord_common::SocketWatcher;

        let reactor = Reactor::new().unwrap();
        assert!(reactor.set_busy(true).unwrap());
        let (near, _far) = udp_pair();
        let socket = Arc::downgrade(&near);
        let watch = reactor.watch(near).unwrap();

        drop(reactor);
        drop(watch);

        assert!(socket.upgrade().is_none());
    }
}
