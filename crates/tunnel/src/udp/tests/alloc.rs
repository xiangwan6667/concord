#![allow(
    unsafe_code,
    reason = "a counting global allocator wraps the system one"
)]

//! Allocations per datagram on an established NAT session, each way and in each mode an inbound
//! drives it. Counting is per thread, and a current-thread runtime runs every task on the test's.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use super::*;
use crate::runtime::TunnelStatus;

struct Counting;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

fn note(size: usize) {
    if ARMED.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCS.try_with(|count| count.set(count.get() + 1));
        let _ = BYTES.try_with(|bytes| bytes.set(bytes.get() + size));
    }
}

// SAFETY: forwards every call to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn start() {
    ALLOCS.with(|count| count.set(0));
    BYTES.with(|bytes| bytes.set(0));
    ARMED.with(|armed| armed.set(true));
}

fn stop() -> (usize, usize) {
    ARMED.with(|armed| armed.set(false));
    (ALLOCS.with(Cell::get), BYTES.with(Cell::get))
}

const PAYLOAD: [u8; 512] = [7; 512];
const WARM: usize = 512;
const COUNTED: usize = 4096;
/// A TUN driver round's datagrams for one session, under the batch's 64.
const ROUND: usize = 16;

/// A socket that takes every datagram it is sent and has `waiting` datagrams to give.
#[derive(Default)]
struct Socket {
    batches: bool,
    recv_batches: bool,
    sent: AtomicUsize,
    waiting: AtomicUsize,
    reader: Mutex<Option<Waker>>,
}

impl Socket {
    fn arrive(&self, count: usize) {
        self.waiting.fetch_add(count, Ordering::SeqCst);
        let reader = lock(&self.reader).take();
        if let Some(reader) = reader {
            reader.wake();
        }
    }

    fn take(&self, cx: &mut Context<'_>, most: usize) -> Poll<usize> {
        let waiting = self.waiting.load(Ordering::SeqCst);
        if waiting == 0 {
            *lock(&self.reader) = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let taken = waiting.min(most);
        self.waiting.fetch_sub(taken, Ordering::SeqCst);
        Poll::Ready(taken)
    }

    fn sent(&self) -> usize {
        self.sent.load(Ordering::SeqCst)
    }
}

impl PacketSession for Socket {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        _pkt: &mut PacketBuf,
        _dst: &Address,
    ) -> Poll<io::Result<()>> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        std::task::ready!(self.take(cx, 1));
        buf.extend_from_slice(&PAYLOAD);
        Poll::Ready(Ok(target()))
    }

    fn batches(&self) -> bool {
        self.batches
    }

    fn poll_send_batch(
        &self,
        _cx: &mut Context<'_>,
        batch: &[Datagram<'_>],
    ) -> Poll<io::Result<usize>> {
        self.sent.fetch_add(batch.len(), Ordering::SeqCst);
        Poll::Ready(Ok(batch.len()))
    }

    fn recv_batches(&self) -> bool {
        self.recv_batches
    }

    fn poll_recv_batch(&self, cx: &mut Context<'_>, batch: &mut RecvBatch) -> Poll<io::Result<()>> {
        let slots = batch.prepare();
        let taken = std::task::ready!(self.take(cx, slots.len() / RECV_SLOT));
        for slot in slots.chunks_mut(RECV_SLOT).take(taken) {
            slot[..PAYLOAD.len()].copy_from_slice(&PAYLOAD);
        }
        let from = SocketAddr::from(([1, 1, 1, 1], 53));
        batch.received(taken, |_| (PAYLOAD.len(), Some(from)));
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct Tally {
    written: AtomicUsize,
}

impl Tally {
    fn written(&self) -> usize {
        self.written.load(Ordering::SeqCst)
    }
}

impl UdpReply for Tally {
    fn poll_write_back(
        &self,
        _cx: &mut Context<'_>,
        _payload: &[u8],
        _from: &Address,
    ) -> Poll<io::Result<()>> {
        self.written.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

struct Tray {
    room: usize,
    taken: usize,
}

impl ReplyOut for Tray {
    fn room(&self) -> usize {
        self.room - self.taken
    }

    fn put(&mut self, _payload: &[u8], _from: &Address) -> io::Result<()> {
        self.taken += 1;
        Ok(())
    }
}

/// A running tunnel with one session whose flow from `source()` to `target()` is established.
fn established(
    socket: Arc<Socket>,
    reply: Arc<dyn UdpReply>,
) -> (Tunnel, Arc<Inner>, Arc<Session>) {
    let (tunnel, inner) = inner();
    tunnel.set_status(TunnelStatus::Running);
    let session = session_with(&inner, socket, reply, 1);
    let id = FlowId {
        src: source(),
        dst: target(),
    };
    inner.nat.flows.insert(id, ready_flow(&session));
    (tunnel, inner, session)
}

fn upload(
    inner: &Arc<Inner>,
    inbound: &InboundInfo,
    reply: &Arc<dyn UdpReply>,
    count: usize,
    round: Option<usize>,
) {
    let per_round = round.unwrap_or(count);
    for _ in 0..count / per_round {
        let open = round.map(|_| BatchRound::begin(inner));
        for _ in 0..per_round {
            let flow = UdpFlow {
                inbound,
                src: source(),
                dst: target(),
                dscp: 0,
            };
            handle(inner, flow, UdpPayload::Borrowed(&PAYLOAD), reply);
        }
        drop(open);
    }
}

async fn until(done: impl Fn() -> bool) {
    while !done() {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_upload_sent_as_it_arrives_does_not_allocate() {
    let socket = Arc::new(Socket::default());
    let reply: Arc<dyn UdpReply> = Arc::new(Tally::default());
    let (_tunnel, inner, _session) = established(socket.clone(), reply.clone());
    let inbound = InboundInfo::new(InboundKind::Tun);

    upload(&inner, &inbound, &reply, WARM, None);
    start();
    upload(&inner, &inbound, &reply, COUNTED, None);
    let (allocs, bytes) = stop();

    assert_eq!(socket.sent(), WARM + COUNTED);
    assert_eq!(allocs, 0, "{COUNTED} datagrams, {bytes} bytes counted");
}

#[tokio::test(flavor = "current_thread")]
async fn an_upload_held_for_a_driver_round_does_not_allocate() {
    let socket = Arc::new(Socket {
        batches: true,
        ..Socket::default()
    });
    let reply: Arc<dyn UdpReply> = Arc::new(Tally::default());
    let (_tunnel, inner, _session) = established(socket.clone(), reply.clone());
    let inbound = InboundInfo::new(InboundKind::Tun);

    upload(&inner, &inbound, &reply, WARM, Some(ROUND));
    start();
    upload(&inner, &inbound, &reply, COUNTED, Some(ROUND));
    let (allocs, bytes) = stop();

    assert_eq!(socket.sent(), WARM + COUNTED);
    assert_eq!(allocs, 0, "{COUNTED} datagrams, {bytes} bytes counted");
}

async fn download_through_the_receive_task(recv_batches: bool) -> (usize, usize) {
    let socket = Arc::new(Socket {
        recv_batches,
        ..Socket::default()
    });
    let tally = Arc::new(Tally::default());
    let (_tunnel, inner, session) = established(socket.clone(), tally.clone());
    let task = tokio::spawn(receive_loop(inner.clone(), session.clone()));

    socket.arrive(WARM);
    until(|| tally.written() == WARM).await;
    start();
    for _ in 0..COUNTED / ROUND {
        socket.arrive(ROUND);
        tokio::task::yield_now().await;
    }
    until(|| tally.written() == WARM + COUNTED).await;
    let counted = stop();

    session.close();
    task.await.unwrap();
    counted
}

#[tokio::test(flavor = "current_thread")]
async fn a_download_received_one_at_a_time_does_not_allocate() {
    let (allocs, bytes) = timeout(
        Duration::from_secs(30),
        download_through_the_receive_task(false),
    )
    .await
    .unwrap();
    assert_eq!(allocs, 0, "{COUNTED} datagrams, {bytes} bytes counted");
}

#[tokio::test(flavor = "current_thread")]
async fn a_download_received_in_batches_does_not_allocate() {
    let (allocs, bytes) = timeout(
        Duration::from_secs(30),
        download_through_the_receive_task(true),
    )
    .await
    .unwrap();
    assert_eq!(allocs, 0, "{COUNTED} datagrams, {bytes} bytes counted");
}

#[tokio::test(flavor = "current_thread")]
async fn a_download_its_writer_adopted_does_not_allocate() {
    let socket = Arc::new(Socket {
        recv_batches: true,
        ..Socket::default()
    });
    let writer = Arc::new(Adopting::default());
    let (_tunnel, inner, session) = established(socket.clone(), writer.clone());
    assert!(adopt(
        &inner,
        &session,
        &(writer.clone() as Arc<dyn UdpReply>)
    ));
    let source = lock(&writer.source).take().unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut drain = |count: usize| {
        let mut taken = 0;
        for _ in 0..count / ROUND {
            socket.arrive(ROUND);
            let mut tray = Tray {
                room: ROUND,
                taken: 0,
            };
            let _ = source.poll_replies(&mut cx, &mut tray);
            taken += tray.taken;
        }
        taken
    };

    let warm = drain(WARM);
    start();
    let taken = drain(COUNTED);
    let (allocs, bytes) = stop();

    assert_eq!((warm, taken), (WARM, COUNTED));
    assert_eq!(allocs, 0, "{COUNTED} datagrams, {bytes} bytes counted");
    session.close();
}
