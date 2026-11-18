use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::poll_fn;
use std::hash::{BuildHasherDefault, Hasher};
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use arc_swap::ArcSwap;
use concord_common::addr::unmap;
use concord_common::packet::{Datagram, PacketSession, RecvBatch, recv_packet, send_packet};
use concord_common::sync::{lock, read, write};
use concord_common::{
    Address, DialCx, FlowMeta, Initiator, Outbound, PacketBuf, UdpFlow, UdpPayload, UdpReply,
};
use concord_group::Touch;
use dashmap::DashMap;
use tokio::sync::{Notify, OnceCell};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

pub(crate) use self::batch::BatchRound;
use self::batch::{
    batch_target, flush_batch, forget_round_flow, is_staged, stage, take_round_flow,
};
pub(crate) use self::nat::{UdpNat, handle};
use self::recv::{adopt, receive_loop};
use self::session::{end_session, enqueue, idle, is_gone, poll_inline, retire, send, session_for};
use self::sweep::start_scanner;
use crate::flow::{FlowState, pre_handle};
use crate::route::{Decision, route};
use crate::runtime::{Inner, Runtime};
use crate::sniff::{QUIC_WAIT, QuicSniffer, UdpSniff};
use crate::table::{Registration, Tracked};
use crate::tcp::{new_record, server_host};

mod batch;
mod nat;
mod recv;
mod session;
mod sweep;

const ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);
/// mihomo's per-session sender holds 128 datagrams (`senderCapacity` in tunnel.go); a
/// queued one keeps only its bytes.
const PENDING_CAPACITY: usize = 128;
const OVERFLOW_CAPACITY: usize = 128;
const MAX_FLOWS: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FlowId {
    src: SocketAddr,
    dst: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SessionKey {
    src: SocketAddr,
    outbound: usize,
    /// Set only for DIRECT, whose socket has one address family.
    v6: Option<bool>,
    /// Set only for a protocol whose session is bound to one destination.
    dst: Option<Address>,
}

struct Ready {
    session: Arc<Session>,
    target: Address,
}

/// A read buffer is 64 KiB whatever the datagram, so a waiting packet keeps only its bytes.
enum Queued {
    Bytes(Box<[u8]>),
    /// The session returned `Pending` on this one and expects it back as it left it.
    Polled(PacketBuf),
}

impl Queued {
    fn unsent(payload: &[u8]) -> Self {
        Queued::Bytes(payload.into())
    }

    fn into_packet(self) -> PacketBuf {
        match self {
            Queued::Bytes(bytes) => PacketBuf::from_slice(&bytes),
            Queued::Polled(packet) => packet,
        }
    }
}

struct Pending {
    queue: VecDeque<Queued>,
    sniffer: Option<Box<QuicSniffer>>,
}

struct Flow {
    ready: OnceLock<Ready>,
    pending: Mutex<Pending>,
    sniffed: Notify,
    last_active: AtomicU32,
}

impl Flow {
    /// A session outlives its idle flows, and a busy one sees many destinations.
    fn detach(&self, id: &FlowId) {
        if let Some(ready) = self.ready.get() {
            lock(&ready.session.flows).remove(id);
        }
    }
}

struct Session {
    key: SessionKey,
    inner: Arc<dyn PacketSession>,
    registration: Registration,
    reply: ArcSwap<Arc<dyn UdpReply>>,
    first_target: SocketAddr,
    restore: RwLock<HashMap<IpAddr, IpAddr>>,
    has_restore: AtomicBool,
    flows: Mutex<HashSet<FlowId>>,
    last_active: AtomicU32,
    overflow: Mutex<VecDeque<(Queued, Address)>>,
    overflow_len: AtomicUsize,
    sender_running: AtomicBool,
    ended: AtomicBool,
    /// Woken when an adopted session ends, so its writer polls it once more and drops it.
    replies: Mutex<Option<Waker>>,
}

impl Session {
    fn update_reply(&self, reply: &Arc<dyn UdpReply>) {
        if !Arc::ptr_eq(&**self.reply.load(), reply) {
            self.reply.store(Arc::new(reply.clone()));
        }
    }

    fn map_target(&self, target: IpAddr, origin: IpAddr) {
        if target == origin {
            return;
        }
        write(&self.restore).entry(target).or_insert(origin);
        self.has_restore.store(true, Ordering::Release);
    }

    fn restored(&self, from: &Address) -> Address {
        let addr = match from {
            Address::Socket(addr) => *addr,
            Address::Domain(..) => self.first_target,
        };
        let ip = unmap(addr.ip());
        let ip = if self.has_restore.load(Ordering::Acquire) {
            read(&self.restore).get(&ip).copied().unwrap_or(ip)
        } else {
            ip
        };
        Address::Socket(SocketAddr::new(ip, addr.port()))
    }

    fn close(&self) {
        self.registration.tracked().record.close();
    }

    fn wake_replies(&self) {
        let waker = lock(&self.replies).take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::task::Poll;

    use concord_common::{
        ConnRecord, InboundInfo, InboundKind, Network, NullSink, Replies, ReplyOut, ReplySource,
    };
    use concord_net::LoopbackGuard;
    use tokio::time::sleep;

    use concord_common::packet::RECV_SLOT;

    use super::batch::{BATCH, BATCH_DATAGRAMS};
    use super::nat::deliver;
    use super::session::drain_overflow;
    use super::*;
    use crate::runtime::Tunnel;
    use crate::table::ConnTable;

    mod alloc;

    #[derive(Default)]
    struct Wire {
        send_error: Option<io::ErrorKind>,
        incoming: Mutex<VecDeque<Address>>,
        closed: AtomicBool,
        stall_once: AtomicBool,
        sent: Mutex<Vec<(usize, Vec<u8>)>>,
        batches: bool,
        /// How many of each batch call to take; an empty script takes them all, 0 is Pending.
        accepts: Mutex<VecDeque<usize>>,
        batched: Mutex<Vec<Vec<Vec<u8>>>>,
        recv_batches: bool,
        arriving: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        /// Sends take part in Tokio's cooperative budget, as a Tokio socket's do.
        budgeted: bool,
        watched: AtomicUsize,
    }

    impl Wire {
        fn poll_budget(&self, cx: &mut Context<'_>) -> Poll<()> {
            if self.budgeted {
                std::task::ready!(tokio::task::coop::poll_proceed(cx)).made_progress();
            }
            Poll::Ready(())
        }
    }

    impl PacketSession for Wire {
        fn poll_send(
            &self,
            cx: &mut Context<'_>,
            pkt: &mut PacketBuf,
            _dst: &Address,
        ) -> Poll<io::Result<()>> {
            std::task::ready!(self.poll_budget(cx));
            if self.stall_once.swap(false, Ordering::Relaxed) {
                pkt.prepend(1).copy_from_slice(b"h");
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(kind) = self.send_error {
                return Poll::Ready(Err(kind.into()));
            }
            let sent = (pkt.headroom(), pkt.as_slice().to_vec());
            lock(&self.sent).push(sent);
            Poll::Ready(Ok(()))
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            buf: &mut PacketBuf,
        ) -> Poll<io::Result<Address>> {
            match lock(&self.incoming).pop_front() {
                Some(from) => {
                    buf.extend_from_slice(b"x");
                    Poll::Ready(Ok(from))
                }
                None => Poll::Pending,
            }
        }

        fn close(&self) {
            self.closed.store(true, Ordering::Relaxed);
        }

        fn watch(&self, _watcher: &dyn concord_common::SocketWatcher) {
            self.watched.fetch_add(1, Ordering::Relaxed);
        }

        fn batches(&self) -> bool {
            self.batches
        }

        fn poll_send_batch(
            &self,
            cx: &mut Context<'_>,
            batch: &[Datagram<'_>],
        ) -> Poll<io::Result<usize>> {
            std::task::ready!(self.poll_budget(cx));
            if let Some(kind) = self.send_error {
                return Poll::Ready(Err(kind.into()));
            }
            let take = lock(&self.accepts).pop_front();
            let take = take.unwrap_or(batch.len()).min(batch.len());
            if take == 0 {
                return Poll::Pending;
            }
            let payloads = batch[..take].iter().map(|d| d.payload.to_vec()).collect();
            lock(&self.batched).push(payloads);
            Poll::Ready(Ok(take))
        }

        fn recv_batches(&self) -> bool {
            self.recv_batches
        }

        fn poll_recv_batch(
            &self,
            _cx: &mut Context<'_>,
            batch: &mut RecvBatch,
        ) -> Poll<io::Result<()>> {
            let mut arriving = lock(&self.arriving);
            if arriving.is_empty() {
                return Poll::Pending;
            }
            let slots = batch.prepare();
            let taken: Vec<_> = (0..slots.len() / RECV_SLOT)
                .map_while(|_| arriving.pop_front())
                .collect();
            for (index, (payload, _)) in taken.iter().enumerate() {
                slots[index * RECV_SLOT..][..payload.len()].copy_from_slice(payload);
            }
            batch.received(taken.len(), |index| {
                (taken[index].0.len(), Some(taken[index].1))
            });
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct Client {
        failures: Mutex<VecDeque<io::ErrorKind>>,
        written: AtomicUsize,
        session_ended: AtomicBool,
        ends: AtomicUsize,
        /// The write-back call, counting from 0, that is not ready the first time.
        stall_at: Mutex<Option<usize>>,
        payloads: Mutex<Vec<Vec<u8>>>,
    }

    impl UdpReply for Client {
        fn poll_write_back(
            &self,
            cx: &mut Context<'_>,
            payload: &[u8],
            _from: &Address,
        ) -> Poll<io::Result<()>> {
            let call = self.written.fetch_add(1, Ordering::Relaxed);
            let mut stall_at = lock(&self.stall_at);
            if *stall_at == Some(call) {
                *stall_at = None;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            match lock(&self.failures).pop_front() {
                Some(kind) => Poll::Ready(Err(kind.into())),
                None => {
                    lock(&self.payloads).push(payload.to_vec());
                    Poll::Ready(Ok(()))
                }
            }
        }

        fn session_ended(&self) {
            self.session_ended.store(true, Ordering::Relaxed);
            self.ends.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Takes the session's receiving, as the TUN's reply handle does.
    #[derive(Default)]
    struct Adopting {
        source: Mutex<Option<Arc<dyn ReplySource>>>,
    }

    impl UdpReply for Adopting {
        fn poll_write_back(
            &self,
            _cx: &mut Context<'_>,
            _payload: &[u8],
            _from: &Address,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn adopt(&self, source: Arc<dyn ReplySource>) -> Result<(), Arc<dyn ReplySource>> {
            *lock(&self.source) = Some(source);
            Ok(())
        }
    }

    struct Collect {
        room: usize,
        got: Vec<(Vec<u8>, Address)>,
    }

    impl Collect {
        fn new(room: usize) -> Self {
            Collect {
                room,
                got: Vec::new(),
            }
        }
    }

    impl ReplyOut for Collect {
        fn room(&self) -> usize {
            self.room - self.got.len()
        }

        fn put(&mut self, payload: &[u8], from: &Address) -> io::Result<()> {
            self.got.push((payload.to_vec(), from.clone()));
            Ok(())
        }
    }

    fn source() -> SocketAddr {
        "10.0.0.1:1000".parse().unwrap()
    }

    fn target() -> Address {
        Address::Socket("1.1.1.1:53".parse().unwrap())
    }

    fn inner() -> (Tunnel, Arc<Inner>) {
        let table = ConnTable::new(Arc::new(NullSink));
        let tunnel = Tunnel::new(table, LoopbackGuard::new(false));
        let inner = tunnel.inner().clone();
        (tunnel, inner)
    }

    fn session(
        inner: &Inner,
        wire: Arc<Wire>,
        client: Arc<Client>,
        outbound: usize,
    ) -> Arc<Session> {
        session_with(inner, wire, client, outbound)
    }

    fn session_with(
        inner: &Inner,
        wire: Arc<dyn PacketSession>,
        client: Arc<dyn UdpReply>,
        outbound: usize,
    ) -> Arc<Session> {
        let state = FlowState::new(FlowMeta {
            dscp: 0,
            network: Network::Udp,
            inbound: InboundInfo::new(InboundKind::Socks5),
            src: source(),
            dst: target(),
        });
        let record = Arc::new(ConnRecord::new(
            state.conn_meta(String::new()),
            Box::new([]),
            Box::new([]),
            Arc::from(""),
            Arc::from(""),
            false,
            0,
        ));
        let key = SessionKey {
            src: source(),
            outbound,
            v6: None,
            dst: None,
        };
        let session = Arc::new(Session {
            key: key.clone(),
            inner: wire,
            registration: inner.table.register(record, 0),
            reply: ArcSwap::from_pointee(client),
            first_target: "1.1.1.1:53".parse().unwrap(),
            restore: RwLock::new(HashMap::new()),
            has_restore: AtomicBool::new(false),
            flows: Mutex::new(HashSet::new()),
            last_active: AtomicU32::new(0),
            overflow: Mutex::new(VecDeque::new()),
            overflow_len: AtomicUsize::new(0),
            sender_running: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            replies: Mutex::new(None),
        });
        inner
            .nat
            .slots
            .insert(key, Arc::new(OnceCell::new_with(Some(session.clone()))));
        let id = FlowId {
            src: source(),
            dst: target(),
        };
        lock(&session.flows).insert(id.clone());
        inner.nat.flows.insert(
            id,
            Arc::new(Flow {
                ready: OnceLock::new(),
                pending: Mutex::new(Pending {
                    queue: VecDeque::new(),
                    sniffer: None,
                }),
                sniffed: Notify::new(),
                last_active: AtomicU32::new(0),
            }),
        );
        session
    }

    fn ready_flow(session: &Arc<Session>) -> Arc<Flow> {
        let ready = OnceLock::new();
        let _ = ready.set(Ready {
            session: session.clone(),
            target: target(),
        });
        Arc::new(Flow {
            ready,
            pending: Mutex::new(Pending {
                queue: VecDeque::new(),
                sniffer: None,
            }),
            sniffed: Notify::new(),
            last_active: AtomicU32::new(0),
        })
    }

    fn assert_retired(inner: &Inner, session: &Session, wire: &Wire) {
        assert!(inner.nat.slots.is_empty());
        assert!(inner.nat.flows.is_empty());
        assert!(session.registration.tracked().record.is_closed());
        assert!(wire.closed.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn a_send_into_a_dead_session_removes_it_from_the_table() {
        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            send_error: Some(io::ErrorKind::BrokenPipe),
            ..Wire::default()
        });
        let session = session(&inner, wire.clone(), Arc::default(), 1);

        send(&inner, &session, UdpPayload::Borrowed(b"x"), &target());

        assert_retired(&inner, &session, &wire);
    }

    #[tokio::test]
    async fn packets_behind_a_stalled_send_wait_as_bytes_and_leave_in_order() {
        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            stall_once: AtomicBool::new(true),
            ..Wire::default()
        });
        let session = session(&inner, wire.clone(), Arc::default(), 1);

        for payload in [b"a", b"b", b"c"] {
            send(&inner, &session, UdpPayload::Borrowed(payload), &target());
        }
        {
            let overflow = lock(&session.overflow);
            assert!(matches!(overflow[0].0, Queued::Polled(_)));
            assert!(
                overflow
                    .iter()
                    .skip(1)
                    .all(|(queued, _)| matches!(queued, Queued::Bytes(bytes) if bytes.len() == 1))
            );
        }
        timeout(Duration::from_secs(5), async {
            while lock(&wire.sent).len() < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let headroom = PacketBuf::DEFAULT_HEADROOM;
        assert_eq!(
            *lock(&wire.sent),
            [
                (headroom - 1, b"ha".to_vec()),
                (headroom, b"b".to_vec()),
                (headroom, b"c".to_vec()),
            ]
        );
    }

    #[tokio::test]
    async fn a_queued_send_into_a_dead_session_removes_it_from_the_table() {
        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            send_error: Some(io::ErrorKind::BrokenPipe),
            ..Wire::default()
        });
        let session = session(&inner, wire.clone(), Arc::default(), 1);
        lock(&session.overflow).push_back((Queued::Bytes(b"x".as_slice().into()), target()));

        drain_overflow(inner.clone(), session.clone()).await;

        assert_retired(&inner, &session, &wire);
    }

    #[tokio::test]
    async fn a_failed_send_that_is_not_fatal_keeps_the_session() {
        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            send_error: Some(io::ErrorKind::PermissionDenied),
            ..Wire::default()
        });
        let session = session(&inner, wire, Arc::default(), 1);

        send(&inner, &session, UdpPayload::Borrowed(b"x"), &target());

        assert_eq!(inner.nat.slots.len(), 1);
        assert_eq!(inner.nat.flows.len(), 1);
    }

    #[tokio::test]
    async fn dropping_a_session_leaves_the_slot_of_its_replacement() {
        let (_tunnel, inner) = inner();
        let old = session(&inner, Arc::default(), Arc::default(), 1);
        let new = session(&inner, Arc::default(), Arc::default(), 1);

        inner.nat.drop_session(&old);

        let slot = inner.nat.slots.get(&new.key).unwrap();
        assert!(Arc::ptr_eq(slot.get().unwrap(), &new));
    }

    async fn run_replies(failure: io::ErrorKind) -> (Arc<Client>, bool, Arc<Inner>) {
        let (tunnel, inner) = inner();
        let wire = Arc::new(Wire::default());
        lock(&wire.incoming).extend([target(), target()]);
        let client = Arc::new(Client::default());
        lock(&client.failures).push_back(failure);
        let session = session(&inner, wire, client.clone(), 1);
        let task = tokio::spawn(receive_loop(inner.clone(), session.clone()));
        let _ = timeout(Duration::from_millis(200), async {
            while client.written.load(Ordering::Relaxed) < 2 {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
        let ended = task.is_finished() || {
            sleep(Duration::from_millis(20)).await;
            task.is_finished()
        };
        session.close();
        drop(tunnel);
        (client, ended, inner)
    }

    #[tokio::test]
    async fn a_reply_keeps_the_flow_it_answers_alive() {
        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire::default());
        lock(&wire.incoming).push_back(target());
        let client = Arc::new(Client::default());
        let session = session(&inner, wire, client.clone(), 1);
        inner.nat.clock.store(42, Ordering::Relaxed);
        let id = FlowId {
            src: source(),
            dst: target(),
        };
        let flow = inner.nat.flows.get(&id).unwrap().clone();
        assert_eq!(flow.last_active.load(Ordering::Relaxed), 0);

        let task = tokio::spawn(receive_loop(inner.clone(), session.clone()));
        timeout(Duration::from_secs(5), async {
            while client.written.load(Ordering::Relaxed) < 1 {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        session.close();
        let _ = task.await;

        assert_eq!(flow.last_active.load(Ordering::Relaxed), 42);
    }

    #[tokio::test]
    async fn a_transient_write_back_error_drops_one_packet_and_keeps_the_session() {
        let (client, ended, _inner) = run_replies(io::ErrorKind::ConnectionRefused).await;

        assert_eq!(client.written.load(Ordering::Relaxed), 2);
        assert!(!ended);
    }

    #[tokio::test]
    async fn a_closed_reply_ends_the_session() {
        let (client, ended, inner) = run_replies(io::ErrorKind::BrokenPipe).await;

        assert_eq!(client.written.load(Ordering::Relaxed), 1);
        assert!(ended);
        assert!(inner.nat.slots.is_empty());
        assert!(client.session_ended.load(Ordering::Relaxed));
    }

    /// Runs a receive loop over a batching session until the client has `want` payloads.
    async fn receive_batched(
        payloads: &[&[u8]],
        client: Arc<Client>,
        want: usize,
    ) -> (Arc<Session>, bool) {
        let (tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            recv_batches: true,
            ..Wire::default()
        });
        let from = SocketAddr::from(([1, 1, 1, 1], 53));
        lock(&wire.arriving).extend(payloads.iter().map(|payload| (payload.to_vec(), from)));
        let session = session(&inner, wire, client.clone(), 1);
        let task = tokio::spawn(receive_loop(inner.clone(), session.clone()));
        let _ = timeout(Duration::from_secs(5), async {
            while lock(&client.payloads).len() < want && !task.is_finished() {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
        sleep(Duration::from_millis(20)).await;
        let ended = task.is_finished();
        session.close();
        drop(tunnel);
        (session, ended)
    }

    fn numbered(count: u8) -> Vec<Vec<u8>> {
        (0..count).map(|i| vec![i; usize::from(i) + 1]).collect()
    }

    #[tokio::test]
    async fn a_received_batch_is_written_back_in_order_and_counted() {
        let payloads = numbered(20);
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let client = Arc::new(Client::default());

        let (session, ended) = receive_batched(&refs, client.clone(), 20).await;

        assert_eq!(*lock(&client.payloads), payloads);
        let bytes: usize = payloads.iter().map(Vec::len).sum();
        let record = &session.registration.tracked().record;
        assert_eq!(record.download.load(Ordering::Relaxed), bytes as u64);
        assert!(!ended);
    }

    #[tokio::test]
    async fn datagrams_behind_a_reply_that_is_not_ready_follow_in_order() {
        let payloads = numbered(6);
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let client = Arc::new(Client {
            stall_at: Mutex::new(Some(2)),
            ..Client::default()
        });

        let (_session, ended) = receive_batched(&refs, client.clone(), 6).await;

        assert_eq!(*lock(&client.payloads), payloads);
        assert!(!ended);
    }

    #[tokio::test]
    async fn a_closed_reply_in_a_batch_ends_the_session() {
        let client = Arc::new(Client::default());
        lock(&client.failures).push_back(io::ErrorKind::BrokenPipe);

        let (_session, ended) = receive_batched(&[b"a", b"b", b"c"], client.clone(), 1).await;

        assert_eq!(client.written.load(Ordering::Relaxed), 1);
        assert!(lock(&client.payloads).is_empty());
        assert!(ended);
        assert!(client.session_ended.load(Ordering::Relaxed));
    }

    fn batching() -> Arc<Wire> {
        Arc::new(Wire {
            batches: true,
            ..Wire::default()
        })
    }

    fn held() -> (usize, usize, usize) {
        BATCH.with(|batch| {
            let batch = batch.borrow();
            (batch.bytes.len(), batch.staged.len(), batch.sessions.len())
        })
    }

    fn payloads(wire: &Wire) -> Vec<Vec<Vec<u8>>> {
        lock(&wire.batched).clone()
    }

    fn per_packet(wire: &Wire) -> Vec<Vec<u8>> {
        lock(&wire.sent).iter().map(|(_, p)| p.clone()).collect()
    }

    async fn sent_count(wire: &Wire, want: usize) {
        timeout(Duration::from_secs(5), async {
            while lock(&wire.sent).len() < want {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_rounds_datagrams_leave_together_when_the_round_ends() {
        let (_tunnel, inner) = inner();
        let wire = batching();
        let session = session(&inner, wire.clone(), Arc::default(), 1);

        let round = BatchRound::begin(&inner);
        for payload in [b"a", b"b", b"c"] {
            send(&inner, &session, UdpPayload::Borrowed(payload), &target());
        }
        assert!(payloads(&wire).is_empty());
        drop(round);

        assert_eq!(
            payloads(&wire),
            [vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]]
        );
        assert!(per_packet(&wire).is_empty());
        assert_eq!(held(), (0, 0, 0));
        assert_eq!(
            session
                .registration
                .tracked()
                .record
                .upload
                .load(Ordering::Relaxed),
            3
        );
    }

    #[tokio::test]
    async fn outside_a_round_each_datagram_leaves_at_once() {
        let (_tunnel, inner) = inner();
        let wire = batching();
        let session = session(&inner, wire.clone(), Arc::default(), 1);

        send(&inner, &session, UdpPayload::Borrowed(b"a"), &target());

        assert_eq!(per_packet(&wire), [b"a".to_vec()]);
        assert!(payloads(&wire).is_empty());
    }

    #[tokio::test]
    async fn a_spent_task_budget_does_not_push_sends_to_the_overflow_task() {
        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            batches: true,
            budgeted: true,
            ..Wire::default()
        });
        let session = session(&inner, wire.clone(), Arc::default(), 1);

        tokio::spawn(async move {
            poll_fn(|cx| {
                while let Poll::Ready(budget) = tokio::task::coop::poll_proceed(cx) {
                    budget.made_progress();
                }
                Poll::Ready(())
            })
            .await;
            assert!(!tokio::task::coop::has_budget_remaining());

            send(&inner, &session, UdpPayload::Borrowed(b"a"), &target());
            let round = BatchRound::begin(&inner);
            for payload in [b"b", b"c"] {
                send(&inner, &session, UdpPayload::Borrowed(payload), &target());
            }
            drop(round);

            assert_eq!(per_packet(&wire), [b"a".to_vec()]);
            assert_eq!(payloads(&wire), [vec![b"b".to_vec(), b"c".to_vec()]]);
            assert!(idle(&session));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_session_that_does_not_batch_sends_inside_a_round_at_once() {
        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire::default());
        let session = session(&inner, wire.clone(), Arc::default(), 1);

        let round = BatchRound::begin(&inner);
        send(&inner, &session, UdpPayload::Borrowed(b"a"), &target());
        assert_eq!(per_packet(&wire), [b"a".to_vec()]);
        drop(round);
    }

    #[tokio::test]
    async fn a_domain_destination_sends_what_was_held_first() {
        let (_tunnel, inner) = inner();
        let wire = batching();
        let session = session(&inner, wire.clone(), Arc::default(), 1);
        let domain = Address::Domain(concord_common::Host::const_new("example.com"), 53);

        let round = BatchRound::begin(&inner);
        send(&inner, &session, UdpPayload::Borrowed(b"a"), &target());
        send(&inner, &session, UdpPayload::Borrowed(b"b"), &domain);
        send(&inner, &session, UdpPayload::Borrowed(b"c"), &target());
        drop(round);

        assert_eq!(per_packet(&wire), [b"b".to_vec()]);
        assert_eq!(payloads(&wire), [vec![b"a".to_vec()], vec![b"c".to_vec()]]);
    }

    #[tokio::test]
    async fn what_a_full_socket_leaves_waits_as_bytes_and_keeps_its_order() {
        let (_tunnel, inner) = inner();
        let wire = batching();
        lock(&wire.accepts).extend([2, 0]);
        let session = session(&inner, wire.clone(), Arc::default(), 1);

        let round = BatchRound::begin(&inner);
        for payload in [b"a", b"b", b"c", b"d"] {
            send(&inner, &session, UdpPayload::Borrowed(payload), &target());
        }
        drop(round);
        assert_eq!(held(), (0, 0, 0));
        {
            let overflow = lock(&session.overflow);
            assert_eq!(overflow.len(), 2);
            assert!(
                overflow
                    .iter()
                    .all(|(queued, _)| matches!(queued, Queued::Bytes(_)))
            );
        }
        let round = BatchRound::begin(&inner);
        send(&inner, &session, UdpPayload::Borrowed(b"e"), &target());
        drop(round);
        sent_count(&wire, 3).await;

        assert_eq!(payloads(&wire), [vec![b"a".to_vec(), b"b".to_vec()]]);
        assert_eq!(
            per_packet(&wire),
            [b"c".to_vec(), b"d".to_vec(), b"e".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_session_past_the_batch_limit_sends_early_in_order() {
        let (_tunnel, inner) = inner();
        let wire = batching();
        let session = session(&inner, wire.clone(), Arc::default(), 1);
        let all: Vec<Vec<u8>> = (0..BATCH_DATAGRAMS + 3)
            .map(|i| u16::try_from(i).unwrap().to_be_bytes().to_vec())
            .collect();

        let round = BatchRound::begin(&inner);
        for payload in &all {
            send(&inner, &session, UdpPayload::Borrowed(payload), &target());
        }
        assert_eq!(payloads(&wire).len(), 1);
        drop(round);

        let calls = payloads(&wire);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].len(), BATCH_DATAGRAMS);
        assert_eq!(calls.concat(), all);
    }

    #[tokio::test]
    async fn a_batch_into_a_dead_session_removes_it_from_the_table() {
        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            batches: true,
            send_error: Some(io::ErrorKind::BrokenPipe),
            ..Wire::default()
        });
        let session = session(&inner, wire.clone(), Arc::default(), 1);

        let round = BatchRound::begin(&inner);
        send(&inner, &session, UdpPayload::Borrowed(b"x"), &target());
        drop(round);

        assert_retired(&inner, &session, &wire);
    }

    #[tokio::test]
    async fn interleaved_sessions_each_send_their_own_datagrams_in_order() {
        let (_tunnel, inner) = inner();
        let (first, second) = (batching(), batching());
        let one = session(&inner, first.clone(), Arc::default(), 1);
        let two = session(&inner, second.clone(), Arc::default(), 2);

        let round = BatchRound::begin(&inner);
        for (session, payload) in [(&one, b"a"), (&two, b"x"), (&one, b"b"), (&two, b"y")] {
            send(&inner, session, UdpPayload::Borrowed(payload), &target());
        }
        assert!(is_staged(&one) && is_staged(&two));
        drop(round);

        assert_eq!(payloads(&first), [vec![b"a".to_vec(), b"b".to_vec()]]);
        assert_eq!(payloads(&second), [vec![b"x".to_vec(), b"y".to_vec()]]);
        assert!(!is_staged(&one) && !is_staged(&two));
        assert_eq!(held(), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_datagram_of_a_ready_flow_borrows_the_reply_it_already_holds() {
        let (_tunnel, inner) = inner();
        let client: Arc<dyn UdpReply> = Arc::new(Client::default());
        let wire = batching();
        let session = session(&inner, wire.clone(), Arc::default(), 1);
        session.update_reply(&client);
        let owners = Arc::strong_count(&client);
        let flow = ready_flow(&session);

        let round = BatchRound::begin(&inner);
        for payload in [b"a", b"b"] {
            deliver(&inner, &flow, UdpPayload::Borrowed(payload), &client);
        }
        assert_eq!(Arc::strong_count(&client), owners);
        drop(round);

        assert_eq!(payloads(&wire), [vec![b"a".to_vec(), b"b".to_vec()]]);
    }

    #[tokio::test]
    async fn the_round_keeps_its_last_flow_until_it_ends_or_forgets_it() {
        let (_tunnel, inner) = inner();
        let session = session(&inner, batching(), Arc::default(), 1);
        let id = FlowId {
            src: source(),
            dst: target(),
        };
        let other = Address::Socket("9.9.9.9:53".parse().unwrap());

        let (none, lease) = take_round_flow(source(), &target());
        assert!(none.is_none());
        lease.keep(id.clone(), ready_flow(&session));
        assert!(
            take_round_flow(source(), &target()).0.is_none(),
            "outside a round"
        );

        let round = BatchRound::begin(&inner);
        let (_, lease) = take_round_flow(source(), &target());
        lease.keep(id.clone(), ready_flow(&session));
        assert!(take_round_flow(source(), &other).0.is_none());
        let (kept, lease) = take_round_flow(source(), &target());
        let (kept_id, flow) = kept.expect("the round's flow");
        assert_eq!(kept_id, id);
        lease.keep(kept_id, flow);

        let (taken, stale) = take_round_flow(source(), &target());
        let (taken_id, flow) = taken.unwrap();
        forget_round_flow();
        stale.keep(taken_id, flow);
        assert!(
            take_round_flow(source(), &target()).0.is_none(),
            "a flow forgotten while it was out does not come back"
        );

        let (_, lease) = take_round_flow(source(), &target());
        lease.keep(id, ready_flow(&session));
        drop(round);
        let _round = BatchRound::begin(&inner);
        assert!(
            take_round_flow(source(), &target()).0.is_none(),
            "a new round starts empty"
        );
    }

    #[tokio::test]
    async fn a_retired_session_is_not_reached_through_the_round() {
        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            batches: true,
            send_error: Some(io::ErrorKind::BrokenPipe),
            ..Wire::default()
        });
        let session = session(&inner, wire, Arc::default(), 1);
        let id = FlowId {
            src: source(),
            dst: target(),
        };

        let _round = BatchRound::begin(&inner);
        let (_, lease) = take_round_flow(source(), &target());
        lease.keep(id, ready_flow(&session));
        retire(&inner, &session);

        assert!(take_round_flow(source(), &target()).0.is_none());
    }

    fn adopted(payloads: &[Vec<u8>]) -> (Tunnel, Arc<Inner>, Arc<Session>, Arc<dyn ReplySource>) {
        let (tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            recv_batches: true,
            ..Wire::default()
        });
        let from = SocketAddr::from(([1, 1, 1, 1], 53));
        lock(&wire.arriving).extend(payloads.iter().map(|payload| (payload.clone(), from)));
        let session = session(&inner, wire, Arc::default(), 1);
        let reply = Arc::new(Adopting::default());
        assert!(adopt(
            &inner,
            &session,
            &(reply.clone() as Arc<dyn UdpReply>)
        ));
        let source = lock(&reply.source).take().unwrap();
        (tunnel, inner, session, source)
    }

    #[tokio::test]
    async fn a_holder_poisoned_lock_still_records_restore_entries_and_the_reply_waker() {
        #[derive(Default)]
        struct Wakes(AtomicUsize);

        impl std::task::Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (_tunnel, _inner, session, source) = adopted(&[]);
        let real: IpAddr = "10.0.0.9".parse().unwrap();
        let fake: IpAddr = "198.18.0.9".parse().unwrap();
        concord_test_support::poison_rwlock(&session.restore);
        session.map_target(real, fake);
        assert_eq!(
            session.restored(&Address::Socket(SocketAddr::new(real, 53))),
            Address::Socket(SocketAddr::new(fake, 53))
        );

        concord_test_support::poison(&session.replies);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let _ = source.poll_replies(&mut Context::from_waker(&waker), &mut Collect::new(32));
        assert!(
            lock(&session.replies)
                .as_ref()
                .is_some_and(|recorded| recorded.will_wake(&waker))
        );
        let before = wakes.0.load(Ordering::SeqCst);
        session.wake_replies();
        assert_eq!(wakes.0.load(Ordering::SeqCst), before + 1);
    }

    #[tokio::test]
    async fn an_adopted_source_passes_its_writer_s_watcher_to_the_session() {
        struct Unused;

        impl concord_common::SocketWatcher for Unused {
            fn watch(
                &self,
                _socket: Arc<std::net::UdpSocket>,
            ) -> io::Result<Arc<dyn concord_common::SocketWatch>> {
                Err(io::Error::other("unused"))
            }
        }

        let (_tunnel, inner) = inner();
        let wire = Arc::new(Wire {
            recv_batches: true,
            ..Wire::default()
        });
        let session = session(&inner, Arc::clone(&wire), Arc::default(), 1);
        let reply = Arc::new(Adopting::default());
        assert!(adopt(
            &inner,
            &session,
            &(reply.clone() as Arc<dyn UdpReply>)
        ));
        let source = lock(&reply.source).take().unwrap();

        source.watch(&Unused);

        assert_eq!(wire.watched.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn an_adopted_session_hands_its_writer_what_arrives_in_order_and_counts_it() {
        let payloads = numbered(5);
        let (_tunnel, _inner, session, source) = adopted(&payloads);
        let mut cx = Context::from_waker(Waker::noop());

        let mut out = Collect::new(2);
        assert_eq!(
            source.poll_replies(&mut cx, &mut out),
            Poll::Ready(Replies::Received)
        );
        assert_eq!(out.got.len(), 2, "no more than the writer has room for");
        let mut rest = Collect::new(32);
        assert_eq!(
            source.poll_replies(&mut cx, &mut rest),
            Poll::Ready(Replies::Drained),
            "read to the empty socket in the one poll"
        );
        assert!(
            source
                .poll_replies(&mut cx, &mut Collect::new(32))
                .is_pending()
        );

        let got: Vec<_> = out.got.into_iter().chain(rest.got).collect();
        assert_eq!(
            got.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(),
            payloads
        );
        assert!(got.iter().all(|(_, from)| *from == target()));
        let bytes: usize = payloads.iter().map(Vec::len).sum();
        let record = &session.registration.tracked().record;
        assert_eq!(record.download.load(Ordering::Relaxed), bytes as u64);
    }

    #[tokio::test]
    async fn a_session_whose_writer_refuses_it_or_that_does_not_batch_keeps_its_own_task() {
        let (_tunnel, inner) = inner();
        let batching = Arc::new(Wire {
            recv_batches: true,
            ..Wire::default()
        });
        let batched = session(&inner, batching, Arc::default(), 1);
        let refusing: Arc<dyn UdpReply> = Arc::new(Client::default());
        assert!(!adopt(&inner, &batched, &refusing));
        assert!(!batched.registration.tracked().record.is_closed());

        let single = session(&inner, Arc::new(Wire::default()), Arc::default(), 2);
        let adopting = Arc::new(Adopting::default());
        assert!(!adopt(
            &inner,
            &single,
            &(adopting.clone() as Arc<dyn UdpReply>)
        ));
        assert!(lock(&adopting.source).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retiring_an_adopted_session_while_its_source_ends_ends_it_once() {
        for _ in 0..50 {
            let (tunnel, inner) = inner();
            let wire = Arc::new(Wire {
                recv_batches: true,
                ..Wire::default()
            });
            let client = Arc::new(Client::default());
            let session = session(&inner, wire, client.clone(), 1);
            let reply = Arc::new(Adopting::default());
            assert!(adopt(
                &inner,
                &session,
                &(reply.clone() as Arc<dyn UdpReply>)
            ));
            let source = lock(&reply.source).take().unwrap();

            let retired = {
                let (inner, session) = (inner.clone(), session.clone());
                tokio::spawn(async move { retire(&inner, &session) })
            };
            let polled = tokio::spawn(async move {
                poll_fn(|cx| match source.poll_replies(cx, &mut Collect::new(32)) {
                    Poll::Ready(Replies::Ended) => Poll::Ready(()),
                    _ => Poll::Pending,
                })
                .await;
            });
            retired.await.unwrap();
            timeout(Duration::from_secs(5), polled)
                .await
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(5), async {
                while Arc::strong_count(&session) > 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("nothing keeps the ended session");

            assert_eq!(client.ends.load(Ordering::SeqCst), 1);
            assert!(inner.nat.slots.is_empty());
            drop(tunnel);
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic(expected = "a UDP batch began inside another")]
    async fn rounds_do_not_nest() {
        let (_tunnel, inner) = inner();
        let _outer = BatchRound::begin(&inner);
        let _inner = BatchRound::begin(&inner);
    }
}
