use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use concord_common::{Address, PacketBuf, PacketSession, Stream, Tasks};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

use super::wire::{control_entry, datagram, read_control_entry, split_datagram};
use crate::quic::{DatagramHub, QuicStream};
use crate::util::lock;

const MAX_PENDING_PER_ID: usize = 32;
const INBOX: usize = 128;
const WRITER_QUEUE: usize = 64;

type Packet = (Address, Vec<u8>);
type Inbox = mpsc::Sender<Packet>;
type WeakInbox = mpsc::WeakSender<Packet>;

#[derive(Default)]
struct Slot {
    target: Option<(Inbox, Address)>,
    pending: Vec<Vec<u8>>,
}

#[derive(Default)]
struct RecvSlots {
    by_id: HashMap<u16, Slot>,
    closed: bool,
}

#[derive(Default)]
struct SendIds {
    next: u16,
    active: HashSet<u16>,
}

/// What every association of one connection shares: the ids the server and
/// this side have handed out, and the packets that arrived before their id was
/// introduced.
#[derive(Default)]
pub(super) struct Shared {
    recv: Mutex<RecvSlots>,
    send: Mutex<SendIds>,
    introduced: Notify,
}

impl Shared {
    fn allocate(&self) -> Option<u16> {
        let mut ids = lock(&self.send);
        let start = ids.next;
        loop {
            let id = ids.next;
            ids.next = ids.next.wrapping_add(1);
            if ids.active.insert(id) {
                return Some(id);
            }
            if ids.next == start {
                return None;
            }
        }
    }

    fn release(&self, ids: &HashSet<u16>) {
        let mut send = lock(&self.send);
        for id in ids {
            send.active.remove(id);
        }
    }

    fn introduce(&self, id: u16, inbox: &Inbox, addr: &Address) {
        let pending = {
            let mut recv = lock(&self.recv);
            if recv.closed {
                return;
            }
            let slot = recv.by_id.entry(id).or_default();
            slot.target = Some((inbox.clone(), addr.clone()));
            std::mem::take(&mut slot.pending)
        };
        self.introduced.notify_waiters();
        for packet in pending {
            let _ = inbox.try_send((addr.clone(), packet));
        }
    }

    fn forget(&self, ids: &HashSet<u16>, inbox: &Inbox) {
        let mut recv = lock(&self.recv);
        for id in ids {
            let ours = recv
                .by_id
                .get(id)
                .and_then(|slot| slot.target.as_ref())
                .is_some_and(|(held, _)| held.same_channel(inbox));
            if ours {
                recv.by_id.remove(id);
            }
        }
    }

    fn deliver(&self, id: u16, payload: &[u8]) {
        let mut recv = lock(&self.recv);
        let RecvSlots { by_id, closed } = &mut *recv;
        let slot = match by_id.entry(id) {
            Entry::Occupied(slot) => slot.into_mut(),
            Entry::Vacant(slot) if !*closed => slot.insert(Slot::default()),
            Entry::Vacant(_) => return,
        };
        match &slot.target {
            Some((inbox, addr)) => {
                let _ = inbox.try_send((addr.clone(), payload.to_vec()));
            }
            None if slot.pending.len() < MAX_PENDING_PER_ID => slot.pending.push(payload.to_vec()),
            None => {}
        }
    }

    /// The packets of a unidirectional stream belong to an id the server may
    /// introduce only after the stream was opened.
    pub(super) async fn target(&self, id: u16) -> io::Result<(WeakInbox, Address)> {
        loop {
            let introduced = self.introduced.notified();
            tokio::pin!(introduced);
            introduced.as_mut().enable();
            {
                let recv = lock(&self.recv);
                if recv.closed {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                if let Some((inbox, addr)) =
                    recv.by_id.get(&id).and_then(|slot| slot.target.as_ref())
                {
                    return Ok((inbox.downgrade(), addr.clone()));
                }
            }
            introduced.await;
        }
    }
}

impl DatagramHub for Shared {
    fn dispatch(&self, message: &Bytes) {
        if let Some((id, payload)) = split_datagram(message) {
            self.deliver(id, payload);
        }
    }

    fn close_all(&self) {
        let mut recv = lock(&self.recv);
        recv.closed = true;
        recv.by_id.clear();
        drop(recv);
        self.introduced.notify_waiters();
    }
}

enum Job {
    Control(Vec<u8>),
    Stream { id: u16, payload: Vec<u8> },
}

/// One UDP association. Control entries and stream packets go through a writer
/// task so that `poll_send` never waits.
pub(super) struct ShadowPackets {
    conn: quinn::Connection,
    shared: Arc<Shared>,
    inbox: WeakInbox,
    incoming: Mutex<mpsc::Receiver<Packet>>,
    sends: Mutex<HashMap<Address, u16>>,
    recv_ids: Arc<Mutex<HashSet<u16>>>,
    jobs: mpsc::Sender<Job>,
    over_stream: bool,
    closed: Arc<AtomicBool>,
    tasks: [JoinHandle<()>; 2],
    _hold: Arc<dyn Send + Sync>,
}

impl ShadowPackets {
    pub(super) fn new(
        conn: quinn::Connection,
        shared: Arc<Shared>,
        control: QuicStream,
        over_stream: bool,
        hold: Arc<dyn Send + Sync>,
        tasks: &Tasks,
    ) -> Self {
        let (inbox, incoming) = mpsc::channel(INBOX);
        let weak_inbox = inbox.downgrade();
        let (jobs, mut queued) = mpsc::channel::<Job>(WRITER_QUEUE);
        let closed = Arc::new(AtomicBool::new(false));
        let (mut control_read, mut control_write) = Box::new(control).into_split();
        let recv_ids = Arc::new(Mutex::new(HashSet::<u16>::new()));
        let writer = {
            let (conn, closed) = (conn.clone(), closed.clone());
            tasks.spawn(async move {
                let mut streams: HashMap<u16, quinn::SendStream> = HashMap::new();
                while let Some(job) = queued.recv().await {
                    let result = match job {
                        Job::Control(entry) => control_write.write_all(&entry).await,
                        Job::Stream { id, payload } => {
                            write_stream_packet(&conn, &mut streams, id, &payload).await
                        }
                    };
                    if result.is_err() {
                        break;
                    }
                }
                closed.store(true, Ordering::Relaxed);
                for stream in streams.values_mut() {
                    let _ = stream.finish();
                }
                let _ = control_write.shutdown().await;
            })
        };
        let reader = {
            let (shared, closed, recv_ids) = (shared.clone(), closed.clone(), recv_ids.clone());
            let writer = writer.abort_handle();
            tasks.spawn(async move {
                while let Ok((addr, id)) = read_control_entry(&mut control_read).await {
                    let mut ids = lock(&recv_ids);
                    if closed.load(Ordering::Relaxed) {
                        break;
                    }
                    ids.insert(id);
                    shared.introduce(id, &inbox, &addr);
                }
                closed.store(true, Ordering::Relaxed);
                writer.abort();
                shared.forget(&lock(&recv_ids), &inbox);
            })
        };
        ShadowPackets {
            conn,
            shared,
            inbox: weak_inbox,
            incoming: Mutex::new(incoming),
            sends: Mutex::new(HashMap::new()),
            recv_ids,
            jobs,
            over_stream,
            closed,
            tasks: [reader, writer],
            _hold: hold,
        }
    }

    fn id_for(&self, dst: &Address) -> io::Result<u16> {
        let mut sends = lock(&self.sends);
        if let Some(id) = sends.get(dst) {
            return Ok(*id);
        }
        let id = self
            .shared
            .allocate()
            .ok_or_else(|| io::Error::other("shadowquic: too many udp contexts"))?;
        let entry = match control_entry(dst, id) {
            Ok(entry) => entry,
            Err(err) => {
                self.shared.release(&HashSet::from([id]));
                return Err(err);
            }
        };
        if self.jobs.try_send(Job::Control(entry)).is_err() {
            self.shared.release(&HashSet::from([id]));
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        sends.insert(dst.clone(), id);
        Ok(id)
    }

    fn release(&self) {
        let ids: HashSet<u16> = lock(&self.sends).values().copied().collect();
        self.shared.release(&ids);
    }
}

async fn write_stream_packet(
    conn: &quinn::Connection,
    streams: &mut HashMap<u16, quinn::SendStream>,
    id: u16,
    payload: &[u8],
) -> io::Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
    if let Entry::Vacant(slot) = streams.entry(id) {
        let mut stream = conn.open_uni().await.map_err(io::Error::other)?;
        stream.write_all(&id.to_be_bytes()).await?;
        slot.insert(stream);
    }
    let stream = streams
        .get_mut(&id)
        .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await?;
    Ok(())
}

impl PacketSession for ShadowPackets {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let payload = pkt.as_slice();
        if payload.len() > usize::from(u16::MAX) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shadowquic: packet too large",
            )));
        }
        let sent = self.id_for(dst).and_then(|id| {
            if self.over_stream {
                let job = Job::Stream {
                    id,
                    payload: payload.to_vec(),
                };
                let _ = self.jobs.try_send(job);
                return Ok(());
            }
            self.conn
                .send_datagram(Bytes::from(datagram(id, payload)))
                .map_err(|err| match err {
                    quinn::SendDatagramError::TooLarge => {
                        io::Error::new(io::ErrorKind::InvalidInput, "datagram too large")
                    }
                    other => io::Error::other(other),
                })
        });
        Poll::Ready(sent)
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        match lock(&self.incoming).poll_recv(cx) {
            Poll::Ready(Some((from, data))) => {
                buf.extend_from_slice(&data);
                Poll::Ready(Ok(from))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

impl Drop for ShadowPackets {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        for task in &self.tasks {
            task.abort();
        }
        self.release();
        if let Some(inbox) = self.inbox.upgrade() {
            self.shared.forget(&lock(&self.recv_ids), &inbox);
        }
    }
}
