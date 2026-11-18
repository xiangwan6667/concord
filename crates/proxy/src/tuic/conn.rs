use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use concord_common::{Address, DialCx, Tasks};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::Shared;
use super::wire::{self, Command, Defrag, Incoming, Version};
use crate::quic::{QuicConn, io_error};
use crate::util::lock;

const QUEUE: usize = 64;
const IDLE_CLOSE: Duration = Duration::from_secs(30 * 60);
/// One Packet command: version, type, the 8-byte packet header, the longest address and a
/// payload of the largest size its 16-bit field holds.
const MAX_STREAM_PACKET: usize = 2 + 8 + 259 + u16::MAX as usize;

pub(super) struct Entry {
    queue: mpsc::Sender<(Address, Bytes)>,
    defrag: Mutex<Defrag>,
}

/// Hands the relayed datagrams of one connection to the association they name.
#[derive(Default)]
pub(super) struct Hub {
    sessions: Mutex<HashMap<u32, Arc<Entry>>>,
}

impl Hub {
    pub(super) fn register(
        &self,
        version: Version,
    ) -> Option<(u32, mpsc::Receiver<(Address, Bytes)>)> {
        let (queue, rx) = mpsc::channel(QUEUE);
        let mut sessions = lock(&self.sessions);
        let id = (0..16).find_map(|_| {
            let id = match version {
                Version::V5 => u32::from(rand::random::<u16>().max(1)),
                Version::V4 => rand::random::<u32>().max(1),
            };
            (!sessions.contains_key(&id)).then_some(id)
        })?;
        sessions.insert(
            id,
            Arc::new(Entry {
                queue,
                defrag: Mutex::new(Defrag::default()),
            }),
        );
        Some((id, rx))
    }

    pub(super) fn remove(&self, id: u32) {
        lock(&self.sessions).remove(&id);
    }

    fn close_all(&self) {
        lock(&self.sessions).clear();
    }

    fn deliver(&self, part: Incoming) {
        let Some(entry) = lock(&self.sessions).get(&part.assoc).cloned() else {
            return;
        };
        if let Some(whole) = lock(&entry.defrag).feed(part) {
            let _ = entry.queue.try_send(whole);
        }
    }
}

/// One QUIC connection to the server, authenticated, with the tasks that feed
/// relayed packets to their associations.
pub(super) struct Live {
    pub(super) quic: QuicConn,
    pub(super) hub: Arc<Hub>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Live {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        self.hub.close_all();
    }
}

impl Live {
    pub(super) fn alive(&self) -> bool {
        self.quic.conn.close_reason().is_none()
    }
}

async fn authenticate(shared: &Shared, conn: &quinn::Connection) -> io::Result<()> {
    let frame = match shared.version {
        Version::V5 => {
            let mut token = [0u8; 32];
            conn.export_keying_material(&mut token, &shared.uuid, shared.password.as_bytes())
                .map_err(|_| io::Error::other("tuic: exporting the keying material failed"))?;
            wire::auth_v5(&shared.uuid, &token)
        }
        Version::V4 => wire::auth_v4(&shared.token),
    };
    let mut stream = conn.open_uni().await.map_err(io_error)?;
    stream.write_all(&frame).await.map_err(io_error)?;
    stream.finish().map_err(io_error)
}

async fn read_datagrams(version: Version, conn: quinn::Connection, hub: Arc<Hub>) {
    while let Ok(datagram) = conn.read_datagram().await {
        match wire::parse_command(version, &datagram) {
            Ok(Command::Packet(part)) => hub.deliver(part),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    conn.close(quinn::VarInt::from_u32(0), b"");
}

async fn read_streams(version: Version, conn: quinn::Connection, hub: Arc<Hub>, tasks: Tasks) {
    while let Ok(mut stream) = conn.accept_uni().await {
        let hub = hub.clone();
        tasks.spawn(async move {
            let Ok(data) = stream.read_to_end(MAX_STREAM_PACKET).await else {
                return;
            };
            if let Ok(Command::Packet(part)) = wire::parse_command(version, &Bytes::from(data)) {
                hub.deliver(part);
            }
        });
    }
}

impl Live {
    async fn establish(shared: &Shared, cx: &DialCx<'_>, udp: bool) -> io::Result<Live> {
        let quic = shared.link.connect_any(cx).await?;
        authenticate(shared, &quic.conn).await?;
        let hub = Arc::new(Hub::default());
        let mut tasks = Vec::new();
        if udp {
            if shared.native {
                tasks.push(quic.tasks.spawn(read_datagrams(
                    shared.version,
                    quic.conn.clone(),
                    hub.clone(),
                )));
            } else {
                tasks.push(quic.tasks.spawn(read_streams(
                    shared.version,
                    quic.conn.clone(),
                    hub.clone(),
                    quic.tasks.clone(),
                )));
            }
        }
        Ok(Live { quic, hub, tasks })
    }
}

/// One connection slot of a pool. It reconnects when its connection is gone.
pub(super) struct Slot {
    udp: bool,
    live: tokio::sync::Mutex<Option<Arc<Live>>>,
    open: AtomicI64,
    visited: Mutex<Instant>,
}

/// Counts a stream or association against its slot while it exists.
pub(super) struct Counted(Arc<Slot>);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Slot {
    fn new(udp: bool) -> Arc<Slot> {
        Arc::new(Slot {
            udp,
            live: tokio::sync::Mutex::new(None),
            open: AtomicI64::new(0),
            visited: Mutex::new(Instant::now()),
        })
    }

    pub(super) fn count(self: &Arc<Self>) -> Counted {
        self.open.fetch_add(1, Ordering::AcqRel);
        Counted(self.clone())
    }

    pub(super) async fn live(&self, shared: &Shared, cx: &DialCx<'_>) -> io::Result<Arc<Live>> {
        let mut live = self.live.lock().await;
        if let Some(current) = live.as_ref().filter(|current| current.alive()) {
            return Ok(current.clone());
        }
        let fresh = Arc::new(Live::establish(shared, cx, self.udp).await?);
        *live = Some(fresh.clone());
        Ok(fresh)
    }

    fn close(&self) {
        if let Ok(mut live) = self.live.try_lock()
            && let Some(live) = live.take()
        {
            live.quic.conn.close(quinn::VarInt::from_u32(0), b"");
        }
    }
}

/// TCP and UDP use separate pools, as in mihomo, and each grows by one
/// connection when its least busy one is full.
#[derive(Default)]
pub(super) struct Pool {
    slots: Mutex<Vec<Arc<Slot>>>,
}

impl Pool {
    pub(super) fn pick(&self, udp: bool, max_open: i64) -> Arc<Slot> {
        let mut slots = lock(&self.slots);
        let best = slots
            .iter()
            .min_by_key(|slot| slot.open.load(Ordering::Acquire))
            .cloned();
        let chosen = match best {
            Some(best) if best.open.load(Ordering::Acquire) + 1 < max_open => best,
            _ => {
                let fresh = Slot::new(udp);
                slots.push(fresh.clone());
                fresh
            }
        };
        let now = Instant::now();
        slots.retain(|slot| {
            let idle = slot.open.load(Ordering::Acquire) == 0
                && now.duration_since(*lock(&slot.visited)) > IDLE_CLOSE;
            let keep = Arc::ptr_eq(slot, &chosen) || !idle;
            if !keep {
                slot.close();
            }
            keep
        });
        *lock(&chosen.visited) = now;
        chosen
    }

    pub(super) fn close(&self) {
        for slot in lock(&self.slots).drain(..) {
            slot.close();
        }
    }
}
