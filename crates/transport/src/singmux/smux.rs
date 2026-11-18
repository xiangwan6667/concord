use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use concord_common::sync::lock;
use concord_common::{BoxRead, BoxStream, BoxWrite, Stream, Tasks};
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::PollSender;

use super::MuxSession;
use super::inbox::{Inbox, send_detached, write_frames};
use crate::http1::invalid;

const VERSION: u8 = 1;
const FIRST_STREAM_ID: u32 = 3;
const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const CMD_UPD: u8 = 4;
const MAX_FRAME: usize = 32768;
const MAX_RECEIVE_BUFFER: i64 = 4 * 1024 * 1024;
const QUEUE: usize = 64;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

fn frame(cmd: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(payload.len())
        .unwrap_or(u16::MAX)
        .to_le_bytes();
    let [s0, s1, s2, s3] = sid.to_le_bytes();
    let mut out = vec![VERSION, cmd, len[0], len[1], s0, s1, s2, s3];
    out.extend_from_slice(payload);
    out
}

struct Entry {
    inbox: Inbox,
    remote_fin: AtomicBool,
}

struct Core {
    streams: Mutex<HashMap<u32, Arc<Entry>>>,
    next_id: AtomicU32,
    tx: mpsc::Sender<Vec<u8>>,
    closed: AtomicBool,
    bucket: AtomicI64,
    bucket_notify: Notify,
    fin_queued: Option<AtomicBool>,
    tasks: Tasks,
}

impl Core {
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let streams = std::mem::take(&mut *lock(&self.streams));
        for entry in streams.values() {
            entry
                .inbox
                .fail(io::ErrorKind::BrokenPipe, "smux session closed");
        }
        self.bucket_notify.notify_one();
    }

    fn return_tokens(&self, n: usize) {
        let n = i64::try_from(n).unwrap_or(i64::MAX);
        if self.bucket.fetch_add(n, Ordering::Relaxed) <= 0 {
            self.bucket_notify.notify_one();
        }
    }
}

pub(super) struct SmuxSession {
    core: Arc<Core>,
    tasks: Vec<JoinHandle<()>>,
    stop: Option<oneshot::Sender<()>>,
}

impl SmuxSession {
    pub fn new(io: BoxStream, tasks: &Tasks) -> Self {
        Self::start(io, FIRST_STREAM_ID, false, tasks)
    }

    pub(super) fn with_first_id(io: BoxStream, first_id: u32, tasks: &Tasks) -> Self {
        Self::start(io, first_id, true, tasks)
    }

    fn start(io: BoxStream, first_id: u32, drain_on_drop: bool, tasks: &Tasks) -> Self {
        let (read, write) = Box::new(io).into_split();
        let (tx, rx) = mpsc::channel(QUEUE);
        let (stop, stopped) = if drain_on_drop {
            let (tx, rx) = oneshot::channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let core = Arc::new(Core {
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(first_id),
            tx,
            closed: AtomicBool::new(false),
            bucket: AtomicI64::new(MAX_RECEIVE_BUFFER),
            bucket_notify: Notify::new(),
            fin_queued: drain_on_drop.then(|| AtomicBool::new(false)),
            tasks: tasks.clone(),
        });
        let reader = {
            let core = core.clone();
            tasks.spawn(async move {
                let _ = read_loop(&core, read).await;
                core.close();
            })
        };
        let writer = {
            let core = core.clone();
            tasks.spawn(async move {
                if let Some(stopped) = stopped {
                    let _ = write_frames_draining(write, rx, stopped, &core, first_id).await;
                } else {
                    let _ = write_frames(write, rx).await;
                }
                core.close();
            })
        };
        SmuxSession {
            core,
            tasks: vec![reader, writer],
            stop,
        }
    }
}

async fn write_frames_draining(
    mut write: BoxWrite,
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut stopped: oneshot::Receiver<()>,
    core: &Core,
    stream_id: u32,
) -> io::Result<()> {
    loop {
        tokio::select! {
            _ = &mut stopped => { rx.close(); break; }
            frame = rx.recv() => {
                let Some(frame) = frame else { break; };
                write.write_all(&frame).await?;
                if rx.is_empty() { write.flush().await?; }
            }
        }
    }
    while let Some(frame) = rx.recv().await {
        write.write_all(&frame).await?;
    }
    if core
        .fin_queued
        .as_ref()
        .is_some_and(|fin| !fin.load(Ordering::Relaxed))
    {
        write.write_all(&frame(CMD_FIN, stream_id, &[])).await?;
    }
    write.flush().await?;
    write.shutdown().await
}

async fn read_loop(core: &Core, mut io: BoxRead) -> io::Result<()> {
    loop {
        while core.bucket.load(Ordering::Relaxed) <= 0 {
            if core.closed.load(Ordering::Relaxed) {
                return Ok(());
            }
            core.bucket_notify.notified().await;
        }
        let mut header = [0u8; 8];
        io.read_exact(&mut header).await?;
        let [version, cmd, l0, l1, s0, s1, s2, s3] = header;
        if version != VERSION {
            return Err(invalid("smux: invalid protocol version"));
        }
        let len = usize::from(u16::from_le_bytes([l0, l1]));
        let sid = u32::from_le_bytes([s0, s1, s2, s3]);
        match cmd {
            CMD_NOP | CMD_SYN => {}
            CMD_FIN => {
                if let Some(entry) = lock(&core.streams).get(&sid) {
                    entry.remote_fin.store(true, Ordering::Relaxed);
                    entry.inbox.fin();
                }
            }
            CMD_PSH => {
                if len == 0 {
                    continue;
                }
                let mut payload = vec![0u8; len];
                io.read_exact(&mut payload).await?;
                let entry = lock(&core.streams).get(&sid).cloned();
                if let Some(entry) = entry {
                    core.bucket
                        .fetch_sub(i64::try_from(len).unwrap_or(i64::MAX), Ordering::Relaxed);
                    if !entry.inbox.push(Bytes::from(payload)) {
                        core.return_tokens(len);
                    }
                }
            }
            CMD_UPD => {
                let mut update = [0u8; 8];
                io.read_exact(&mut update).await?;
            }
            _ => return Err(invalid("smux: invalid command")),
        }
    }
}

/// Without a runtime to drain on, the writer stops with the session.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Drop for SmuxSession {
    fn drop(&mut self) {
        self.core.close();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
            let mut tasks = self.tasks.drain(..);
            if let Some(reader) = tasks.next() {
                reader.abort();
            }
            if let Some(mut writer) = tasks.next() {
                let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
                let guard = AbortOnDrop(writer.abort_handle());
                self.core.tasks.spawn_detached(async move {
                    let _guard = guard;
                    if tokio::time::timeout_at(deadline, &mut writer)
                        .await
                        .is_err()
                    {
                        writer.abort();
                        let _ = writer.await;
                    }
                });
            }
        } else {
            for task in &self.tasks {
                task.abort();
            }
        }
    }
}

impl MuxSession for SmuxSession {
    fn open(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(async move {
            if self.core.closed.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let id = self.core.next_id.fetch_add(2, Ordering::Relaxed);
            let entry = Arc::new(Entry {
                inbox: Inbox::default(),
                remote_fin: AtomicBool::new(false),
            });
            lock(&self.core.streams).insert(id, entry.clone());
            let stream = SmuxStream::new(id, self.core.clone(), entry);
            self.core
                .tx
                .send(frame(CMD_SYN, id, &[]))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn streams(&self) -> usize {
        lock(&self.core.streams).len()
    }

    fn is_closed(&self) -> bool {
        self.core.closed.load(Ordering::Relaxed)
    }

    fn close(&self) {
        self.core.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}

struct Shared {
    id: u32,
    core: Arc<Core>,
    entry: Arc<Entry>,
    closed: AtomicBool,
}

impl Shared {
    fn release(&self) {
        lock(&self.core.streams).remove(&self.id);
        let dropped = self.entry.inbox.close_read();
        if dropped > 0 {
            self.core.return_tokens(dropped);
        }
    }
}

struct SmuxRead {
    shared: Arc<Shared>,
}

struct SmuxWrite {
    shared: Arc<Shared>,
    sender: PollSender<Vec<u8>>,
}

struct SmuxStream {
    write: SmuxWrite,
    read: SmuxRead,
}

impl SmuxStream {
    fn new(id: u32, core: Arc<Core>, entry: Arc<Entry>) -> Self {
        let sender = PollSender::new(core.tx.clone());
        let shared = Arc::new(Shared {
            id,
            core,
            entry,
            closed: AtomicBool::new(false),
        });
        SmuxStream {
            write: SmuxWrite {
                shared: shared.clone(),
                sender,
            },
            read: SmuxRead { shared },
        }
    }
}

impl AsyncRead for SmuxRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let shared = &*self.get_mut().shared;
        if shared.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(()));
        }
        let n = ready!(shared.entry.inbox.poll_read(cx, buf))?;
        if n > 0 {
            shared.core.return_tokens(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for SmuxRead {
    fn drop(&mut self) {
        let dropped = self.shared.entry.inbox.close_read();
        if dropped > 0 {
            self.shared.core.return_tokens(dropped);
        }
    }
}

impl AsyncWrite for SmuxWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let shared = &*this.shared;
        if shared.closed.load(Ordering::Relaxed) || shared.entry.remote_fin.load(Ordering::Relaxed)
        {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let take = data.len().min(MAX_FRAME);
        let Some(chunk) = data.get(..take).filter(|chunk| !chunk.is_empty()) else {
            return Poll::Ready(Ok(0));
        };
        ready!(this.sender.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        this.sender
            .send_item(frame(CMD_PSH, shared.id, chunk))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let shared = &*this.shared;
        if !shared.closed.load(Ordering::Relaxed) {
            ready!(this.sender.poll_reserve(cx))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            this.sender
                .send_item(frame(CMD_FIN, shared.id, &[]))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            if let Some(fin_queued) = &shared.core.fin_queued {
                fin_queued.store(true, Ordering::Relaxed);
            }
            shared.closed.store(true, Ordering::Relaxed);
            shared.release();
        }
        Poll::Ready(Ok(()))
    }
}

/// Smux has no half-close, so like `poll_shutdown` this ends the whole stream.
impl Drop for SmuxWrite {
    fn drop(&mut self) {
        let shared = &*self.shared;
        if !shared.closed.swap(true, Ordering::Relaxed) {
            if shared.core.fin_queued.is_none() {
                send_detached(
                    &shared.core.tasks,
                    &shared.core.tx,
                    frame(CMD_FIN, shared.id, &[]),
                );
            }
            shared.release();
        }
    }
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

impl Stream for SmuxStream {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let SmuxStream { write, read } = *self;
        (Box::new(read), Box::new(write))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    async fn next_frame(far: &mut (impl AsyncRead + Unpin)) -> (u8, u32) {
        let mut header = [0u8; 8];
        far.read_exact(&mut header).await.unwrap();
        let [_, cmd, l0, l1, s0, s1, s2, s3] = header;
        let mut payload = vec![0; usize::from(u16::from_le_bytes([l0, l1]))];
        far.read_exact(&mut payload).await.unwrap();
        (cmd, u32::from_le_bytes([s0, s1, s2, s3]))
    }

    #[tokio::test]
    async fn first_smux_syn_matches_mihomo_and_sing_box_client_bytes() {
        let (near, mut far) = duplex(128);
        let session = SmuxSession::new(Box::new(near), &Default::default());
        let _first = session.open().await.unwrap();
        let mut header = [0; 8];
        far.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [1, 0, 0, 0, 3, 0, 0, 0]);
        let _second = session.open().await.unwrap();
        far.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [1, 0, 0, 0, 5, 0, 0, 0]);
    }

    #[tokio::test]
    async fn dropping_either_half_first_leaves_the_session_to_other_streams() {
        for read_first in [true, false] {
            let (near, far) = duplex(64 * 1024);
            let (mut far_read, mut far_write) = tokio::io::split(far);
            let session = SmuxSession::new(Box::new(near), &Default::default());
            let first = session.open().await.unwrap();
            let mut second = session.open().await.unwrap();
            assert_eq!(next_frame(&mut far_read).await, (CMD_SYN, FIRST_STREAM_ID));
            assert_eq!(
                next_frame(&mut far_read).await,
                (CMD_SYN, FIRST_STREAM_ID + 2)
            );
            let (read, write) = first.into_split();
            let rest: Box<dyn Send> = if read_first {
                drop(read);
                Box::new(write)
            } else {
                drop(write);
                Box::new(read)
            };
            let flood = usize::try_from(MAX_RECEIVE_BUFFER).unwrap() / MAX_FRAME + 8;
            tokio::time::timeout(Duration::from_secs(10), async {
                if !read_first {
                    assert_eq!(next_frame(&mut far_read).await, (CMD_FIN, FIRST_STREAM_ID));
                }
                let chunk = vec![7u8; MAX_FRAME];
                for _ in 0..flood {
                    far_write
                        .write_all(&frame(CMD_PSH, FIRST_STREAM_ID, &chunk))
                        .await
                        .unwrap();
                }
                far_write
                    .write_all(&frame(CMD_PSH, FIRST_STREAM_ID + 2, b"ok"))
                    .await
                    .unwrap();
                let mut got = [0u8; 2];
                second.read_exact(&mut got).await.unwrap();
                assert_eq!(&got, b"ok");
                drop(rest);
                if read_first {
                    assert_eq!(next_frame(&mut far_read).await, (CMD_FIN, FIRST_STREAM_ID));
                }
            })
            .await
            .expect("a dropped half held the session up");
        }
    }
}
