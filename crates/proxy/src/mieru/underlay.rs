use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use concord_common::{BoxRead, BoxStream, BoxWrite, Tasks};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::cipher::{Opener, Sealer};
use super::frame::{self, DataFrame};
use super::meta::{self, MAX_OPEN_PAYLOAD, META_LEN, Meta, NONCE_LEN, TAG_LEN, invalid};
use super::padding;
use super::pattern::Pattern;
use crate::util::lock;

const OUT_QUEUE: usize = 32;
const EVENT_QUEUE: usize = 256;
const BATCH: usize = 16;
const STREAM_OVERHEAD: usize = META_LEN + TAG_LEN * 2;
const WINDOW: u16 = 4096;
const TICK: Duration = Duration::from_secs(5);
const IDLE_BASE: Duration = Duration::from_secs(120);

pub(super) trait Wire: Send + Sync {
    fn open_session(&self, id: u32) -> io::Result<mpsc::Receiver<Event>>;
    fn sender(&self, id: u32) -> mpsc::Sender<Out>;
    fn queue(&self, id: u32, out: Out);
    fn forget(&self, id: u32);
    fn is_closed(&self) -> bool;
    fn close(&self);
    fn usable(&self) -> bool;
}

impl Wire for Underlay {
    fn open_session(&self, id: u32) -> io::Result<mpsc::Receiver<Event>> {
        Underlay::open_session(self, id)
    }

    fn sender(&self, _id: u32) -> mpsc::Sender<Out> {
        Underlay::sender(self)
    }

    fn queue(&self, _id: u32, out: Out) {
        Underlay::queue(self, out);
    }

    fn forget(&self, id: u32) {
        Underlay::forget(self, id);
    }

    fn is_closed(&self) -> bool {
        Underlay::is_closed(self)
    }

    fn close(&self) {
        Underlay::close(self);
    }

    fn usable(&self) -> bool {
        Underlay::usable(self)
    }
}

pub(super) enum Out {
    First { id: u32, data: Vec<u8> },
    Data { id: u32, data: Vec<u8> },
    Close { id: u32 },
    CloseAck { id: u32 },
}

pub(super) enum Event {
    Data(Bytes),
    Closed,
}

pub(super) struct Underlay {
    out: mpsc::Sender<Out>,
    sessions: Mutex<HashMap<u32, mpsc::Sender<Event>>>,
    die: CancellationToken,
    last_used: Mutex<Instant>,
    idle_limit: Duration,
    volume_limit: u64,
    bytes: AtomicU64,
    tasks: Tasks,
}

struct Writer {
    sealer: Sealer,
    user: String,
    pattern: Arc<Pattern>,
    seqs: HashMap<u32, u32>,
}

impl Writer {
    fn seq(&mut self, id: u32) -> u32 {
        let slot = self.seqs.entry(id).or_insert(0);
        let seq = *slot;
        *slot = slot.wrapping_add(1);
        seq
    }

    fn session(&mut self, kind: u8, id: u32, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let seq = self.seq(id);
        let padding = padding::session_padding(
            self.pattern.max_end.min(255),
            STREAM_OVERHEAD + payload.len(),
            &self.user,
        );
        frame::write_session(&mut self.sealer, kind, id, seq, payload, &padding, out)
    }

    fn data(&mut self, id: u32, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let seq = self.seq(id);
        let prefix = padding::middle_padding(self.pattern.max_middle.min(255));
        let suffix = padding::middle_padding(self.pattern.max_end.min(255));
        let frame = DataFrame {
            kind: meta::DATA_C2S,
            id,
            seq,
            unack: 0,
            window: WINDOW,
            fragment: 0,
            prefix: &prefix,
            suffix: &suffix,
            payload,
            low: self.pattern.low_entropy,
        };
        frame::write_data(&mut self.sealer, &frame, out)
    }

    fn fragment_size(&self) -> usize {
        match self.pattern.low_entropy {
            Some(low) => padding::max_fragment(low.mode),
            None => meta::MAX_PDU,
        }
    }

    fn first(&mut self, id: u32, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if self.pattern.low_entropy.is_none() && data.len() <= MAX_OPEN_PAYLOAD {
            return self.session(meta::OPEN_REQUEST, id, data, out);
        }
        self.session(meta::OPEN_REQUEST, id, &[], out)?;
        self.send_data(id, data, out)
    }

    fn send_data(&mut self, id: u32, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let size = self.fragment_size();
        for part in data.chunks(size) {
            self.data(id, part, out)?;
        }
        Ok(())
    }
}

fn is_session_frame(out: &Out) -> bool {
    matches!(out, Out::Close { .. } | Out::CloseAck { .. })
}

async fn write_fragmented(sink: &mut BoxWrite, data: &[u8], max_sleep_ms: u32) -> io::Result<()> {
    let total = data.len();
    let min = total.isqrt() + 1;
    let max = min.max(total / 2);
    let mut rest = data;
    while !rest.is_empty() {
        let size = rand::rng().random_range(min..=max).min(rest.len());
        let (head, tail) = rest.split_at(size);
        sink.write_all(head).await?;
        if max_sleep_ms > 0 {
            let pause = rand::rng().random_range(0..=max_sleep_ms);
            tokio::time::sleep(Duration::from_millis(u64::from(pause))).await;
        }
        rest = tail;
    }
    Ok(())
}

impl Underlay {
    pub(super) fn start(
        conn: BoxStream,
        key: &[u8; 32],
        user: &str,
        pattern: Arc<Pattern>,
        factor: usize,
        tasks: &Tasks,
    ) -> Arc<Underlay> {
        let (out, queue) = mpsc::channel(OUT_QUEUE);
        let underlay = Arc::new(Underlay {
            out,
            sessions: Mutex::new(HashMap::new()),
            die: tasks.child_token(),
            last_used: Mutex::new(Instant::now()),
            idle_limit: IDLE_BASE + Duration::from_secs(rand::rng().random_range(0..61)),
            volume_limit: (512u64 << 20) << factor.min(8),
            bytes: AtomicU64::new(0),
            tasks: tasks.clone(),
        });
        let (source, sink) = conn.into_split();
        let writer = Writer {
            sealer: Sealer::new(key, user, pattern.nonce.clone()),
            user: user.to_string(),
            pattern,
            seqs: HashMap::new(),
        };
        tasks.spawn(write_loop(underlay.clone(), sink, queue, writer));
        tasks.spawn(read_loop(underlay.clone(), source, *key));
        underlay
    }

    pub(super) fn sender(&self) -> mpsc::Sender<Out> {
        self.out.clone()
    }

    pub(super) fn is_closed(&self) -> bool {
        self.die.is_cancelled()
    }

    pub(super) fn close(&self) {
        self.die.cancel();
        lock(&self.sessions).clear();
    }

    pub(super) fn usable(&self) -> bool {
        if self.is_closed() || self.bytes.load(Ordering::Relaxed) > self.volume_limit {
            return false;
        }
        let idle = lock(&self.last_used).elapsed();
        !(lock(&self.sessions).is_empty() && idle > self.idle_limit)
    }

    pub(super) fn open_session(&self, id: u32) -> io::Result<mpsc::Receiver<Event>> {
        if self.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let (tx, rx) = mpsc::channel(EVENT_QUEUE);
        let mut sessions = lock(&self.sessions);
        if sessions.contains_key(&id) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        sessions.insert(id, tx);
        *lock(&self.last_used) = Instant::now();
        Ok(rx)
    }

    pub(super) fn has_session(&self, id: u32) -> bool {
        lock(&self.sessions).contains_key(&id)
    }

    pub(super) fn forget(&self, id: u32) {
        lock(&self.sessions).remove(&id);
        *lock(&self.last_used) = Instant::now();
    }

    pub(super) fn queue(&self, out: Out) {
        if let Err(mpsc::error::TrySendError::Full(out)) = self.out.try_send(out) {
            let sender = self.out.clone();
            self.tasks.spawn_detached(async move {
                let _ = sender.send(out).await;
            });
        }
    }

    fn sender_of(&self, id: u32) -> Option<mpsc::Sender<Event>> {
        lock(&self.sessions).get(&id).cloned()
    }

    fn idle_expired(&self) -> bool {
        lock(&self.sessions).is_empty() && lock(&self.last_used).elapsed() > self.idle_limit * 2
    }
}

async fn run_writer(
    underlay: &Underlay,
    sink: &mut BoxWrite,
    queue: &mut mpsc::Receiver<Out>,
    writer: &mut Writer,
) -> io::Result<()> {
    let mut batch = Vec::new();
    loop {
        let Some(first) = queue.recv().await else {
            return Ok(());
        };
        let mut frames = vec![first];
        while frames.len() < BATCH {
            match queue.try_recv() {
                Ok(frame) => frames.push(frame),
                Err(_) => break,
            }
        }
        batch.clear();
        for frame in frames {
            let fragmented = is_session_frame(&frame) && writer.pattern.fragment.enable;
            let mut alone = Vec::new();
            let target = if fragmented { &mut alone } else { &mut batch };
            match frame {
                Out::First { id, data } => writer.first(id, &data, target)?,
                Out::Data { id, data } => writer.send_data(id, &data, target)?,
                Out::Close { id } => {
                    writer.session(meta::CLOSE_REQUEST, id, &[], target)?;
                    writer.seqs.remove(&id);
                }
                Out::CloseAck { id } => {
                    writer.session(meta::CLOSE_RESPONSE, id, &[], target)?;
                    writer.seqs.remove(&id);
                }
            }
            if fragmented {
                sink.write_all(&batch).await?;
                batch.clear();
                write_fragmented(sink, &alone, writer.pattern.fragment.max_sleep_ms).await?;
                underlay
                    .bytes
                    .fetch_add(alone.len() as u64, Ordering::Relaxed);
            }
        }
        if !batch.is_empty() {
            underlay
                .bytes
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            sink.write_all(&batch).await?;
        }
        sink.flush().await?;
    }
}

async fn write_loop(
    underlay: Arc<Underlay>,
    mut sink: BoxWrite,
    mut queue: mpsc::Receiver<Out>,
    mut writer: Writer,
) {
    let result = tokio::select! {
        _ = underlay.die.cancelled() => Ok(()),
        result = run_writer(&underlay, &mut sink, &mut queue, &mut writer) => result,
    };
    if let Err(err) = result {
        tracing::debug!(%err, "mieru: write failed");
    }
    underlay.close();
}

pub(super) struct Reader {
    io: BoxRead,
    buf: BytesMut,
    opener: Opener,
}

pub(super) struct Segment {
    pub(super) meta: Meta,
    pub(super) payload: Vec<u8>,
}

impl Reader {
    pub(super) fn new(io: BoxRead, key: &[u8; 32]) -> Reader {
        Reader {
            io,
            buf: BytesMut::with_capacity(8 * 1024),
            opener: Opener::new(key),
        }
    }

    async fn fill(&mut self, len: usize) -> io::Result<()> {
        while self.buf.len() < len {
            self.buf.reserve(len - self.buf.len());
            if self.io.read_buf(&mut self.buf).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        Ok(())
    }

    fn take(&mut self, len: usize) -> BytesMut {
        self.buf.split_to(len)
    }

    pub(super) async fn segment(&mut self) -> io::Result<Segment> {
        if !self.opener.started() {
            self.fill(NONCE_LEN + META_LEN + TAG_LEN).await?;
            let nonce = self.take(NONCE_LEN);
            self.opener.start(&nonce)?;
        }
        self.fill(META_LEN + TAG_LEN).await?;
        let sealed = self.take(META_LEN + TAG_LEN);
        let meta = Meta::decode(&self.opener.open(&sealed)?)?;
        let payload = match meta {
            Meta::Session {
                payload_len,
                suffix_len,
                ..
            } => {
                let payload = self.payload(usize::from(payload_len), None).await?;
                self.skip(usize::from(suffix_len)).await?;
                payload
            }
            Meta::Data {
                kind,
                prefix_len,
                payload_len,
                suffix_len,
                low,
                ..
            } => {
                self.skip(usize::from(prefix_len)).await?;
                let payload = if meta::is_low_entropy(kind) {
                    self.payload(usize::from(payload_len), Some(low)).await?
                } else {
                    self.payload(usize::from(payload_len), None).await?
                };
                self.skip(usize::from(suffix_len)).await?;
                payload
            }
        };
        Ok(Segment { meta, payload })
    }

    async fn skip(&mut self, len: usize) -> io::Result<()> {
        if len > 0 {
            self.fill(len).await?;
            self.take(len);
        }
        Ok(())
    }

    async fn payload(
        &mut self,
        len: usize,
        low: Option<meta::LowEntropyMeta>,
    ) -> io::Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        self.fill(len + TAG_LEN).await?;
        let wire = self.take(len + TAG_LEN);
        let Some(low) = low else {
            return self.opener.open(&wire);
        };
        if padding::encoded_len(usize::from(low.extracted_len), low.mode)? != len {
            return Err(invalid("low entropy payload length"));
        }
        let (body, tag) = wire.split_at(len);
        let mut sealed = padding::decode_low(
            body,
            usize::from(low.extracted_len),
            low.mode,
            low.mask,
            low.rotation,
        )?;
        sealed.extend_from_slice(tag);
        self.opener.open(&sealed)
    }
}

async fn dispatch(underlay: &Arc<Underlay>, segment: Segment) -> io::Result<()> {
    let deliver = |id: u32, event: Event| {
        let target = underlay.sender_of(id);
        async move {
            match target {
                Some(tx) => tx.send(event).await.is_ok(),
                None => false,
            }
        }
    };
    match segment.meta {
        Meta::Session { kind, id, .. } => match kind {
            meta::OPEN_RESPONSE => {
                if !segment.payload.is_empty() {
                    deliver(id, Event::Data(Bytes::from(segment.payload))).await;
                }
            }
            meta::CLOSE_REQUEST => {
                underlay.queue(Out::CloseAck { id });
                deliver(id, Event::Closed).await;
                underlay.forget(id);
            }
            meta::CLOSE_RESPONSE => {
                deliver(id, Event::Closed).await;
                underlay.forget(id);
            }
            _ => return Err(invalid("unexpected session segment")),
        },
        Meta::Data { kind, id, .. } => match kind {
            meta::DATA_S2C | meta::DATA_S2C_LOW => {
                if segment.payload.is_empty() {
                    return Ok(());
                }
                if underlay.has_session(id) {
                    if !deliver(id, Event::Data(Bytes::from(segment.payload))).await {
                        underlay.forget(id);
                    }
                } else {
                    underlay.queue(Out::Close { id });
                }
            }
            meta::ACK_S2C => {}
            _ => return Err(invalid("unexpected data segment")),
        },
    }
    Ok(())
}

async fn read_loop(underlay: Arc<Underlay>, source: BoxRead, key: [u8; 32]) {
    let mut reader = Reader::new(source, &key);
    let result: io::Result<()> = async {
        let mut tick = tokio::time::interval(TICK);
        loop {
            if reader.buf.is_empty() {
                tokio::select! {
                    _ = underlay.die.cancelled() => return Ok(()),
                    _ = tick.tick() => {
                        if underlay.idle_expired() {
                            return Ok(());
                        }
                        continue;
                    }
                    read = reader.io.read_buf(&mut reader.buf) => {
                        if read? == 0 {
                            return Err(io::ErrorKind::UnexpectedEof.into());
                        }
                    }
                }
            }
            let segment = tokio::select! {
                _ = underlay.die.cancelled() => return Ok(()),
                segment = reader.segment() => segment?,
            };
            underlay
                .bytes
                .fetch_add((segment.payload.len() + META_LEN) as u64, Ordering::Relaxed);
            tokio::select! {
                _ = underlay.die.cancelled() => return Ok(()),
                done = dispatch(&underlay, segment) => done?,
            }
        }
    }
    .await;
    if let Err(err) = result {
        tracing::debug!(%err, "mieru: read failed");
    }
    underlay.close();
}
