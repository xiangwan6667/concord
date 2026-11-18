use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

use super::congestion::{Cubic, Rtt};
use super::meta::{self, Meta};
use super::packet::{Inbound, PacketUnderlay};
use super::underlay::{Event, Out};

const MIN_WINDOW: u32 = 16;
const TREE: usize = 4096;
const SEND_QUEUE: usize = 1024;
const MAX_OPEN_PAYLOAD: usize = meta::MAX_OPEN_PAYLOAD;
const ACK_DELAY: Duration = Duration::from_millis(1);
const RETRANSMISSION_CHECK: Duration = Duration::from_millis(10);
const MIN_OUTPUT: Duration = Duration::from_millis(1);
const EARLY_RETRANSMISSION: u8 = 3;
const EARLY_RETRANSMISSION_LIMIT: u8 = 1;
const BACK_OFF: f64 = 1.5;
pub(super) const MAX_BACK_OFF: Duration = Duration::from_secs(10);
const TX_LIMIT: u8 = 20;
const HEARTBEAT: Duration = Duration::from_secs(5);
const HEARTBEAT_JITTER_MS: i64 = 1000;
const SILENCE_LIMIT: Duration = Duration::from_secs(60);
const CLOSE_DRAIN: Duration = Duration::from_secs(1);
const BURST: usize = 128;

#[derive(Clone, Copy)]
enum Kind {
    Open,
    Data(u8),
}

struct Seg {
    kind: Kind,
    seq: u32,
    payload: Vec<u8>,
    tx_count: u8,
    ack_count: u8,
    tx_time: Instant,
    tx_timeout: Duration,
}

enum End {
    /// The peer closed the session; data it sent before is still delivered.
    Peer,
    Local,
    Failed(io::Error),
}

impl From<io::Error> for End {
    fn from(err: io::Error) -> End {
        End::Failed(err)
    }
}

#[derive(Default)]
struct Stats {
    sent: u64,
    early: u64,
    timeouts: u64,
}

pub(super) struct Session {
    id: u32,
    wire: Arc<PacketUnderlay>,
    events: mpsc::Sender<Event>,
    out_rx: mpsc::Receiver<Out>,
    in_rx: mpsc::Receiver<Inbound>,
    send_queue: VecDeque<Seg>,
    send_buf: BTreeMap<u32, Seg>,
    recv_buf: BTreeMap<u32, Inbound>,
    ready: VecDeque<Event>,
    next_send: u32,
    next_recv: u32,
    remote_window: u32,
    opened: bool,
    established: bool,
    closing: Option<Instant>,
    rtt: Rtt,
    cubic: Cubic,
    next_retransmission: Instant,
    ack_deadline: Option<Instant>,
    last_tx: Instant,
    last_rx: Instant,
    heartbeat: Duration,
    stats: Stats,
}

fn beat() -> Duration {
    let ms = rand::rng().random_range(-HEARTBEAT_JITTER_MS..=HEARTBEAT_JITTER_MS);
    let base = i64::try_from(HEARTBEAT.as_millis()).unwrap_or(5000);
    Duration::from_millis(u64::try_from(base + ms).unwrap_or(0))
}

impl Session {
    pub(super) fn new(
        wire: Arc<PacketUnderlay>,
        id: u32,
        events: mpsc::Sender<Event>,
        out_rx: mpsc::Receiver<Out>,
        in_rx: mpsc::Receiver<Inbound>,
    ) -> Session {
        let now = Instant::now();
        Session {
            id,
            wire,
            events,
            out_rx,
            in_rx,
            send_queue: VecDeque::new(),
            send_buf: BTreeMap::new(),
            recv_buf: BTreeMap::new(),
            ready: VecDeque::new(),
            next_send: 0,
            next_recv: 0,
            remote_window: MIN_WINDOW,
            opened: false,
            established: false,
            closing: None,
            rtt: Rtt::new(ACK_DELAY, BACK_OFF),
            cubic: Cubic::new(MIN_WINDOW, TREE as u32),
            next_retransmission: now,
            ack_deadline: None,
            last_tx: now,
            last_rx: now,
            heartbeat: beat(),
            stats: Stats::default(),
        }
    }

    pub(super) async fn run(mut self) {
        let end = self.drive().await;
        tracing::debug!(
            id = self.id,
            sent = self.stats.sent,
            early = self.stats.early,
            timeouts = self.stats.timeouts,
            window = self.cubic.window(),
            "mieru: udp session ended"
        );
        match end {
            End::Peer => {
                self.ready.push_back(Event::Closed);
                while let Some(event) = self.ready.pop_front() {
                    if self.events.send(event).await.is_err() {
                        break;
                    }
                }
            }
            End::Local => {}
            End::Failed(err) => tracing::debug!(%err, id = self.id, "mieru: udp session failed"),
        }
        self.wire.remove(self.id);
    }

    async fn drive(&mut self) -> End {
        loop {
            if let Err(end) = self.output().await {
                return end;
            }
            if let Some(end) = self.finished().await {
                return end;
            }
            let wake = self.next_wake();
            let room = self.closing.is_none() && self.send_room();
            let events = self.events.clone();
            tokio::select! {
                () = self.wire.die.cancelled() => return End::Local,
                segment = self.in_rx.recv() => {
                    let Some(segment) = segment else { return End::Local };
                    if let Err(end) = self.input(segment) {
                        return end;
                    }
                    for _ in 0..BURST {
                        let Ok(segment) = self.in_rx.try_recv() else { break };
                        if let Err(end) = self.input(segment) {
                            return end;
                        }
                    }
                }
                out = self.out_rx.recv(), if room => match out {
                    Some(out) => self.accept(out),
                    None => self.closing = self.closing.or(Some(Instant::now())),
                },
                permit = events.reserve(), if !self.ready.is_empty() => {
                    match (permit, self.ready.pop_front()) {
                        (Ok(permit), Some(event)) => permit.send(event),
                        _ => self.abandon(),
                    }
                }
                () = sleep_until(wake) => {}
            }
        }
    }

    /// The application dropped its end: nothing more is read, and the session winds down.
    fn abandon(&mut self) {
        self.ready.clear();
        if self.closing.is_none() {
            self.closing = Some(Instant::now());
        }
    }

    fn accept(&mut self, out: Out) {
        match out {
            Out::First { data, .. } => {
                if self.opened {
                    return;
                }
                self.opened = true;
                if self.wire.low_entropy() || data.len() > MAX_OPEN_PAYLOAD {
                    self.push(Kind::Open, Vec::new());
                    self.enqueue(&data);
                } else {
                    self.push(Kind::Open, data);
                }
            }
            Out::Data { data, .. } => self.enqueue(&data),
            Out::Close { .. } | Out::CloseAck { .. } => {
                self.closing = Some(self.closing.unwrap_or_else(Instant::now));
            }
        }
    }

    fn push(&mut self, kind: Kind, payload: Vec<u8>) {
        let now = Instant::now();
        self.send_queue.push_back(Seg {
            kind,
            seq: self.next_send,
            payload,
            tx_count: 0,
            ack_count: 0,
            tx_time: now,
            tx_timeout: Duration::ZERO,
        });
        self.next_send = self.next_send.wrapping_add(1);
    }

    /// Room for one more application chunk: all its fragments, with a slot left for the close.
    fn send_room(&self) -> bool {
        let fragments = meta::MAX_PDU.div_ceil(self.wire.fragment_size().max(1));
        SEND_QUEUE - self.send_queue.len() > fragments
    }

    fn enqueue(&mut self, data: &[u8]) {
        let size = self.wire.fragment_size().max(1);
        let count = data.len().div_ceil(size);
        for (index, part) in data.chunks(size).enumerate() {
            let fragment = u8::try_from((count - 1 - index) & 0xff).unwrap_or(0);
            self.push(Kind::Data(fragment), part.to_vec());
        }
    }

    async fn finished(&mut self) -> Option<End> {
        if !self.opened && self.events.is_closed() {
            return Some(End::Local);
        }
        if self.opened && self.last_rx.elapsed() > SILENCE_LIMIT {
            return Some(End::Failed(io::ErrorKind::TimedOut.into()));
        }
        let started = self.closing?;
        let drained = self.send_queue.is_empty() && self.send_buf.is_empty();
        if !drained && started.elapsed() < CLOSE_DRAIN {
            return None;
        }
        if self.opened {
            let seq = self.next_send;
            match self
                .wire
                .session_datagram(meta::CLOSE_REQUEST, self.id, seq, &[])
            {
                Ok(close) => {
                    let _ = self.wire.transmit(&close).await;
                }
                Err(err) => return Some(End::Failed(err)),
            }
        }
        Some(End::Local)
    }

    fn receive_window(&self) -> u16 {
        let used = self.recv_buf.len() + self.ready.len();
        u16::try_from(TREE.saturating_sub(used)).unwrap_or(0)
    }

    fn send_window(&self) -> usize {
        let cwnd = self.cubic.window() as usize;
        cwnd.saturating_sub(self.send_buf.len())
            .min(self.remote_window as usize)
    }

    fn timeout_for(&self, tx_count: u8) -> Duration {
        self.rtt
            .rto()
            .mul_f64(BACK_OFF.powi(i32::from(tx_count)))
            .min(MAX_BACK_OFF)
    }

    fn defer_data(&self) -> bool {
        !self.established
            && self
                .send_queue
                .front()
                .is_some_and(|seg| matches!(seg.kind, Kind::Data(_)))
    }

    async fn emit(&mut self, seq: u32) -> io::Result<()> {
        let ack = (self.next_recv, self.receive_window());
        let Some(seg) = self.send_buf.get(&seq) else {
            return Ok(());
        };
        let datagram = match seg.kind {
            Kind::Open => {
                self.wire
                    .session_datagram(meta::OPEN_REQUEST, self.id, seg.seq, &seg.payload)
            }
            Kind::Data(fragment) => self.wire.data_datagram(
                meta::DATA_C2S,
                self.id,
                seg.seq,
                ack,
                fragment,
                &seg.payload,
            ),
        }?;
        self.wire.transmit(&datagram).await?;
        self.last_tx = Instant::now();
        Ok(())
    }

    async fn output(&mut self) -> Result<(), End> {
        let mut transmissions = 0usize;
        let now = Instant::now();
        if !self.send_buf.is_empty() && now >= self.next_retransmission {
            let (mut loss, mut timeout) = (false, false);
            let mut next = None;
            let seqs: Vec<u32> = self.send_buf.keys().copied().collect();
            for seq in seqs {
                let rto = self.rtt.rto();
                let Some(seg) = self.send_buf.get_mut(&seq) else {
                    continue;
                };
                if seg.tx_count >= TX_LIMIT {
                    return Err(End::Failed(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "too many retransmissions",
                    )));
                }
                let early = seg.ack_count >= EARLY_RETRANSMISSION
                    && seg.tx_count <= EARLY_RETRANSMISSION_LIMIT;
                if early || now.saturating_duration_since(seg.tx_time) >= seg.tx_timeout {
                    if early {
                        self.stats.early += 1;
                        loss = true;
                    } else {
                        self.stats.timeouts += 1;
                        timeout = true;
                    }
                    seg.ack_count = 0;
                    seg.tx_count += 1;
                    seg.tx_time = Instant::now();
                    seg.tx_timeout = rto
                        .mul_f64(BACK_OFF.powi(i32::from(seg.tx_count)))
                        .min(MAX_BACK_OFF);
                    self.emit(seq).await?;
                    transmissions += 1;
                }
                if let Some(seg) = self.send_buf.get(&seq) {
                    let due = seg.tx_time + seg.tx_timeout;
                    next = Some(next.map_or(due, |current: Instant| current.min(due)));
                }
            }
            if let Some(next) = next {
                self.next_retransmission = next;
            }
            if timeout {
                self.cubic.on_timeout();
            } else if loss {
                self.cubic.on_loss();
            }
        }

        while !self.send_queue.is_empty() && self.send_window() > 0 {
            if self.send_buf.len() + 1 >= TREE || self.defer_data() {
                break;
            }
            if transmissions >= self.send_window() {
                break;
            }
            let Some(mut seg) = self.send_queue.pop_front() else {
                break;
            };
            seg.tx_count += 1;
            seg.tx_time = Instant::now();
            seg.tx_timeout = self.timeout_for(seg.tx_count);
            let deadline = seg.tx_time + seg.tx_timeout;
            if self.send_buf.is_empty() {
                self.next_retransmission = deadline.min(seg.tx_time + RETRANSMISSION_CHECK);
            } else if self.next_retransmission > deadline {
                self.next_retransmission = deadline;
            }
            let seq = seg.seq;
            self.send_buf.insert(seq, seg);
            self.stats.sent += 1;
            self.emit(seq).await?;
            transmissions += 1;
        }

        let now = Instant::now();
        let due = self.ack_deadline.is_some_and(|at| now >= at);
        let silent = now.saturating_duration_since(self.last_tx) > self.heartbeat;
        if self.established && (due || silent) {
            self.ack_deadline = None;
            let ack = (self.next_recv, self.receive_window());
            let datagram = self.wire.data_datagram(
                meta::ACK_C2S,
                self.id,
                self.next_send.saturating_sub(1),
                ack,
                0,
                &[],
            )?;
            self.wire.transmit(&datagram).await?;
            self.last_tx = Instant::now();
            self.heartbeat = beat();
        }
        Ok(())
    }

    fn next_wake(&self) -> Instant {
        let now = Instant::now();
        let mut next = now + HEARTBEAT;
        if !self.send_buf.is_empty() {
            next = next.min(self.next_retransmission);
        }
        if self.established {
            if let Some(at) = self.ack_deadline {
                next = next.min(at);
            }
            next = next.min(self.last_tx + self.heartbeat);
        }
        if let Some(started) = self.closing {
            next = next.min(started + CLOSE_DRAIN);
        }
        next = next.min(self.last_rx + SILENCE_LIMIT);
        next.max(now + MIN_OUTPUT)
    }

    fn request_ack(&mut self) {
        if self.ack_deadline.is_none() {
            self.ack_deadline = Some(Instant::now() + ACK_DELAY);
        }
    }

    fn input(&mut self, segment: Inbound) -> Result<(), End> {
        self.last_rx = Instant::now();
        match segment.meta {
            Meta::Session { kind, seq, .. } => match kind {
                meta::OPEN_RESPONSE => {
                    self.accept_segment(seq, segment);
                    self.established = true;
                }
                meta::CLOSE_REQUEST => {
                    let seq = self.next_send;
                    if let Ok(reply) =
                        self.wire
                            .session_datagram(meta::CLOSE_RESPONSE, self.id, seq, &[])
                    {
                        self.reply(reply);
                    }
                    return Err(End::Peer);
                }
                _ => return Err(End::Peer),
            },
            Meta::Data {
                kind,
                seq,
                unack,
                window,
                ..
            } => {
                self.acknowledge(unack, window);
                if kind == meta::ACK_S2C {
                    if let Some(first) = self.send_buf.values_mut().next()
                        && first.seq == unack
                    {
                        first.ack_count = first.ack_count.saturating_add(1);
                    }
                } else {
                    self.accept_segment(seq, segment);
                }
            }
        }
        Ok(())
    }

    fn reply(&self, datagram: Vec<u8>) {
        let wire = self.wire.clone();
        self.wire.tasks.spawn_detached(async move {
            let _ = wire.transmit(&datagram).await;
        });
    }

    fn acknowledge(&mut self, unack: u32, window: u16) {
        while let Some(entry) = self.send_buf.first_entry() {
            if *entry.key() >= unack {
                break;
            }
            let seg = entry.remove();
            self.rtt
                .update(Instant::now().saturating_duration_since(seg.tx_time));
            self.cubic.on_ack();
        }
        self.remote_window = u32::from(window);
    }

    fn accept_segment(&mut self, seq: u32, segment: Inbound) {
        self.request_ack();
        if self.receive_window() == 0 || self.recv_buf.len() >= TREE {
            return;
        }
        self.recv_buf.insert(seq, segment);
        while let Some(entry) = self.recv_buf.first_entry() {
            let at = *entry.key();
            if at > self.next_recv {
                break;
            }
            let segment = entry.remove();
            if at < self.next_recv {
                continue;
            }
            self.next_recv = self.next_recv.wrapping_add(1);
            if let Meta::Data { window, .. } = segment.meta {
                self.remote_window = u32::from(window);
            }
            if !segment.payload.is_empty() {
                self.ready
                    .push_back(Event::Data(Bytes::from(segment.payload)));
            }
        }
        self.request_ack();
    }
}
