use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use concord_common::addr::unmap;
use concord_common::packet::{PacketSession, recv_packet, send_packet};
use concord_common::{Address, PacketBuf, Tasks};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::cipher::PacketCipher;
use super::frame::{self, DataFrame};
use super::meta::{self, META_LEN, Meta, NONCE_LEN, TAG_LEN, invalid};
use super::padding;
use super::pattern::Pattern;
use super::session::Session;
use super::underlay::{Event, Out, Wire};
use crate::util::lock;

pub(super) const PACKET_OVERHEAD: usize = NONCE_LEN + META_LEN + TAG_LEN * 2;
const NON_HEADER: usize = NONCE_LEN + META_LEN + TAG_LEN;
const KEY_LIFE: Duration = Duration::from_secs(60);
const IDLE_BASE: Duration = Duration::from_secs(120);
const TICK: Duration = Duration::from_secs(5);
const OUT_QUEUE: usize = 32;
const INBOUND_QUEUE: usize = 256;
const EVENT_QUEUE: usize = 256;
const MAX_PADDING: usize = 255;

pub(super) struct Inbound {
    pub(super) meta: Meta,
    pub(super) payload: Vec<u8>,
}

struct Handle {
    inbound: mpsc::Sender<Inbound>,
    out: mpsc::Sender<Out>,
}

/// A local socket, or the packet session of a `dialer-proxy` node, as mihomo's
/// `mieruPacketDialer` listens through the node's dialer.
pub(super) enum Carrier {
    Socket(UdpSocket),
    Session(Arc<dyn PacketSession>),
}

impl From<UdpSocket> for Carrier {
    fn from(socket: UdpSocket) -> Self {
        Carrier::Socket(socket)
    }
}

impl Carrier {
    async fn send_to(&self, datagram: &[u8], server: SocketAddr) -> io::Result<()> {
        match self {
            Carrier::Socket(socket) => socket.send_to(datagram, server).await.map(drop),
            Carrier::Session(session) => {
                let mut pkt = PacketBuf::with_headroom(session.headroom());
                pkt.extend_from_slice(datagram);
                send_packet(&**session, &mut pkt, &Address::Socket(server)).await
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        match self {
            Carrier::Socket(socket) => socket
                .recv_from(buf)
                .await
                .map(|(len, from)| (len, Some(from))),
            Carrier::Session(session) => {
                let (pkt, from) = recv_packet(&**session).await?;
                let len = pkt.len().min(buf.len());
                buf.get_mut(..len)
                    .ok_or_else(|| io::Error::other("short buffer"))?
                    .copy_from_slice(pkt.as_slice().get(..len).unwrap_or_default());
                let from = match from {
                    Address::Socket(addr) => Some(addr),
                    Address::Domain(..) => None,
                };
                Ok((len, from))
            }
        }
    }
}

pub(super) struct PacketUnderlay {
    me: Weak<PacketUnderlay>,
    socket: Carrier,
    server: SocketAddr,
    cipher: PacketCipher,
    pattern: Arc<Pattern>,
    user: String,
    mtu: usize,
    sessions: Mutex<HashMap<u32, Handle>>,
    pub(super) die: CancellationToken,
    born: Instant,
    last_used: Mutex<Instant>,
    idle_limit: Duration,
    volume_limit: u64,
    bytes: AtomicU64,
    pub(super) tasks: Tasks,
}

impl PacketUnderlay {
    #[expect(
        clippy::too_many_arguments,
        reason = "the carrier, its credentials, its limits and its owner, each given once"
    )]
    pub(super) fn start(
        socket: impl Into<Carrier>,
        server: SocketAddr,
        key: &[u8; 32],
        user: &str,
        pattern: Arc<Pattern>,
        mtu: usize,
        factor: usize,
        tasks: &Tasks,
    ) -> Arc<PacketUnderlay> {
        let underlay = Arc::new_cyclic(|me| PacketUnderlay {
            me: me.clone(),
            socket: socket.into(),
            server,
            cipher: PacketCipher::new(key, user, pattern.nonce.clone()),
            pattern,
            user: user.to_string(),
            mtu,
            sessions: Mutex::new(HashMap::new()),
            die: tasks.child_token(),
            born: Instant::now(),
            last_used: Mutex::new(Instant::now()),
            idle_limit: IDLE_BASE + Duration::from_secs(rand::rng().random_range(0..61)),
            volume_limit: (512u64 << 20) << factor.min(8),
            bytes: AtomicU64::new(0),
            tasks: tasks.clone(),
        });
        tasks.spawn(read_loop(underlay.clone()));
        underlay
    }

    /// Plaintext bytes one datagram carries in a data segment.
    pub(super) fn fragment_size(&self) -> usize {
        let room = self.mtu.saturating_sub(PACKET_OVERHEAD);
        match self.pattern.low_entropy {
            Some(low) => padding::params(low.mode)
                .map_or(room, |params| room / padding::CHUNK * params.source_bytes),
            None => room,
        }
    }

    pub(super) fn low_entropy(&self) -> bool {
        self.pattern.low_entropy.is_some()
    }

    fn padding_cap(&self, payload: usize, existing: usize, configured: usize) -> usize {
        let room = self.mtu.saturating_sub(payload + PACKET_OVERHEAD);
        let base = if room <= existing {
            0
        } else {
            (room - existing).min(MAX_PADDING)
        };
        base.min(configured)
    }

    pub(super) fn session_datagram(
        &self,
        kind: u8,
        id: u32,
        seq: u32,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let cap = self.padding_cap(payload.len(), 0, self.pattern.max_end);
        let padding = padding::session_padding(cap, PACKET_OVERHEAD + payload.len(), &self.user);
        let mut out = Vec::with_capacity(PACKET_OVERHEAD + payload.len() + padding.len());
        frame::write_session(
            &mut self.cipher.sealer(),
            kind,
            id,
            seq,
            payload,
            &padding,
            &mut out,
        )?;
        Ok(out)
    }

    pub(super) fn data_datagram(
        &self,
        kind: u8,
        id: u32,
        seq: u32,
        ack: (u32, u16),
        fragment: u8,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let low = self.pattern.low_entropy.filter(|_| kind == meta::DATA_C2S);
        let wire_len = match low {
            Some(low) => padding::encoded_len(payload.len(), low.mode)?,
            None => payload.len(),
        };
        let prefix =
            padding::middle_padding(self.padding_cap(wire_len, 0, self.pattern.max_middle));
        let suffix =
            padding::middle_padding(self.padding_cap(wire_len, prefix.len(), self.pattern.max_end));
        let frame = DataFrame {
            kind,
            id,
            seq,
            unack: ack.0,
            window: ack.1,
            fragment,
            prefix: &prefix,
            suffix: &suffix,
            payload,
            low,
        };
        let mut out = Vec::with_capacity(PACKET_OVERHEAD + wire_len + prefix.len() + suffix.len());
        frame::write_data(&mut self.cipher.sealer(), &frame, &mut out)?;
        if low.is_some() && out.len() > self.mtu {
            return Err(invalid("low entropy datagram exceeds the MTU"));
        }
        Ok(out)
    }

    pub(super) async fn transmit(&self, datagram: &[u8]) -> io::Result<()> {
        match self.socket.send_to(datagram, self.server).await {
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                ) => {}
            Err(err) => return Err(err),
        }
        self.bytes
            .fetch_add(datagram.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn remove(&self, id: u32) {
        lock(&self.sessions).remove(&id);
        *lock(&self.last_used) = Instant::now();
    }

    fn route(&self, id: u32, segment: Inbound) -> bool {
        let inbound = lock(&self.sessions)
            .get(&id)
            .map(|handle| handle.inbound.clone());
        match inbound {
            Some(inbound) => {
                let _ = inbound.try_send(segment);
                true
            }
            None => false,
        }
    }

    async fn dispatch(&self, segment: Inbound) -> io::Result<()> {
        match segment.meta {
            Meta::Session { kind, id, .. } => {
                if matches!(
                    kind,
                    meta::OPEN_RESPONSE | meta::CLOSE_REQUEST | meta::CLOSE_RESPONSE
                ) {
                    self.route(id, segment);
                }
            }
            Meta::Data {
                kind, id, unack, ..
            } => {
                if matches!(kind, meta::DATA_S2C | meta::DATA_S2C_LOW | meta::ACK_S2C)
                    && !self.route(id, segment)
                {
                    let close = self.session_datagram(meta::CLOSE_REQUEST, id, unack, &[])?;
                    self.transmit(&close).await?;
                }
            }
        }
        Ok(())
    }

    fn idle_expired(&self) -> bool {
        lock(&self.sessions).is_empty() && lock(&self.last_used).elapsed() > self.idle_limit
    }
}

pub(super) fn parse(cipher: &PacketCipher, raw: &[u8]) -> io::Result<Inbound> {
    if raw.len() < NON_HEADER {
        return Err(invalid("short datagram"));
    }
    let (nonce, rest) = raw.split_at(NONCE_LEN);
    let (sealed, rest) = rest.split_at(META_LEN + TAG_LEN);
    let meta = Meta::decode(&cipher.open(nonce, sealed)?)?;
    let payload = match meta {
        Meta::Session {
            payload_len,
            suffix_len,
            ..
        } => payload(
            cipher,
            nonce,
            rest,
            usize::from(payload_len),
            usize::from(suffix_len),
            None,
        )?,
        Meta::Data {
            kind,
            prefix_len,
            payload_len,
            suffix_len,
            low,
            ..
        } => {
            let rest = rest
                .get(usize::from(prefix_len)..)
                .ok_or_else(|| invalid("padding prefix exceeds the datagram"))?;
            let low = meta::is_low_entropy(kind).then_some(low);
            payload(
                cipher,
                nonce,
                rest,
                usize::from(payload_len),
                usize::from(suffix_len),
                low,
            )?
        }
    };
    Ok(Inbound { meta, payload })
}

fn payload(
    cipher: &PacketCipher,
    nonce: &[u8],
    rest: &[u8],
    len: usize,
    suffix: usize,
    low: Option<meta::LowEntropyMeta>,
) -> io::Result<Vec<u8>> {
    if len == 0 {
        return if rest.len() == suffix {
            Ok(Vec::new())
        } else {
            Err(invalid("padding size does not match"))
        };
    }
    let wire = len + TAG_LEN;
    if rest.len() != wire + suffix {
        return Err(invalid("payload size does not match"));
    }
    let sealed = rest.get(..wire).ok_or_else(|| invalid("short payload"))?;
    let Some(low) = low else {
        return cipher.open(nonce, sealed);
    };
    let extracted = usize::from(low.extracted_len);
    if padding::encoded_len(extracted, low.mode)? != len {
        return Err(invalid("low entropy payload length"));
    }
    let (body, tag) = sealed.split_at(len);
    let mut plain = padding::decode_low(body, extracted, low.mode, low.mask, low.rotation)?;
    plain.extend_from_slice(tag);
    cipher.open(nonce, &plain)
}

impl Wire for PacketUnderlay {
    fn open_session(&self, id: u32) -> io::Result<mpsc::Receiver<Event>> {
        if self.die.is_cancelled() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let me = self
            .me
            .upgrade()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let (events, events_rx) = mpsc::channel(EVENT_QUEUE);
        let (out, out_rx) = mpsc::channel(OUT_QUEUE);
        let (inbound, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let mut sessions = lock(&self.sessions);
        if sessions.contains_key(&id) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        sessions.insert(id, Handle { inbound, out });
        drop(sessions);
        *lock(&self.last_used) = Instant::now();
        self.tasks
            .spawn(Session::new(me, id, events, out_rx, inbound_rx).run());
        Ok(events_rx)
    }

    fn sender(&self, id: u32) -> mpsc::Sender<Out> {
        match lock(&self.sessions).get(&id) {
            Some(handle) => handle.out.clone(),
            None => mpsc::channel(1).0,
        }
    }

    fn queue(&self, id: u32, out: Out) {
        let Some(sender) = lock(&self.sessions)
            .get(&id)
            .map(|handle| handle.out.clone())
        else {
            return;
        };
        if let Err(mpsc::error::TrySendError::Full(out)) = sender.try_send(out) {
            self.tasks.spawn_detached(async move {
                let _ = sender.send(out).await;
            });
        }
    }

    fn forget(&self, _id: u32) {}

    fn is_closed(&self) -> bool {
        self.die.is_cancelled()
    }

    fn close(&self) {
        self.die.cancel();
        lock(&self.sessions).clear();
    }

    fn usable(&self) -> bool {
        if self.is_closed()
            || self.born.elapsed() >= KEY_LIFE
            || self.bytes.load(Ordering::Relaxed) > self.volume_limit
        {
            return false;
        }
        !(lock(&self.sessions).is_empty() && lock(&self.last_used).elapsed() > self.idle_limit)
    }
}

async fn read_loop(underlay: Arc<PacketUnderlay>) {
    let mut buf = vec![0u8; 2048];
    let mut tick = tokio::time::interval(TICK);
    let result: io::Result<()> = async {
        loop {
            tokio::select! {
                _ = underlay.die.cancelled() => return Ok(()),
                _ = tick.tick() => {
                    if underlay.idle_expired() {
                        return Ok(());
                    }
                }
                got = underlay.socket.recv_from(&mut buf) => {
                    let (len, from) = match got {
                        Ok(got) => got,
                        Err(err) if matches!(
                            err.kind(),
                            io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                        ) => continue,
                        Err(err) => return Err(err),
                    };
                    if from.is_some_and(|from| {
                        (unmap(from.ip()), from.port()) != (unmap(underlay.server.ip()), underlay.server.port())
                    }) {
                        continue;
                    }
                    underlay.bytes.fetch_add(len as u64, Ordering::Relaxed);
                    let Some(raw) = buf.get(..len) else { continue };
                    match parse(&underlay.cipher, raw) {
                        Ok(segment) => underlay.dispatch(segment).await?,
                        Err(err) => tracing::trace!(%err, "mieru: dropped a datagram"),
                    }
                }
            }
        }
    }
    .await;
    if let Err(err) = result {
        tracing::debug!(%err, "mieru: udp read failed");
    }
    underlay.close();
}
