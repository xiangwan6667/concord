use crate::anytls::padding::{Padding, Size};
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker, ready};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use concord_common::{BoxRead, BoxWrite, DialCx, DialEnv, Initiator, Stream, split_with_lock};
use futures_util::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::pool::{IdleLane, Pool};
use super::scan::RecordScan;
use super::transport::LaneIo;
use crate::node::Link;

struct Replay {
    link: Arc<Link>,
    token: [u8; 32],
    env: DialEnv,
    open: Vec<u8>,
    history: Vec<u8>,
}

type Reconnecting = Pin<Box<dyn Future<Output = io::Result<IdleLane>> + Send>>;

#[derive(Default)]
struct IoWakers {
    read: AtomicWaker,
    write: AtomicWaker,
}

impl Wake for IoWakers {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.read.wake();
        self.write.wake();
    }
}

pub(super) fn frame(out: &mut Vec<u8>, kind: u8, data: &[u8]) -> io::Result<()> {
    let len = u16::try_from(data.len()).map_err(|_| io::Error::other("miu frame too large"))?;
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

pub(super) struct MiuStream {
    inner: Option<LaneIo>,
    pool: Arc<Pool>,
    generation: u64,
    incoming: BytesMut,
    outgoing: Vec<u8>,
    sent: usize,
    record_ends: VecDeque<usize>,
    packet: u32,
    current: Option<(u8, usize)>,
    read_end: bool,
    write_end: bool,
    failed: bool,
    peer_idle: Option<Duration>,
    peer_raw: bool,
    raw_remaining: usize,
    raw_outgoing: Vec<u8>,
    raw_sent: usize,
    raw_write: bool,
    inner_tls13: bool,
    up_scan: RecordScan,
    down_scan: RecordScan,
    replay: Option<Replay>,
    reconnecting: Option<Reconnecting>,
    wakers: Arc<IoWakers>,
    recycling: bool,
    open_pending: bool,
    open_wait: Option<Pin<Box<tokio::time::Sleep>>>,
    allow_raw: bool,
}

impl MiuStream {
    pub(super) fn new(lane: IdleLane, pool: Arc<Pool>, generation: u64) -> Self {
        Self {
            inner: Some(lane.io),
            pool,
            generation,
            incoming: BytesMut::new(),
            outgoing: Vec::new(),
            sent: 0,
            record_ends: VecDeque::new(),
            packet: 1,
            current: None,
            read_end: false,
            write_end: false,
            failed: false,
            peer_idle: lane.peer_idle,
            peer_raw: lane.peer_raw,
            raw_remaining: 0,
            raw_outgoing: Vec::new(),
            raw_sent: 0,
            raw_write: false,
            inner_tls13: false,
            up_scan: RecordScan::default(),
            down_scan: RecordScan::default(),
            replay: None,
            reconnecting: None,
            wakers: Arc::default(),
            recycling: false,
            open_pending: false,
            open_wait: None,
            allow_raw: true,
        }
    }

    pub(super) fn with_open(mut self, open: Vec<u8>, udp: bool) -> Self {
        self.outgoing = open;
        self.open_pending = true;
        self.open_wait = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
        self.allow_raw = !udp;
        self
    }

    pub(super) fn replay_pooled(
        mut self,
        link: Arc<Link>,
        token: [u8; 32],
        env: DialEnv,
        open: Vec<u8>,
    ) -> Self {
        self.replay = Some(Replay {
            link,
            token,
            env,
            open,
            history: Vec::new(),
        });
        self
    }

    fn finish_open(&mut self) {
        if !self.open_pending {
            return;
        }
        self.open_pending = false;
        self.open_wait = None;
        self.wakers.wake_by_ref();
    }

    fn begin_replay(&mut self) -> bool {
        let Some(replay) = self.replay.take() else {
            return false;
        };
        self.inner.take();
        self.generation = self.pool.clear();
        self.incoming.clear();
        self.outgoing.clear();
        self.record_ends.clear();
        self.sent = 0;
        self.current = None;
        self.failed = false;
        self.peer_raw = false;
        self.peer_idle = None;
        self.packet = 2;
        self.up_scan = RecordScan::default();
        self.down_scan = RecordScan::default();
        self.inner_tls13 = false;
        self.raw_write = false;
        self.raw_outgoing.clear();
        self.raw_sent = 0;
        let pool = self.pool.clone();
        let generation = self.generation;
        let end = self.write_end;
        self.reconnecting = Some(Box::pin(async move {
            let timeout = Duration::from_secs(10);
            tokio::time::timeout(timeout, async move {
                let cx = DialCx::new(
                    &replay.env,
                    Initiator::Proxy,
                    Some(tokio::time::Instant::now() + timeout),
                );
                let padding = pool.padding.load_full();
                let lane = super::dial_lane(&replay.link, &replay.token, &padding, &cx).await?;
                let mut stream = Self::new(lane, pool, generation);
                stream.recycling = true;
                stream.outgoing = replay.open;
                for data in replay.history.chunks(16000) {
                    frame(&mut stream.outgoing, 5, data)?;
                }
                stream.shape()?;
                if end {
                    frame(&mut stream.outgoing, 7, &[])?;
                }
                stream.flush().await?;
                let io = stream
                    .inner
                    .take()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
                Ok(IdleLane::reused(io, None, false))
            })
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        }));
        true
    }

    fn poll_reconnect(&mut self) -> Poll<io::Result<()>> {
        let Some(reconnecting) = self.reconnecting.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let waker = Waker::from(self.wakers.clone());
        let result = ready!(reconnecting.as_mut().poll(&mut Context::from_waker(&waker)));
        self.reconnecting = None;
        self.wakers.wake_by_ref();
        match result {
            Ok(lane) => {
                self.inner = Some(lane.io);
                Poll::Ready(Ok(()))
            }
            Err(error) => {
                self.failed = true;
                Poll::Ready(Err(error))
            }
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            ready!(self.poll_reconnect())?;
            match self.drain_current(cx) {
                Poll::Ready(Err(_)) if self.begin_replay() => {}
                result => return result,
            }
        }
    }

    fn drain_current(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(data) = self.outgoing.get(self.sent..).filter(|s| !s.is_empty()) {
            let io = self
                .inner
                .as_mut()
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
            let written = ready!(
                Pin::new(io).poll_write(
                    cx,
                    data.get(
                        ..self
                            .record_ends
                            .front()
                            .copied()
                            .unwrap_or(self.outgoing.len())
                            - self.sent
                    )
                    .unwrap_or_default()
                )
            );
            match written {
                Ok(0) => {
                    self.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(n) => {
                    self.sent += n;
                    if self.record_ends.front() == Some(&self.sent) {
                        self.record_ends.pop_front();
                    }
                }
                Err(err) => {
                    self.failed = true;
                    return Poll::Ready(Err(err));
                }
            }
        }
        self.outgoing.clear();
        self.sent = 0;
        if !self.raw_outgoing.is_empty() {
            let io = self
                .inner
                .as_mut()
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
            if let Err(error) = ready!(Pin::new(&mut *io).poll_flush(cx)) {
                self.failed = true;
                return Poll::Ready(Err(error));
            }
            while let Some(data) = self
                .raw_outgoing
                .get(self.raw_sent..)
                .filter(|s| !s.is_empty())
            {
                match ready!(Pin::new(io.raw()?).poll_write(cx, data)) {
                    Ok(0) => {
                        self.failed = true;
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    Ok(count) => self.raw_sent += count,
                    Err(error) => {
                        self.failed = true;
                        return Poll::Ready(Err(error));
                    }
                }
            }
            self.raw_outgoing.clear();
            self.raw_sent = 0;
        }
        Poll::Ready(Ok(()))
    }

    fn read_raw(&mut self, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let count = self.raw_remaining.min(output.remaining());
        let mut read = ReadBuf::new(output.initialize_unfilled_to(count));
        let io = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        if let Err(error) = ready!(Pin::new(io.raw()?).poll_read(cx, &mut read)) {
            self.failed = true;
            return Poll::Ready(Err(error));
        }
        let count = read.filled().len();
        if count == 0 {
            self.failed = true;
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        output.advance(count);
        self.raw_remaining -= count;
        Poll::Ready(Ok(()))
    }

    fn shape(&mut self) -> io::Result<()> {
        let padding = self.pool.padding.load();
        let packet = self.packet;
        self.packet = self.packet.saturating_add(1);
        if packet >= padding.stop {
            return Ok(());
        }
        let data = std::mem::take(&mut self.outgoing);
        let mut position = 0;
        for item in padding.sizes(packet) {
            let target = match item {
                Size::Check if position == data.len() => break,
                Size::Check => continue,
                Size::Bytes(size) if size > 3 && size < 8192 => size,
                Size::Bytes(_) => break,
            };
            let count = (data.len() - position).min(target);
            self.outgoing
                .extend_from_slice(data.get(position..position + count).unwrap_or_default());
            position += count;
            if target >= count + 3 {
                frame(&mut self.outgoing, 0, &vec![0; target - count - 3])?;
            }
            if self.record_ends.back() != Some(&self.outgoing.len()) && !self.outgoing.is_empty() {
                self.record_ends.push_back(self.outgoing.len());
            }
        }
        self.outgoing
            .extend_from_slice(data.get(position..).unwrap_or_default());
        Ok(())
    }

    fn fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut storage = [0; 16 * 1024];
        let mut buf = ReadBuf::new(&mut storage);
        let io = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        if let Err(err) = ready!(Pin::new(io).poll_read(cx, &mut buf)) {
            self.failed = true;
            return Poll::Ready(Err(err));
        }
        if buf.filled().is_empty() {
            self.failed = true;
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        self.incoming.extend_from_slice(buf.filled());
        Poll::Ready(Ok(()))
    }

    fn control(&mut self, kind: u8, size: usize) -> io::Result<()> {
        let body = self.incoming.split_to(size);
        match kind {
            0 => Ok(()),
            3 => {
                if let Some(padding) = Padding::parse(&body) {
                    self.pool.padding.store(Arc::new(padding));
                }
                Ok(())
            }
            2 => {
                let settings = std::str::from_utf8(&body).map_err(io::Error::other)?;
                let version = settings.lines().find_map(|line| line.strip_prefix("v="));
                if version != Some("2") {
                    return Err(io::Error::other("unsupported miu version"));
                }
                self.peer_raw = settings.lines().any(|line| line.trim() == "raw=1");
                self.peer_idle = settings.lines().find_map(|line| {
                    line.strip_prefix("idle=")
                        .and_then(|value| value.parse::<u64>().ok())
                        .map(Duration::from_secs)
                });
                Ok(())
            }
            6 if size == 4 => {
                if !self.allow_raw
                    || !self.incoming.is_empty()
                    || !self.inner.as_mut().is_some_and(LaneIo::at_raw_boundary)
                {
                    return Err(io::Error::other(
                        "miu: RAW is not at an outer TLS record boundary",
                    ));
                }
                let length: [u8; 4] = body
                    .as_ref()
                    .try_into()
                    .map_err(|_| io::Error::other("miu: bad RAW length"))?;
                self.raw_remaining = u32::from_be_bytes(length) as usize;
                Ok(())
            }
            7 if size == 0 => {
                self.read_end = true;
                Ok(())
            }
            _ => Err(io::Error::other("unexpected miu frame")),
        }
    }
}

impl MiuStream {
    fn poll_payload(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self;
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while !this.read_end {
            if this.raw_remaining > 0 {
                return this.read_raw(cx, output);
            }
            if this.current.is_none() {
                while this.incoming.len() < 3 {
                    ready!(this.fill(cx))?;
                }
                let mut header = this.incoming.split_to(3);
                let kind = header.get_u8();
                let size = usize::from(header.get_u16());
                if matches!(kind, 5..=7) {
                    this.replay = None;
                }
                this.current = Some((kind, size));
            }
            let (kind, size) = this.current.unwrap_or((0, 0));
            if kind == 5 && size > 0 {
                if this.incoming.is_empty() {
                    ready!(this.fill(cx))?;
                }
                let count = size.min(this.incoming.len()).min(output.remaining());
                let data = this.incoming.split_to(count);
                if this.allow_raw {
                    this.down_scan.feed(&data, &mut this.inner_tls13);
                }
                output.put_slice(&data);
                this.current = if count == size {
                    None
                } else {
                    Some((kind, size - count))
                };
                return Poll::Ready(Ok(()));
            }
            if kind == 5 {
                this.current = None;
                continue;
            }
            while this.incoming.len() < size {
                ready!(this.fill(cx))?;
            }
            if let Err(err) = this.control(kind, size) {
                this.failed = true;
                return Poll::Ready(Err(err));
            }
            this.current = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for MiuStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.wakers.read.register(cx.waker());
        if this.open_pending {
            if let Some(wait) = &mut this.open_wait {
                ready!(wait.as_mut().poll(cx));
                this.open_wait = None;
                this.shape()?;
            }
            ready!(this.drain(cx))?;
            this.finish_open();
            this.wakers.read.register(cx.waker());
        }
        loop {
            ready!(this.poll_reconnect())?;
            match this.poll_payload(cx, output) {
                Poll::Ready(Err(_)) if this.begin_replay() => {}
                result => return result,
            }
        }
    }
}

impl AsyncWrite for MiuStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.wakers.write.register(cx.waker());
        if this.write_end {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.open_pending && this.open_wait.is_none() {
            ready!(this.drain(cx))?;
            this.finish_open();
            this.wakers.write.register(cx.waker());
        }
        if !this.open_pending {
            ready!(this.drain(cx))?;
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let raw = this.raw_write && data.len() >= 4096;
        let count = data.len().min(if raw { 1 << 20 } else { 32000 });
        let data = data.get(..count).unwrap_or_default();
        if let Some(replay) = &mut this.replay {
            if replay.history.len() + count <= 64 << 10 {
                replay.history.extend_from_slice(data);
            } else {
                this.replay = None;
            }
        }
        if raw {
            frame(&mut this.outgoing, 6, &(count as u32).to_be_bytes())?;
            this.raw_outgoing.extend_from_slice(data);
        } else {
            for chunk in data.chunks(16000) {
                frame(&mut this.outgoing, 5, chunk)?;
            }
            if !this.raw_write {
                this.shape()?;
                this.raw_write = this.allow_raw
                    && this.up_scan.feed(data, &mut this.inner_tls13)
                    && this.peer_raw;
            }
        }
        this.finish_open();
        this.wakers.write.register(cx.waker());
        if let Poll::Ready(Err(err)) = this.drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.wakers.write.register(cx.waker());
        if this.open_pending {
            if this.open_wait.take().is_some() {
                this.shape()?;
            }
            ready!(this.drain(cx))?;
            this.finish_open();
            this.wakers.write.register(cx.waker());
        }
        loop {
            ready!(this.drain(cx))?;
            let io = this
                .inner
                .as_mut()
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
            match ready!(Pin::new(io).poll_flush(cx)) {
                Err(_) if this.begin_replay() => {}
                result => {
                    this.failed |= result.is_err();
                    return Poll::Ready(result);
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.finish_open();
        self.wakers.write.register(cx.waker());
        ready!(self.drain(cx))?;
        if !self.write_end {
            frame(&mut self.outgoing, 7, &[])?;
            self.write_end = true;
        }
        self.poll_flush(cx)
    }
}

impl Stream for MiuStream {
    concord_common::stream_policy!(inner;
        own: into_split;
        default: peer_addr, read_requirements, write_requirements, poll_read_buffer,
            poll_write_buffer, raw_socket, tcp, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        split_with_lock(*self)
    }
}

impl Drop for MiuStream {
    fn drop(&mut self) {
        if self.recycling {
            return;
        }
        if self.open_pending
            && self.open_wait.is_some()
            && let Some(io) = self.inner.take()
        {
            self.pool.put(
                self.generation,
                IdleLane::reused(io, self.peer_idle, self.peer_raw),
            );
            return;
        }
        if self.read_end
            && self.write_end
            && !self.failed
            && self.outgoing.is_empty()
            && self.incoming.is_empty()
            && self.raw_remaining == 0
            && self.raw_outgoing.is_empty()
            && let Some(io) = self.inner.take()
        {
            self.pool.put(
                self.generation,
                IdleLane::reused(io, self.peer_idle, self.peer_raw),
            );
            return;
        }
        let Some(io) = self.inner.take().filter(|_| !self.failed) else {
            return;
        };
        let mut cleanup = Self::new(
            IdleLane::reused(io, self.peer_idle, self.peer_raw),
            self.pool.clone(),
            self.generation,
        );
        cleanup.recycling = true;
        cleanup.incoming = std::mem::take(&mut self.incoming);
        cleanup.current = self.current.take();
        cleanup.raw_remaining = self.raw_remaining;
        cleanup.outgoing = std::mem::take(&mut self.outgoing);
        cleanup.sent = self.sent;
        cleanup.record_ends = std::mem::take(&mut self.record_ends);
        cleanup.raw_outgoing = std::mem::take(&mut self.raw_outgoing);
        cleanup.raw_sent = self.raw_sent;
        cleanup.read_end = self.read_end;
        cleanup.allow_raw = self.allow_raw;
        let write_end = self.write_end;
        self.pool.tasks.spawn_detached(async move {
            let clean = tokio::time::timeout(Duration::from_secs(3), async {
                cleanup.flush().await?;
                if !cleanup.read_end || !write_end {
                    let kind = if cleanup.read_end { 7 } else { 8 };
                    frame(&mut cleanup.outgoing, kind, &[])?;
                    cleanup.flush().await?;
                }
                let mut discard = [0; 32 * 1024];
                while cleanup.read(&mut discard).await? != 0 {}
                Ok::<_, io::Error>(())
            })
            .await;
            if matches!(clean, Ok(Ok(())))
                && cleanup.incoming.is_empty()
                && let Some(io) = cleanup.inner.take()
            {
                cleanup.pool.put(
                    cleanup.generation,
                    IdleLane::reused(io, cleanup.peer_idle, cleanup.peer_raw),
                );
            }
        });
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
