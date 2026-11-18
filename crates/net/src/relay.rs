use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io::{self, IoSlice, IoSliceMut};
use std::pin::{Pin, pin};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use concord_common::stream_buffer::{ReadBufferOptions, StreamBuffer};
use concord_common::{Attached, BoxStream, Stream};
use concord_platform::{SEND_TCP_VECTORED, SplicePipe};
use tokio::io::Interest;
use tokio::net::TcpStream;
use tokio::task::coop::poll_proceed;
use tokio::time::{Instant, Sleep, sleep};
use tokio_util::sync::CancellationToken;

// Matches the kernel's UIO_FASTIOV: a bounded batch keeps imported iovecs on its stack.
const TCP_BATCH_BUFFERS: usize = 8;
const ATTACHED_REPORT: Duration = Duration::from_secs(1);

/// Receives every chunk as it is written; the caller adds it to an atomic counter.
/// Upload is the first stream's bytes going to the second.
pub trait Meter: Send + Sync {
    fn on_upload(&self, bytes: u64);
    fn on_download(&self, bytes: u64);
}

#[derive(Debug)]
pub enum RelayEnd {
    Eof,
    Cancelled,
    Error(io::Error),
}

#[derive(Debug)]
pub struct RelayOutcome {
    pub upload: u64,
    pub download: u64,
    pub end: RelayEnd,
}

enum Step {
    Progress,
    Finished,
}

enum Bulk {
    Unused,
    Pipe(SplicePipe),
    Off,
}

enum Moved {
    Some,
    Eof,
    Unavailable,
}

fn splice_unsupported(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied
    )
}

fn poll_vectored<W: Stream + ?Sized>(
    cx: &mut Context<'_>,
    writer: &mut W,
    buffers: &[IoSlice<'_>],
) -> Poll<io::Result<usize>> {
    if SEND_TCP_VECTORED && let Some(socket) = writer.tcp() {
        loop {
            ready!(socket.poll_write_ready(cx))?;
            match socket.try_io(Interest::WRITABLE, || {
                concord_platform::send_tcp_vectored(socket, buffers)
            }) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
    Pin::new(writer).poll_write_vectored(cx, buffers)
}

/// Where a half is between reading its source and shutting down its destination.
enum Phase {
    Reading,
    /// The source ended: what is accepted goes out, then the destination shuts down.
    ReadDone,
    /// Reading failed with bytes accepted: they go out before the error ends the relay.
    ReadFailed(io::Error),
    Finished,
}

struct Half {
    buffer: Option<StreamBuffer>,
    read_queue: VecDeque<StreamBuffer>,
    read_was_full: bool,
    queued: VecDeque<StreamBuffer>,
    phase: Phase,
    remaining: usize,
    total: u64,
    need_flush: bool,
    bulk: Bulk,
}

impl Half {
    fn new() -> Self {
        Half {
            buffer: None,
            read_queue: VecDeque::new(),
            read_was_full: false,
            queued: VecDeque::new(),
            phase: Phase::Reading,
            remaining: 0,
            total: 0,
            need_flush: false,
            bulk: Bulk::Unused,
        }
    }

    fn idle(&self) -> bool {
        self.buffer.is_none()
            && self.read_queue.is_empty()
            && self.queued.is_empty()
            && matches!(self.phase, Phase::Reading)
            && !self.need_flush
    }

    fn read_done(&self) -> bool {
        matches!(self.phase, Phase::ReadDone)
    }

    fn finished(&self) -> bool {
        matches!(self.phase, Phase::Finished)
    }

    fn poll_read_vectored(
        &mut self,
        cx: &mut Context<'_>,
        socket: &tokio::net::TcpStream,
        options: ReadBufferOptions,
    ) -> Poll<io::Result<StreamBuffer>> {
        loop {
            ready!(socket.poll_read_ready(cx))?;
            // Prefetched reads and buffered writes share the same bounded owner budget.
            let slots = TCP_BATCH_BUFFERS
                .checked_sub(self.queued.len())
                .filter(|n| *n > 0)
                .ok_or(io::ErrorKind::InvalidData)?;
            let mut buffers: [StreamBuffer; TCP_BATCH_BUFFERS] = std::array::from_fn(|index| {
                if index < slots {
                    options.take()
                } else {
                    StreamBuffer::default()
                }
            });
            let result = {
                let mut slices = buffers
                    .each_mut()
                    .map(|buffer| IoSliceMut::new(buffer.spare_mut()));
                socket.try_read_vectored(slices.get_mut(..slots).ok_or(io::ErrorKind::InvalidData)?)
            };
            let mut filled = match result {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Poll::Ready(Err(err)),
                Ok(0) => return Poll::Ready(Ok(StreamBuffer::default())),
                Ok(filled) => filled,
            };
            for mut buffer in buffers.into_iter().take(slots) {
                let capacity = buffer.spare_mut().len();
                let take = filled.min(capacity);
                if take > 0 {
                    self.read_was_full = take == capacity;
                    buffer.advance(take)?;
                    self.read_queue.push_back(buffer);
                    filled -= take;
                }
            }
            if filled != 0 {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            return Poll::Ready(
                self.read_queue
                    .pop_front()
                    .ok_or(io::ErrorKind::InvalidData.into()),
            );
        }
    }

    fn drain<W: Stream + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
    ) -> Poll<io::Result<()>> {
        while !self.queued.is_empty() {
            let result = {
                let slices: [IoSlice<'_>; TCP_BATCH_BUFFERS] = std::array::from_fn(|index| {
                    IoSlice::new(self.queued.get(index).map_or(&[], StreamBuffer::as_slice))
                });
                poll_vectored(
                    cx,
                    writer,
                    slices
                        .get(..self.queued.len())
                        .ok_or(io::ErrorKind::InvalidData)?,
                )
            };
            let mut written = ready!(result)?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            while written > 0 {
                let front = self.queued.front_mut().ok_or(io::ErrorKind::InvalidData)?;
                let consumed = front.len().min(written);
                front.consume(consumed)?;
                written -= consumed;
                if front.is_empty() {
                    self.queued.pop_front();
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_bulk(
        &mut self,
        cx: &mut Context<'_>,
        src: &TcpStream,
        dst: &TcpStream,
        meter: &dyn Fn(u64),
    ) -> Poll<io::Result<Moved>> {
        if matches!(self.bulk, Bulk::Unused) {
            self.bulk = match SplicePipe::new() {
                Ok(pipe) => Bulk::Pipe(pipe),
                Err(_) => Bulk::Off,
            };
        }
        let Bulk::Pipe(pipe) = &mut self.bulk else {
            return Poll::Ready(Ok(Moved::Unavailable));
        };
        loop {
            if pipe.queued() > 0 {
                ready!(dst.poll_write_ready(cx))?;
                match dst.try_io(Interest::WRITABLE, || pipe.drain(dst)) {
                    Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Ok(moved) => {
                        self.total += moved as u64;
                        meter(moved as u64);
                        return Poll::Ready(Ok(Moved::Some));
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(err) => return Poll::Ready(Err(err)),
                }
            }
            ready!(src.poll_read_ready(cx))?;
            match src.try_io(Interest::READABLE, || pipe.fill(src)) {
                Ok(0) => {
                    self.phase = Phase::ReadDone;
                    return Poll::Ready(Ok(Moved::Eof));
                }
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) if splice_unsupported(&err) => {
                    self.bulk = Bulk::Off;
                    return Poll::Ready(Ok(Moved::Unavailable));
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }

    /// Sends what was accepted before the read failed, then hands back the error.
    fn poll_read_failed<W: Stream + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
    ) -> Poll<io::Result<Step>> {
        ready!(self.drain(cx, writer))?;
        ready!(Pin::new(&mut *writer).poll_flush(cx))?;
        self.need_flush = false;
        match std::mem::replace(&mut self.phase, Phase::Reading) {
            Phase::ReadFailed(err) => Poll::Ready(Err(err)),
            _ => Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
        }
    }

    fn poll<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        writer: &mut W,
        meter: &dyn Fn(u64),
    ) -> Poll<io::Result<Step>>
    where
        R: Stream + ?Sized,
        W: Stream + ?Sized,
    {
        loop {
            match self.phase {
                Phase::Finished => return Poll::Ready(Ok(Step::Finished)),
                Phase::ReadFailed(_) => return self.poll_read_failed(cx, writer),
                Phase::Reading | Phase::ReadDone => {}
            }
            if self.queued.len() == TCP_BATCH_BUFFERS {
                ready!(self.drain(cx, writer))?;
            }
            if self.buffer.is_none()
                && let Some(buffer) = self.read_queue.pop_front()
            {
                self.remaining = buffer.len();
                self.buffer = Some(buffer);
            }
            let defer_tcp_flush = !self.queued.is_empty()
                && writer.tcp().is_some()
                && reader.tcp().is_none()
                && reader.direct().is_none();
            if self.need_flush
                && self.buffer.is_none()
                && (writer.tcp().is_some() || writer.direct().is_some())
                && !defer_tcp_flush
            {
                ready!(self.drain(cx, writer))?;
                ready!(Pin::new(&mut *writer).poll_flush(cx))?;
                self.need_flush = false;
            }
            if SplicePipe::AVAILABLE
                && self.buffer.is_none()
                && !self.read_done()
                && !matches!(self.bulk, Bulk::Off)
                && let (Some(src), Some(dst)) = (reader.tcp(), writer.tcp())
            {
                match ready!(self.poll_bulk(cx, src, dst, meter))? {
                    Moved::Some => return Poll::Ready(Ok(Step::Progress)),
                    Moved::Eof => continue,
                    Moved::Unavailable => {}
                }
            }
            if self.buffer.is_none() && !self.read_done() {
                let moved = if let Some(socket) = writer.tcp()
                    && let Some(direct) = reader.direct()
                {
                    Some(ready!(direct.poll_send_to(cx, socket))?)
                } else if let Some(socket) = reader.tcp()
                    && let Some(direct) = writer.direct()
                {
                    Some(ready!(direct.poll_recv_from(cx, socket))?)
                } else {
                    None
                };
                match moved {
                    Some(0) => {
                        self.phase = Phase::ReadDone;
                        continue;
                    }
                    Some(n) => {
                        self.total += n as u64;
                        meter(n as u64);
                        return Poll::Ready(Ok(Step::Progress));
                    }
                    None => {}
                }
            }
            if self.buffer.is_some()
                && writer.tcp().is_some()
                && reader.tcp().is_none()
                && reader.direct().is_none()
            {
                // An accepted buffered write does no socket I/O, so it must charge its own budget.
                let budget = ready!(poll_proceed(cx));
                let buffer = self.buffer.as_mut().ok_or(io::ErrorKind::InvalidData)?;
                let written = buffer.len();
                if written != self.remaining {
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                self.queued.push_back(buffer.take_owned());
                self.buffer = None;
                self.remaining = 0;
                self.total += written as u64;
                self.need_flush = true;
                meter(written as u64);
                budget.made_progress();
                return Poll::Ready(Ok(Step::Progress));
            }
            if self.buffer.is_some() && !self.queued.is_empty() {
                ready!(self.drain(cx, writer))?;
            }
            if let Some(buffer) = self.buffer.as_mut() {
                let written = ready!(writer.poll_write_buffer(cx, buffer))?;
                if written == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.remaining = self
                    .remaining
                    .checked_sub(written)
                    .ok_or(io::ErrorKind::InvalidData)?;
                self.total += written as u64;
                self.need_flush = true;
                meter(written as u64);
                if self.remaining == 0 {
                    if !buffer.is_empty() {
                        return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                    }
                    self.buffer = None;
                    return Poll::Ready(Ok(Step::Progress));
                }
                continue;
            }
            if self.read_done() {
                ready!(self.drain(cx, writer))?;
                ready!(Pin::new(&mut *writer).poll_flush(cx))?;
                self.need_flush = false;
                // A peer that is already gone cannot be told, and that is not an error.
                ready!(Pin::new(&mut *writer).poll_shutdown(cx)).ok();
                self.phase = Phase::Finished;
                return Poll::Ready(Ok(Step::Finished));
            }
            let requirements = writer.write_requirements();
            let options = ReadBufferOptions::for_copy(reader.read_requirements(), requirements)?;
            // A full preceding read permits scatter reads; short request/response traffic
            // keeps one owner, and the first header/payload write remains scalar.
            let can_read_vectored = self.read_was_full
                && !writer.needs_handshake()
                && writer.tcp().is_none()
                && writer.direct().is_none()
                && reader.direct().is_none();
            let vectored = can_read_vectored && reader.tcp().is_some();
            let result = if vectored {
                self.poll_read_vectored(
                    cx,
                    reader.tcp().ok_or(io::ErrorKind::InvalidData)?,
                    options,
                )
            } else {
                reader.poll_read_buffer(cx, options)
            };
            match result {
                Poll::Pending => {
                    if self.need_flush {
                        ready!(self.drain(cx, writer))?;
                        ready!(Pin::new(&mut *writer).poll_flush(cx))?;
                        self.need_flush = false;
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    if self.queued.is_empty() && !self.need_flush {
                        return Poll::Ready(Err(err));
                    }
                    self.phase = Phase::ReadFailed(err);
                }
                Poll::Ready(Ok(buffer)) if buffer.is_empty() => self.phase = Phase::ReadDone,
                Poll::Ready(Ok(buffer)) => {
                    if !vectored {
                        self.read_was_full = buffer.tailroom() == requirements.rear;
                    }
                    self.remaining = buffer.len();
                    self.buffer = Some(buffer);
                }
            }
        }
    }
}

enum Attach {
    Taken(Box<dyn Attached>, bool),
    NotNow,
    Never,
}

/// Hands the bare socket on one side to the user-space stack on the other; the flag says
/// whether the stack is `a`.
fn attach(a: &mut Option<BoxStream>, b: &mut Option<BoxStream>) -> Attach {
    let (stack, original, stack_first) = if b.as_deref().and_then(Stream::tcp).is_some() {
        (a, b, true)
    } else if a.as_deref().and_then(Stream::tcp).is_some() {
        (b, a, false)
    } else {
        return Attach::NotNow;
    };
    let Some(stack) = stack.as_deref_mut() else {
        return Attach::NotNow;
    };
    let Some(direct) = stack.direct() else {
        return Attach::NotNow;
    };
    let Some(stream) = original.take() else {
        return Attach::NotNow;
    };
    let socket = match stream.into_tcp() {
        Ok(socket) => socket,
        Err(stream) => {
            *original = Some(stream);
            return Attach::Never;
        }
    };
    let copy = match duplicate(socket.stream()) {
        Ok(copy) => copy,
        Err(_) => {
            *original = Some(Box::new(socket));
            return Attach::Never;
        }
    };
    let mut copy = Some(socket.share_guard(copy));
    if let Some(handle) = direct.attach_owned(&mut copy) {
        debug_assert!(copy.is_none(), "accepted attachments take the socket");
        return Attach::Taken(handle, stack_first);
    }
    *original = Some(Box::new(socket));
    Attach::Never
}

fn duplicate(socket: &tokio::net::TcpStream) -> io::Result<tokio::net::TcpStream> {
    let copy: std::net::TcpStream = socket2::SockRef::from(socket).try_clone()?.into();
    copy.set_nonblocking(true)?;
    tokio::net::TcpStream::from_std(copy)
}

struct Handover {
    handle: Box<dyn Attached>,
    stack_first: bool,
    /// Upload and download the copy path moved before the stack took the socket.
    base: (u64, u64),
}

/// What an attached connection moved since the last report, as upload and download.
fn report(handover: &Handover, up: &mut Half, down: &mut Half, meter: &dyn Meter) -> bool {
    let (to_socket, from_socket) = handover.handle.moved();
    let (moved_up, moved_down) = if handover.stack_first {
        (to_socket, from_socket)
    } else {
        (from_socket, to_socket)
    };
    let (upload, download) = (handover.base.0 + moved_up, handover.base.1 + moved_down);
    let (new_up, new_down) = (
        upload.saturating_sub(up.total),
        download.saturating_sub(down.total),
    );
    if new_up > 0 {
        meter.on_upload(new_up);
    }
    if new_down > 0 {
        meter.on_download(new_down);
    }
    up.total = upload;
    down.total = download;
    new_up > 0 || new_down > 0
}

/// Copies both ways until both sides have closed. When one side reaches EOF its
/// write half is shut down on the other stream, and the other direction runs until its own EOF.
pub async fn relay(
    a: BoxStream,
    b: BoxStream,
    meter: &dyn Meter,
    cancel: &CancellationToken,
) -> RelayOutcome {
    let (mut a, mut b) = (Some(a), Some(b));
    let (mut up, mut down) = (Half::new(), Half::new());
    let mut cancelled = pin!(cancel.cancelled());
    let on_upload = |bytes| meter.on_upload(bytes);
    let on_download = |bytes| meter.on_download(bytes);
    let mut attached: Option<Handover> = None;
    let mut attach_off = false;
    let mut ticker: Option<Pin<Box<Sleep>>> = None;

    let end = poll_fn(|cx| {
        if cancelled.as_mut().poll(cx).is_ready() {
            if let Some(handover) = attached.as_ref() {
                report(handover, &mut up, &mut down, meter);
            }
            return Poll::Ready(RelayEnd::Cancelled);
        }
        if attached.is_none() && !attach_off && up.idle() && down.idle() {
            match attach(&mut a, &mut b) {
                Attach::Taken(handle, stack_first) => {
                    attached = Some(Handover {
                        handle,
                        stack_first,
                        base: (up.total, down.total),
                    });
                }
                Attach::NotNow => {}
                Attach::Never => attach_off = true,
            }
        }
        if let Some(handover) = attached.as_mut() {
            let done = handover.handle.poll_done(cx);
            report(handover, &mut up, &mut down, meter);
            match done {
                Poll::Ready(Ok(())) => return Poll::Ready(RelayEnd::Eof),
                Poll::Ready(Err(err)) => return Poll::Ready(RelayEnd::Error(err)),
                Poll::Pending => {}
            }
            let tick = ticker.get_or_insert_with(|| Box::pin(sleep(ATTACHED_REPORT)));
            while tick.as_mut().poll(cx).is_ready() {
                tick.as_mut().reset(Instant::now() + ATTACHED_REPORT);
            }
            return Poll::Pending;
        }
        let a = a.as_deref_mut().expect("copy retains its first stream");
        let b = b.as_deref_mut().expect("copy retains its second stream");
        // A socket on either side takes a unit of the task's budget on every ready poll, so
        // the relay yields where tokio does. Only legs that never touch one charge here, as
        // `tokio::io::copy` would: a deferred wake, unlike `wake_by_ref`, does not wake an
        // idle worker.
        let charges_itself = a.tcp().is_some() || b.tcp().is_some();
        loop {
            let budget = if charges_itself {
                None
            } else if let Poll::Ready(budget) = poll_proceed(cx) {
                Some(budget)
            } else {
                return Poll::Pending;
            };
            let mut progressed = false;
            if !up.finished() {
                match up.poll(cx, &mut *a, &mut *b, &on_upload) {
                    Poll::Ready(Err(err)) => return Poll::Ready(RelayEnd::Error(err)),
                    Poll::Ready(Ok(Step::Progress)) => progressed = true,
                    _ => {}
                }
            }
            if !down.finished() {
                match down.poll(cx, &mut *b, &mut *a, &on_download) {
                    Poll::Ready(Err(err)) => return Poll::Ready(RelayEnd::Error(err)),
                    Poll::Ready(Ok(Step::Progress)) => progressed = true,
                    _ => {}
                }
            }
            if up.finished() && down.finished() {
                return Poll::Ready(RelayEnd::Eof);
            }
            if !progressed {
                break;
            }
            if let Some(budget) = budget {
                budget.made_progress();
            }
        }
        Poll::Pending
    })
    .await;

    RelayOutcome {
        upload: up.total,
        download: down.total,
        end,
    }
}

#[cfg(test)]
mod tests;
