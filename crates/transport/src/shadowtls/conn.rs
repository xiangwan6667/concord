use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use aws_lc_rs::hmac;
use concord_common::BoxStream;
use concord_common::layered::{Layered, ReadLayer, WriteLayer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::frames::{ALERT, APPLICATION_DATA, FrameReader, HEADER, MAX_PLAINTEXT};
use crate::http1::invalid;
use crate::outgoing::Outgoing;

pub(super) const HMAC_SIZE: usize = 4;
const HMAC_HEADER: usize = HEADER + HMAC_SIZE;
const ALERT_RECORD: usize = 31;
const SHA1_LEN: usize = 20;

/// A running HMAC-SHA1 whose digest can be read without ending it, as Go's `hash.Sum` is.
#[derive(Clone)]
pub(super) struct HmacSha1(hmac::Context);

impl HmacSha1 {
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn sum(&self) -> [u8; SHA1_LEN] {
        let mut out = [0u8; SHA1_LEN];
        let tag = self.0.clone().sign();
        for (out, byte) in out.iter_mut().zip(tag.as_ref()) {
            *out = *byte;
        }
        out
    }

    fn tag(&self) -> [u8; HMAC_SIZE] {
        let mut out = [0u8; HMAC_SIZE];
        for (out, byte) in out.iter_mut().zip(self.sum()) {
            *out = byte;
        }
        out
    }
}

pub(super) fn new_hmac(key: &[u8]) -> HmacSha1 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    HmacSha1(hmac::Context::with_key(&key))
}

fn record_header(len: usize) -> [u8; HEADER] {
    let [hi, lo] = u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes();
    [APPLICATION_DATA, 3, 3, hi, lo]
}

struct V2Read {
    head: [u8; HEADER],
    head_have: usize,
    remaining: usize,
}

struct V2Write {
    prefix: Option<[u8; 8]>,
    out: Outgoing,
}

pub(super) fn v2_conn(inner: BoxStream, prefix: [u8; 8]) -> BoxStream {
    let read = V2Read {
        head: [0; HEADER],
        head_have: 0,
        remaining: 0,
    };
    let write = V2Write {
        prefix: Some(prefix),
        out: Outgoing::new(),
    };
    Box::new(Layered::new(inner, read, write))
}

impl ReadLayer for V2Read {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.remaining > 0 {
                let take = self.remaining.min(buf.remaining());
                if take == 0 {
                    return Poll::Ready(Ok(()));
                }
                let target = buf.initialize_unfilled_to(take);
                let mut window = ReadBuf::new(target);
                ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                let got = window.filled().len();
                if got == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                buf.advance(got);
                self.remaining -= got;
                return Poll::Ready(Ok(()));
            }
            let Some(window) = self.head.get_mut(self.head_have..) else {
                return Poll::Ready(Err(invalid("shadow-tls: header window")));
            };
            let mut window = ReadBuf::new(window);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
            let got = window.filled().len();
            if got == 0 {
                if self.head_have == 0 {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.head_have += got;
            if self.head_have < HEADER {
                continue;
            }
            self.head_have = 0;
            let [kind, _, _, hi, lo] = self.head;
            if kind != APPLICATION_DATA {
                return Poll::Ready(Err(invalid(format!(
                    "shadow-tls: unexpected TLS record type: {kind}"
                ))));
            }
            self.remaining = usize::from(u16::from_be_bytes([hi, lo]));
        }
    }
}

impl WriteLayer for V2Write {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let prefix = self.prefix;
        let max = MAX_PLAINTEXT - prefix.map_or(0, |p| p.len());
        let written = ready!(self.out.poll_write_record(io, cx, data, max, |out, chunk| {
            let prefix_len = prefix.map_or(0, |p| p.len());
            out.extend_from_slice(&record_header(prefix_len + chunk.len()));
            if let Some(prefix) = prefix {
                out.extend_from_slice(&prefix);
            }
            out.extend_from_slice(chunk);
        }))?;
        if written > 0 {
            self.prefix = None;
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.out.poll_drain(io, cx))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.out.poll_drain(io, cx))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

struct V3Read {
    verify: HmacSha1,
    ignore: Option<HmacSha1>,
    frames: FrameReader,
    pending: Vec<u8>,
    pos: usize,
    alert: Arc<AtomicBool>,
}

/// The read half cannot write, so a protocol violation raises `alert` and the write half
/// queues the ALERT record on its next call.
struct V3Write {
    add: HmacSha1,
    out: Outgoing,
    alert: Arc<AtomicBool>,
}

pub(super) fn v3_conn(
    inner: BoxStream,
    add: HmacSha1,
    verify: HmacSha1,
    ignore: Option<HmacSha1>,
) -> BoxStream {
    let alert = Arc::new(AtomicBool::new(false));
    let read = V3Read {
        verify,
        ignore,
        frames: FrameReader::new(),
        pending: Vec::new(),
        pos: 0,
        alert: Arc::clone(&alert),
    };
    let write = V3Write {
        add,
        out: Outgoing::new(),
        alert,
    };
    Box::new(Layered::new(inner, read, write))
}

impl V3Write {
    fn queue_alert_if_raised(&mut self) {
        if !self.alert.swap(false, Ordering::Acquire) {
            return;
        }
        let mut record = [0u8; ALERT_RECORD];
        rand::Rng::fill(&mut rand::rng(), &mut record);
        let [hi, lo] = u16::try_from(ALERT_RECORD - HEADER)
            .unwrap_or_default()
            .to_be_bytes();
        record[..HEADER].copy_from_slice(&[ALERT, 3, 3, hi, lo]);
        self.out.queue_raw(&record);
    }
}

fn verify_record(frame: &[u8], mac: &mut HmacSha1, update: bool) -> bool {
    let (Some(head), Some(payload)) = (frame.get(..HMAC_HEADER), frame.get(HMAC_HEADER..)) else {
        return false;
    };
    if head.first() != Some(&APPLICATION_DATA) || head.get(1) != Some(&3) || head.get(2) != Some(&3)
    {
        return false;
    }
    mac.update(payload);
    let expected = mac.tag();
    if update {
        mac.update(&expected);
    }
    head.get(HEADER..) == Some(expected.as_slice())
}

impl ReadLayer for V3Read {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(rest) = self.pending.get(self.pos..).filter(|rest| !rest.is_empty()) {
                let take = rest.len().min(buf.remaining());
                if let Some(chunk) = rest.get(..take) {
                    buf.put_slice(chunk);
                }
                self.pos += take;
                return Poll::Ready(Ok(()));
            }
            let frame = match ready!(self.frames.poll_frame(io, cx)) {
                Ok(Some(frame)) => frame,
                Ok(None) => return Poll::Ready(Ok(())),
                Err(err) => return Poll::Ready(Err(err)),
            };
            match frame.first().copied() {
                Some(ALERT) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "shadow-tls: remote alert",
                    )));
                }
                Some(APPLICATION_DATA) => {
                    if let Some(ignore) = self.ignore.as_mut() {
                        if verify_record(&frame, ignore, false) {
                            continue;
                        }
                        self.ignore = None;
                    }
                    if !verify_record(&frame, &mut self.verify, true) {
                        self.alert.store(true, Ordering::Release);
                        return Poll::Ready(Err(invalid(
                            "shadow-tls: application data verification failed",
                        )));
                    }
                    self.pending = frame;
                    self.pos = HMAC_HEADER;
                }
                other => {
                    self.alert.store(true, Ordering::Release);
                    return Poll::Ready(Err(invalid(format!(
                        "shadow-tls: unexpected TLS record type: {}",
                        other.unwrap_or_default()
                    ))));
                }
            }
        }
    }
}

impl WriteLayer for V3Write {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.queue_alert_if_raised();
        let add = &mut self.add;
        self.out
            .poll_write_record(io, cx, data, MAX_PLAINTEXT, |out, chunk| {
                out.extend_from_slice(&record_header(HMAC_SIZE + chunk.len()));
                add.update(chunk);
                let digest = add.tag();
                add.update(&digest);
                out.extend_from_slice(&digest);
                out.extend_from_slice(chunk);
            })
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.queue_alert_if_raised();
        ready!(self.out.poll_drain(io, cx))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.queue_alert_if_raised();
        ready!(self.out.poll_drain(io, cx))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn v2_halves_move_data_both_ways_and_shutdown_keeps_reading() {
        let (near, far) = duplex(8192);
        let (mut read, mut write) = v2_conn(Box::new(near), [7; 8]).into_split();
        let (mut far_read, mut far_write) = tokio::io::split(far);
        let writer = tokio::spawn(async move {
            write.write_all(b"hi").await.unwrap();
            write.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        let mut sent = Vec::new();
        far_read.read_to_end(&mut sent).await.unwrap();
        let mut want = vec![APPLICATION_DATA, 3, 3, 0, 10];
        want.extend_from_slice(&[7; 8]);
        want.extend_from_slice(b"hi");
        assert_eq!(sent, want);
        writer.await.unwrap();
        far_write
            .write_all(&[APPLICATION_DATA, 3, 3, 0, 2, b'o', b'k'])
            .await
            .unwrap();
        far_write.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), b"ok");
    }

    #[test]
    fn hmac_sum_matches_rfc_2202_and_keeps_running() {
        let mut mac = new_hmac(b"Jefe");
        mac.update(b"what do ya ");
        let partial = mac.sum();
        mac.update(b"want for nothing?");
        let mut whole = new_hmac(b"Jefe");
        whole.update(b"what do ya ");
        assert_eq!(whole.sum(), partial);
        assert_eq!(
            mac.sum(),
            [
                0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
                0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79
            ]
        );
        assert_eq!(mac.tag(), [0xef, 0xfc, 0xdf, 0x6a]);
    }

    fn pair() -> (BoxStream, BoxStream) {
        let (a, b) = duplex(8192);
        let one = new_hmac(b"one");
        let two = new_hmac(b"two");
        (
            v3_conn(Box::new(a), one.clone(), two.clone(), None),
            v3_conn(Box::new(b), two, one, None),
        )
    }

    #[tokio::test]
    async fn v3_halves_move_data_both_ways_and_shutdown_keeps_reading() {
        let (left, right) = pair();
        let (mut left_read, mut left_write) = left.into_split();
        let (mut right_read, mut right_write) = right.into_split();
        let left_task = tokio::spawn(async move {
            left_write.write_all(b"ping").await.unwrap();
            left_write.shutdown().await.unwrap();
            let mut got = Vec::new();
            left_read.read_to_end(&mut got).await.unwrap();
            got
        });
        let right_task = tokio::spawn(async move {
            let mut got = Vec::new();
            right_read.read_to_end(&mut got).await.unwrap();
            right_write.write_all(b"pong").await.unwrap();
            right_write.shutdown().await.unwrap();
            got
        });
        assert_eq!(right_task.await.unwrap(), b"ping");
        assert_eq!(left_task.await.unwrap(), b"pong");
    }

    #[tokio::test]
    async fn v3_verification_failure_sends_an_alert_on_the_write_half() {
        let (near, far) = duplex(8192);
        let one = new_hmac(b"one");
        let two = new_hmac(b"two");
        let (mut read, mut write) = v3_conn(Box::new(near), one, two, None).into_split();
        let (mut far_read, mut far_write) = tokio::io::split(far);
        far_write
            .write_all(&[APPLICATION_DATA, 3, 3, 0, 5, 0, 0, 0, 0, b'x'])
            .await
            .unwrap();
        assert!(read.read(&mut [0u8; 8]).await.is_err());
        write.flush().await.unwrap();
        write.shutdown().await.unwrap();
        let mut sent = Vec::new();
        far_read.read_to_end(&mut sent).await.unwrap();
        assert_eq!(sent.len(), ALERT_RECORD);
        assert_eq!(sent.first(), Some(&ALERT));
    }
}
