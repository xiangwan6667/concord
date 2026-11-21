use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::{fmt, io};

use concord_common::{BoxRead, BoxStream, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::invalid_data;

pub const RECORD_HEADER_LEN: usize = 5;
const MAX_RECORD_BODY: usize = 0x4800;

#[derive(Clone, Copy, Debug)]
enum State {
    Header { have: usize },
    HeaderOut { given: usize, body: usize },
    Body { left: usize },
}

pub struct RecordIo<S> {
    inner: S,
    header: [u8; RECORD_HEADER_LEN],
    state: State,
    aligned: bool,
}

impl<S> fmt::Debug for RecordIo<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordIo")
            .field("state", &self.state)
            .field("aligned", &self.aligned)
            .finish_non_exhaustive()
    }
}

impl<S> RecordIo<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; RECORD_HEADER_LEN],
            state: State::Header { have: 0 },
            aligned: true,
        }
    }

    /// Reads straight through, as many bytes per call as the reader asks for.
    /// `at_record_boundary` means nothing on it.
    pub fn unaligned(inner: S) -> Self {
        Self {
            aligned: false,
            ..Self::new(inner)
        }
    }

    /// Stops aligning reads; only at a record boundary, where nothing is half handed out.
    pub(crate) fn set_unaligned(&mut self) {
        if self.at_record_boundary() {
            self.aligned = false;
        }
    }

    pub(crate) fn is_aligned(&self) -> bool {
        self.aligned
    }

    /// True when every byte read from the transport so far ended a record, so
    /// the next byte on the wire starts one.
    pub fn at_record_boundary(&self) -> bool {
        matches!(self.state, State::Header { have: 0 })
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl RecordIo<BoxStream> {
    /// The read half keeps the record position, so a split mid-record stays aligned.
    pub(crate) fn into_split(self) -> (RecordIo<BoxRead>, BoxWrite) {
        let (read, write) = self.inner.into_split();
        let reader = RecordIo {
            inner: read,
            header: self.header,
            state: self.state,
            aligned: self.aligned,
        };
        (reader, write)
    }
}

fn read_some<S: AsyncRead + Unpin>(
    inner: &mut S,
    cx: &mut Context<'_>,
    dst: &mut [u8],
) -> Poll<io::Result<usize>> {
    let mut buf = ReadBuf::new(dst);
    ready!(Pin::new(inner).poll_read(cx, &mut buf))?;
    Poll::Ready(Ok(buf.filled().len()))
}

/// Hands out one record per read: the five header bytes, then the body, and
/// never a byte of the next record. Whatever sits on top (rustls, BoringSSL)
/// therefore cannot hold wire bytes past the record it is working on, which is
/// what lets XTLS Vision take the socket over between two records.
impl<S: AsyncRead + Unpin> AsyncRead for RecordIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.aligned {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match this.state {
                State::Header { have } => {
                    let Some(dst) = this.header.get_mut(have..) else {
                        return Poll::Ready(Err(invalid_data("tls record header overrun")));
                    };
                    let n = ready!(read_some(&mut this.inner, cx, dst))?;
                    if n == 0 {
                        return if have == 0 {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                        };
                    }
                    let have = have + n;
                    if have < RECORD_HEADER_LEN {
                        this.state = State::Header { have };
                        continue;
                    }
                    let [kind, major, _, hi, lo] = this.header;
                    let body = usize::from(u16::from_be_bytes([hi, lo]));
                    if !(20..=24).contains(&kind) || major != 3 || body > MAX_RECORD_BODY {
                        this.state = State::Header { have: 0 };
                        return Poll::Ready(Err(invalid_data("not a tls record")));
                    }
                    this.state = State::HeaderOut { given: 0, body };
                }
                State::HeaderOut { given, body } => {
                    let Some(rest) = this.header.get(given..) else {
                        return Poll::Ready(Err(invalid_data("tls record header overrun")));
                    };
                    let take = rest.len().min(buf.remaining());
                    buf.put_slice(rest.get(..take).unwrap_or_default());
                    let given = given + take;
                    this.state = if given < RECORD_HEADER_LEN {
                        State::HeaderOut { given, body }
                    } else if body == 0 {
                        State::Header { have: 0 }
                    } else {
                        State::Body { left: body }
                    };
                    return Poll::Ready(Ok(()));
                }
                State::Body { left } => {
                    let want = left.min(buf.remaining());
                    let n = ready!(read_some(
                        &mut this.inner,
                        cx,
                        buf.initialize_unfilled_to(want)
                    ))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    buf.advance(n);
                    this.state = if n == left {
                        State::Header { have: 0 }
                    } else {
                        State::Body { left: left - n }
                    };
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<S: Stream> Stream for RecordIo<S> {
    concord_common::stream_policy!(default: all);
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    fn record(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind, 3, 3];
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    async fn read_all(io: &mut RecordIo<tokio::io::DuplexStream>) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 100_000];
        loop {
            match io.read(&mut buf).await {
                Ok(0) => return (out, true),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => return (out, false),
            }
        }
    }

    #[tokio::test]
    async fn unaligned_reads_span_records() {
        let (mut far, near) = duplex(1 << 16);
        let wire = [record(23, &[1; 40]), record(23, &[2; 7])].concat();
        far.write_all(&wire).await.unwrap();
        let mut io = RecordIo::unaligned(near);
        let mut got = vec![0u8; wire.len()];
        io.read_exact(&mut got).await.unwrap();
        assert_eq!(got, wire);
    }

    #[tokio::test]
    async fn never_reads_past_the_record_it_is_serving() {
        let (mut far, near) = duplex(1 << 16);
        let first = record(23, &[1; 40]);
        let second = record(23, &[2; 7]);
        far.write_all(&first).await.unwrap();
        far.write_all(&second).await.unwrap();
        let mut io = RecordIo::new(near);
        let mut got = vec![0u8; first.len()];
        let mut filled = 0;
        while filled < got.len() {
            let n = io.read(&mut got[filled..]).await.unwrap();
            assert!(n > 0);
            filled += n;
        }
        assert_eq!(got, first);
        assert!(io.at_record_boundary());

        let mut rest = Vec::new();
        far.shutdown().await.unwrap();
        io.get_mut().read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, second);
    }

    #[tokio::test]
    async fn serves_records_split_across_tiny_reads() {
        let (mut far, near) = duplex(1 << 16);
        let rec = record(22, &[9; 33]);
        far.write_all(&rec).await.unwrap();
        far.shutdown().await.unwrap();
        let mut io = RecordIo::new(near);
        let mut out = Vec::new();
        let mut one = [0u8; 3];
        loop {
            let n = io.read(&mut one).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&one[..n]);
        }
        assert_eq!(out, rec);
        assert!(io.at_record_boundary());
    }

    #[tokio::test]
    async fn passes_zero_length_records() {
        let (mut far, near) = duplex(1 << 16);
        let mut wire = record(23, &[]);
        wire.extend(record(23, &[5]));
        far.write_all(&wire).await.unwrap();
        far.shutdown().await.unwrap();
        let mut io = RecordIo::new(near);
        let mut out = Vec::new();
        io.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, wire);
    }

    #[tokio::test]
    async fn truncated_record_is_an_unexpected_eof() {
        let (mut far, near) = duplex(1 << 16);
        let rec = record(23, &[1; 20]);
        far.write_all(&rec[..12]).await.unwrap();
        far.shutdown().await.unwrap();
        let mut io = RecordIo::new(near);
        let mut out = Vec::new();
        let err = io.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(!io.at_record_boundary());
    }

    #[tokio::test]
    async fn rejects_things_that_are_not_records() {
        for wire in [
            b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec(),
            vec![23, 2, 0, 0, 1, 0],
            vec![23, 3, 3, 0xff, 0xff, 0],
            vec![0, 3, 3, 0, 1, 0],
        ] {
            let (mut far, near) = duplex(1 << 16);
            far.write_all(&wire).await.unwrap();
            let mut io = RecordIo::new(near);
            let mut buf = [0u8; 64];
            let err = io.read(&mut buf).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn random_bytes_never_panic_and_never_overread() {
        let mut rng = StdRng::seed_from_u64(0x7e57);
        for round in 0..300 {
            let len = rng.random_range(0..400usize);
            let mut wire: Vec<u8> = (0..len).map(|_| rng.random()).collect();
            if round % 2 == 0 && wire.len() > 5 {
                wire[0] = 23;
                wire[1] = 3;
                let body = rng.random_range(0..wire.len());
                wire[3..5].copy_from_slice(&u16::try_from(body).unwrap().to_be_bytes());
            }
            let (mut far, near) = duplex(1 << 16);
            far.write_all(&wire).await.unwrap();
            far.shutdown().await.unwrap();
            let mut io = RecordIo::new(near);
            let (served, clean) = read_all(&mut io).await;
            assert!(wire.starts_with(&served));
            if clean {
                assert_eq!(served, wire);
            }
        }
    }
}
