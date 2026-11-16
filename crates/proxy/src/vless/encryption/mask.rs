use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::{BoxRead, BoxWrite};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::crypto::{Ctr, xor};

pub(super) struct Mask {
    pub(super) cipher: Option<Ctr>,
    header: [u8; 5],
    have: usize,
    skip: usize,
}

impl Mask {
    fn new(cipher: Option<Ctr>, skip: usize) -> Self {
        Self {
            cipher,
            header: [0; 5],
            have: 0,
            skip,
        }
    }

    fn apply(&mut self, mut bytes: &mut [u8], decode: bool) {
        while !bytes.is_empty() {
            let skip = self.skip.min(bytes.len());
            bytes = bytes.get_mut(skip..).unwrap_or_default();
            self.skip -= skip;
            if bytes.is_empty() {
                break;
            }
            let count = (5 - self.have).min(bytes.len());
            let (head, rest) = bytes.split_at_mut(count);
            if decode && let Some(cipher) = &mut self.cipher {
                xor(cipher, head);
            }
            if let Some(header) = self.header.get_mut(self.have..self.have + count) {
                header.copy_from_slice(head);
            }
            if !decode && let Some(cipher) = &mut self.cipher {
                xor(cipher, head);
            }
            self.have += count;
            if self.have == 5 {
                self.skip = if self.header[..3] == [23, 3, 3] {
                    usize::from(u16::from_be_bytes([self.header[3], self.header[4]]))
                } else {
                    0
                };
                self.have = 0;
            }
            bytes = rest;
        }
    }
}

pub(super) struct MaskedRead {
    io: BoxRead,
    pub(super) mask: Mask,
}

impl MaskedRead {
    pub(super) fn new(io: BoxRead, cipher: Option<Ctr>, skip: usize) -> Self {
        Self {
            io,
            mask: Mask::new(cipher, skip),
        }
    }
}

impl AsyncRead for MaskedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let start = buf.filled().len();
        ready!(Pin::new(&mut *this.io).poll_read(cx, buf))?;
        if let Some(bytes) = buf.filled_mut().get_mut(start..) {
            this.mask.apply(bytes, true);
        }
        Poll::Ready(Ok(()))
    }
}

pub(super) struct MaskedWrite {
    io: BoxWrite,
    mask: Mask,
    pending: Vec<u8>,
    sent: usize,
}

impl MaskedWrite {
    pub(super) fn new(io: BoxWrite, cipher: Option<Ctr>, skip: usize) -> Self {
        Self {
            io,
            mask: Mask::new(cipher, skip),
            pending: Vec::new(),
            sent: 0,
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(bytes) = self
            .pending
            .get(self.sent..)
            .filter(|bytes| !bytes.is_empty())
        {
            let count = ready!(Pin::new(&mut *self.io).poll_write(cx, bytes))?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += count;
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MaskedWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if this.mask.cipher.is_none() {
            return Pin::new(&mut *this.io).poll_write(cx, bytes);
        }
        let count = bytes.len().min(16 * 1024);
        this.pending
            .extend_from_slice(bytes.get(..count).unwrap_or_default());
        this.mask.apply(&mut this.pending, false);
        if let Poll::Ready(Err(error)) = this.drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut *this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut *self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "tests compare fixed wire header and payload offsets"
    )]

    use super::*;

    #[test]
    fn masking_survives_fragmented_headers_and_leaves_record_bodies_intact() {
        let mut plain = vec![1; 19];
        for size in [17_u16, 255, 8192, 16640] {
            plain.extend_from_slice(&[23, 3, 3, (size >> 8) as u8, size as u8]);
            plain.extend(std::iter::repeat_n(42, usize::from(size)));
        }
        for chunk in [1, 2, 3, 5, 13, 8192, 65536] {
            let mut encoded = plain.clone();
            let mut mask = Mask::new(Some(super::super::crypto::ctr(b"key", &[5; 16])), 19);
            for bytes in encoded.chunks_mut(chunk) {
                mask.apply(bytes, false);
            }
            assert_eq!(&encoded[..19], &plain[..19]);
            assert_ne!(&encoded[19..24], &plain[19..24]);
            assert_eq!(&encoded[24..41], &plain[24..41]);
            let mut mask = Mask::new(Some(super::super::crypto::ctr(b"key", &[5; 16])), 19);
            for bytes in encoded.chunks_mut(7) {
                mask.apply(bytes, true);
            }
            assert_eq!(encoded, plain);
        }
    }
}
