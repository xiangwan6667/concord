use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::{BoxRead, BoxWrite};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::crypto::Ctr;

pub(super) struct HeaderMask {
    ctr: Ctr,
    skip: usize,
    head: [u8; 5],
    have: usize,
}

impl HeaderMask {
    pub(super) fn new(key: &[u8], iv: [u8; 16], skip: usize) -> Self {
        Self {
            ctr: Ctr::new(key, iv),
            skip,
            head: [0; 5],
            have: 0,
        }
    }

    pub(super) fn apply(&mut self, mut data: &mut [u8], decrypt: bool) {
        while !data.is_empty() {
            let skip = self.skip.min(data.len());
            self.skip -= skip;
            data = data.split_at_mut(skip).1;
            if data.is_empty() {
                break;
            }
            let take = data.len().min(5 - self.have);
            let (header, rest) = data.split_at_mut(take);
            if decrypt {
                self.ctr.apply(header);
            }
            self.head
                .split_at_mut(self.have)
                .1
                .split_at_mut(take)
                .0
                .copy_from_slice(header);
            if !decrypt {
                self.ctr.apply(header);
            }
            self.have += take;
            if self.have == 5 {
                self.skip = if self.head[..3] == [23, 3, 3] {
                    usize::from(u16::from_be_bytes([self.head[3], self.head[4]]))
                } else {
                    0
                };
                self.have = 0;
            }
            data = rest;
        }
    }
}

pub(super) struct MaskedRead {
    pub(super) inner: BoxRead,
    pub(super) mask: Option<HeaderMask>,
}

impl AsyncRead for MaskedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, out))?;
        if let Some(mask) = &mut this.mask {
            mask.apply(out.filled_mut().split_at_mut(before).1, true);
        }
        Poll::Ready(Ok(()))
    }
}

pub(super) struct MaskedWrite {
    inner: BoxWrite,
    mask: Option<HeaderMask>,
    pending: Vec<u8>,
    position: usize,
    accepted: usize,
}

impl MaskedWrite {
    pub(super) fn new(inner: BoxWrite, mask: Option<HeaderMask>) -> Self {
        Self {
            inner,
            mask,
            pending: Vec::new(),
            position: 0,
            accepted: 0,
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(rest) = self
            .pending
            .get(self.position..)
            .filter(|rest| !rest.is_empty())
        {
            let written = ready!(Pin::new(&mut self.inner).poll_write(cx, rest))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.position += written;
        }
        self.pending.clear();
        self.position = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MaskedWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.mask.is_none() {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }
        if this.pending.is_empty() {
            this.pending.extend_from_slice(data);
            this.accepted = data.len();
            if let Some(mask) = &mut this.mask {
                mask.apply(&mut this.pending, false);
            }
        }
        ready!(this.drain(cx))?;
        Poll::Ready(Ok(this.accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_mask_survives_every_fragment_boundary_and_skips_bodies() {
        let mut wire = vec![9; 23];
        for size in [17u16, 8192, 47] {
            wire.extend_from_slice(&[23, 3, 3]);
            wire.extend_from_slice(&size.to_be_bytes());
            wire.extend(std::iter::repeat_n(42, usize::from(size)));
        }
        let mut encoded = wire.clone();
        let mut mask = HeaderMask::new(b"key", [7; 16], 23);
        for bytes in encoded.chunks_mut(3) {
            mask.apply(bytes, false);
        }
        assert_eq!(&encoded[..23], &wire[..23]);
        assert_eq!(&encoded[28..45], &wire[28..45]);
        assert_ne!(&encoded[23..28], &wire[23..28]);
        for size in [1, 2, 4, 5, 16, 111, 8192, 17000] {
            let mut decoded = encoded.clone();
            let mut mask = HeaderMask::new(b"key", [7; 16], 23);
            for bytes in decoded.chunks_mut(size) {
                mask.apply(bytes, true);
            }
            assert_eq!(decoded, wire);
        }
    }
}

#[cfg(test)]
mod invalid_prefix_tests {
    use super::*;

    #[test]
    fn non_tls_header_does_not_skip_its_claimed_body_length() {
        let input = [22, 3, 3, 255, 255, 23, 3, 3, 0, 17];
        let mut expected = input;
        Ctr::new(b"key", [7; 16]).apply(&mut expected);
        let mut actual = input;
        let mut mask = HeaderMask::new(b"key", [7; 16], 0);
        mask.apply(&mut actual, false);
        assert_eq!(actual, expected);
        HeaderMask::new(b"key", [7; 16], 0).apply(&mut actual, true);
        assert_eq!(actual, input);
    }
}
