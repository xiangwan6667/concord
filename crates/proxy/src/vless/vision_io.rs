use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_tls::{TlsRead, TlsWrite};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::encryption::{EncryptionRead, EncryptionWrite};

pub(super) enum VisionRead {
    Tls(TlsRead),
    Encrypted(EncryptionRead),
}

impl VisionRead {
    pub(super) fn raw_mut(&mut self) -> &mut (dyn AsyncRead + Send + Unpin) {
        match self {
            Self::Tls(io) => io.raw_mut().as_mut(),
            Self::Encrypted(io) => io.raw_mut(),
        }
    }
    pub(super) fn at_record_boundary(&self) -> bool {
        match self {
            Self::Tls(io) => io.at_record_boundary(),
            Self::Encrypted(io) => io.at_record_boundary(),
        }
    }
    pub(super) fn has_pending_plaintext(&self) -> bool {
        match self {
            Self::Tls(io) => io.has_pending_plaintext(),
            Self::Encrypted(io) => io.has_pending_plaintext(),
        }
    }
    pub(super) fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        match self {
            Self::Tls(io) => io.drain_plaintext(out),
            Self::Encrypted(io) => io.drain_plaintext(out),
        }
    }
}

impl AsyncRead for VisionRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(io) => Pin::new(io).poll_read(cx, buf),
            Self::Encrypted(io) => Pin::new(io).poll_read(cx, buf),
        }
    }
}

pub(super) enum VisionWrite {
    Tls(TlsWrite),
    Encrypted(EncryptionWrite),
}

impl VisionWrite {
    pub(super) fn raw_mut(&mut self) -> &mut (dyn AsyncWrite + Send + Unpin) {
        match self {
            Self::Tls(io) => io.raw_mut().as_mut(),
            Self::Encrypted(io) => io.raw_mut(),
        }
    }
}

impl AsyncWrite for VisionWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(io) => Pin::new(io).poll_write(cx, bytes),
            Self::Encrypted(io) => Pin::new(io).poll_write(cx, bytes),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(io) => Pin::new(io).poll_flush(cx),
            Self::Encrypted(io) => Pin::new(io).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(io) => Pin::new(io).poll_shutdown(cx),
            Self::Encrypted(io) => Pin::new(io).poll_shutdown(cx),
        }
    }
}
