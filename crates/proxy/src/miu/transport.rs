use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::{BoxStream, Stream};
use concord_tls::TlsConn;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) enum LaneIo {
    Tls(Box<TlsConn>),
    #[cfg(test)]
    Plain(BoxStream),
}

impl LaneIo {
    fn framed(&mut self) -> &mut dyn Stream {
        match self {
            Self::Tls(io) => &mut **io,
            #[cfg(test)]
            Self::Plain(io) => &mut **io,
        }
    }

    pub(super) fn raw(&mut self) -> io::Result<&mut BoxStream> {
        match self {
            Self::Tls(io) => Ok(io.raw_mut()),
            #[cfg(test)]
            Self::Plain(_) => Err(io::Error::other("miu: RAW requires outer TLS")),
        }
    }

    pub(super) fn at_raw_boundary(&mut self) -> bool {
        match self {
            Self::Tls(io) => !io.has_pending_plaintext() && io.at_record_boundary(),
            #[cfg(test)]
            Self::Plain(_) => false,
        }
    }
}

impl AsyncRead for LaneIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.framed()).poll_read(cx, buf)
    }
}

impl AsyncWrite for LaneIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.framed()).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.framed()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.framed()).poll_shutdown(cx)
    }
}
