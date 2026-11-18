use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use concord_common::{BoxRead, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::ReusableBoxFuture;

use super::h3;
use crate::quic::io_error;

pub(super) type Sent = (h3::Send, io::Result<()>);

pub(super) struct Read {
    stream: h3::Recv,
    data: Bytes,
    _client: Arc<h3::Client>,
}

impl AsyncRead for Read {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.data.is_empty() && out.remaining() != 0 {
            match ready!(this.stream.poll_recv_data(cx)).map_err(io_error)? {
                Some(mut data) => this.data = data.copy_to_bytes(data.remaining()),
                None => return Poll::Ready(Ok(())),
            }
        }
        let len = out.remaining().min(this.data.len());
        out.put_slice(&this.data.split_to(len));
        Poll::Ready(Ok(()))
    }
}

pub(super) struct Write {
    stream: Option<h3::Send>,
    pending: ReusableBoxFuture<'static, Sent>,
    in_flight: bool,
    unreported: Bytes,
    finished: bool,
    failed: bool,
    _client: Arc<h3::Client>,
}

impl Write {
    fn complete(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.in_flight {
            let (stream, result) = ready!(self.pending.poll(cx));
            self.stream = Some(stream);
            self.in_flight = false;
            if let Err(error) = result {
                self.unreported = Bytes::new();
                self.failed = true;
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Write {
    fn drop(&mut self) {
        if self.in_flight && !self.finished {
            // Finish an already-started DATA frame before Quinn's implicit FIN.
            let sending = std::mem::replace(
                &mut self.pending,
                ReusableBoxFuture::new(std::future::pending()),
            );
            super::tunnel::finish_write(sending, self._client.clone());
        }
    }
}

impl AsyncWrite for Write {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.finished || this.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // h3 send_data can emit a frame header before Pending. Its owned payload must still
        // finish after cancellation, or the peer would receive a truncated DATA frame.
        if this.in_flight || !this.unreported.is_empty() {
            ready!(this.complete(cx))?;
            let count = data.len().min(this.unreported.len());
            if this.unreported.get(..count) == data.get(..count) {
                this.unreported.advance(count);
                return Poll::Ready(Ok(count));
            }
            this.unreported = Bytes::new();
        }
        let Some(mut stream) = this.stream.take() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let bytes = Bytes::copy_from_slice(data);
        this.unreported = bytes.clone();
        this.pending.set(async move {
            let result = stream.send_data(bytes).await.map_err(io_error);
            (stream, result)
        });
        this.in_flight = true;
        ready!(this.complete(cx))?;
        this.unreported = Bytes::new();
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.complete(cx))?;
        this.unreported = Bytes::new();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.complete(cx))?;
        this.unreported = Bytes::new();
        if !this.finished {
            let Some(mut stream) = this.stream.take() else {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            };
            this.pending.set(async move {
                let result = stream.finish().await.map_err(io_error);
                (stream, result)
            });
            this.in_flight = true;
            this.finished = true;
        }
        this.complete(cx)
    }
}

pub(super) struct Body {
    read: Read,
    write: Write,
}

impl Body {
    pub(super) fn new(stream: h3::RequestStream, client: Arc<h3::Client>) -> Self {
        let (send, recv) = stream.split();
        Self {
            read: Read {
                stream: recv,
                data: Bytes::new(),
                _client: client.clone(),
            },
            write: Write {
                stream: Some(send),
                pending: ReusableBoxFuture::new(std::future::pending()),
                in_flight: false,
                unreported: Bytes::new(),
                finished: false,
                failed: false,
                _client: client,
            },
        }
    }
}

impl AsyncRead for Body {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, out)
    }
}

impl AsyncWrite for Body {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

impl Stream for Body {
    concord_common::stream_policy!(
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            raw_socket, tcp, peer_addr, needs_handshake, into_tcp, direct;
        own: into_split);
    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        (Box::new(self.read), Box::new(self.write))
    }
}
