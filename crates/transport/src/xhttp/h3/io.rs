use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Session, error};

pub(super) type Receive = ::h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type Send = ::h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;

pub(super) struct Reader {
    recv: Receive,
    pending: Bytes,
    _session: Arc<Session>,
}

impl Reader {
    pub(super) fn new(recv: Receive, session: Arc<Session>) -> Self {
        Self {
            recv,
            pending: Bytes::new(),
            _session: session,
        }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while this.pending.is_empty() {
            let Some(mut data) = ready!(this.recv.poll_recv_data(cx)).map_err(error)? else {
                return Poll::Ready(Ok(()));
            };
            this.pending = data.copy_to_bytes(data.remaining());
        }
        let len = buf.remaining().min(this.pending.len());
        buf.put_slice(&this.pending.split_to(len));
        Poll::Ready(Ok(()))
    }
}

pub(super) struct Upload {
    stream: Send,
    finished: bool,
}

impl Upload {
    pub(super) fn new(stream: Send) -> Self {
        Self {
            stream,
            finished: false,
        }
    }

    pub(super) async fn send(&mut self, body: Bytes) -> io::Result<()> {
        self.stream.send_data(body).await.map_err(error)
    }

    pub(super) async fn finish(&mut self) -> io::Result<()> {
        self.stream.finish().await.map_err(error)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        if !self.finished {
            self.stream
                .stop_stream(::h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

type Sending = BoxFuture<'static, (Upload, io::Result<()>)>;

pub(super) struct Writer {
    send: Option<Upload>,
    pending: Option<Sending>,
    writing: Option<usize>,
    failure: Option<(io::ErrorKind, String)>,
    finished: bool,
    _session: Arc<Session>,
}

impl Writer {
    pub(super) fn new(send: Send, session: Arc<Session>) -> Self {
        Self {
            send: Some(Upload::new(send)),
            pending: None,
            writing: None,
            failure: None,
            finished: false,
            _session: session,
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((kind, message)) = &self.failure {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if let Some(pending) = &mut self.pending {
            let (send, result) = ready!(pending.as_mut().poll(cx));
            self.pending = None;
            self.send = Some(send);
            if let Err(err) = result {
                self.failure = Some((err.kind(), err.to_string()));
                return Poll::Ready(Err(err));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if let Some(written) = this.writing.take() {
            return Poll::Ready(Ok(written));
        }
        if this.finished {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(mut send) = this.send.take() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let body = Bytes::copy_from_slice(data);
        this.pending = Some(Box::pin(async move {
            let result = send.send(body).await;
            (send, result)
        }));
        this.writing = Some(data.len());
        ready!(this.drain(cx))?;
        this.writing = None;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().drain(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if !this.finished {
            this.finished = true;
            let Some(mut send) = this.send.take() else {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            };
            this.pending = Some(Box::pin(async move {
                let result = send.finish().await;
                (send, result)
            }));
        }
        this.drain(cx)
    }
}
