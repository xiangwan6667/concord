use super::{Active, TcpConn};
use concord_common::{BoxRead, BoxWrite, Stream};
use concord_netstack::{NetReadHalf, NetWriteHalf};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct IpStream<T> {
    conn: TcpConn,
    _tunnel: Arc<T>,
}

impl<T: Send + Sync + 'static> AsyncRead for IpStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl<T: Send + Sync + 'static> AsyncWrite for IpStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl<T: Send + Sync + 'static> Stream for IpStream<T> {
    concord_common::stream_policy!(conn;
        forward: direct;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            raw_socket, tcp, peer_addr, needs_handshake, into_tcp;
        own: into_split);
    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let IpStream { conn, _tunnel } = *self;
        let (read, write, active) = conn.into_split();
        let hold = Arc::new((active, _tunnel));
        (
            Box::new(IpRead {
                read,
                _hold: hold.clone(),
            }),
            Box::new(IpWrite { write, _hold: hold }),
        )
    }
}

type Hold<T> = Arc<(Active, Arc<T>)>;

struct IpRead<T> {
    read: NetReadHalf,
    _hold: Hold<T>,
}

impl<T: Send + Sync + 'static> AsyncRead for IpRead<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

struct IpWrite<T> {
    write: NetWriteHalf,
    _hold: Hold<T>,
}

impl<T: Send + Sync + 'static> AsyncWrite for IpWrite<T> {
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

impl<T> IpStream<T> {
    pub(crate) fn new(conn: TcpConn, hold: Arc<T>) -> Self {
        Self {
            conn,
            _tunnel: hold,
        }
    }
}
