mod browser;
mod config;
mod h1;
mod h3;
mod packet_up;
mod padding;
mod request;
mod transport;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use concord_common::sync::lock;
use concord_common::{BoxStream, Stream, Tasks};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use config::{SessionIds, Settings, effective_mode, session_id_generator};
pub use config::{XhttpOptions, XhttpReuse};
use packet_up::PacketUp;
use request::RequestFactory;
use transport::{Lease, Maker, Pending, ReuseManager, Transport};

use crate::DialFn;
use crate::http1::invalid;
pub use h3::QuicDialFn;

#[derive(Clone)]
pub enum XhttpDial {
    Tcp(DialFn),
    Quic(QuicDialFn),
}

impl From<DialFn> for XhttpDial {
    fn from(dial: DialFn) -> Self {
        Self::Tcp(dial)
    }
}

pub(crate) type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub(crate) type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// `download-settings`: a second server for the download half, with its own
/// request shape and connections.
#[derive(Clone)]
pub struct XhttpDownload {
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub reuse: Option<XhttpReuse>,
    pub keep_alive_period: i64,
    pub http1: bool,
    pub dial: XhttpDial,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    StreamOne,
    StreamUp,
    PacketUp,
}

struct Side {
    factory: Arc<RequestFactory>,
    make: Maker,
    manager: Option<ReuseManager>,
}

impl Side {
    fn lease(&self) -> Lease {
        match &self.manager {
            Some(manager) => manager.lease(),
            None => Lease::owned((self.make)()),
        }
    }
}

/// The client of one `xhttp` node. Each `dial` is one logical connection made of
/// HTTP requests, over its own HTTP/1.1 or HTTP/2 connection unless reuse
/// settings share them.
pub struct XhttpClient {
    mode: Mode,
    settings: Settings,
    ids: SessionIds,
    up: Side,
    down: Option<Side>,
    tasks: Tasks,
}

fn side(
    opts: &XhttpOptions,
    settings: Settings,
    browser: &browser::Browser,
    http1: bool,
    dial: XhttpDial,
    tasks: &Tasks,
) -> io::Result<Side> {
    let period = opts.keep_alive_period;
    let tasks = tasks.clone();
    let make: Maker = match dial {
        XhttpDial::Tcp(dial) => {
            Arc::new(move || Transport::new(http1, dial.clone(), period, tasks.clone()))
        }
        XhttpDial::Quic(dial) => Arc::new(move || Transport::h3(dial.clone(), tasks.clone())),
    };
    let manager = opts
        .reuse
        .as_ref()
        .map(|reuse| ReuseManager::new(reuse, make.clone()))
        .transpose()?;
    Ok(Side {
        factory: Arc::new(RequestFactory::new(opts.clone(), settings, browser.clone())),
        make,
        manager,
    })
}

impl XhttpClient {
    pub fn new(
        opts: XhttpOptions,
        dial: impl Into<XhttpDial>,
        download: Option<XhttpDownload>,
        tasks: Tasks,
    ) -> io::Result<Arc<XhttpClient>> {
        let mode = match effective_mode(&opts, download.is_some()) {
            "stream-one" => Mode::StreamOne,
            "stream-up" => Mode::StreamUp,
            "packet-up" => Mode::PacketUp,
            other => {
                return Err(invalid(format!(
                    "xhttp mode {other} is not implemented yet"
                )));
            }
        };
        if mode == Mode::StreamOne && download.is_some() {
            return Err(invalid(
                r#"xhttp mode "stream-one" cannot be used with download-settings"#,
            ));
        }
        let settings = Settings::resolve(&opts)?;
        let ids = session_id_generator(&opts)?;
        let browser = browser::Browser::new();
        let up = side(
            &opts,
            settings.clone(),
            &browser,
            opts.http1,
            dial.into(),
            &tasks,
        )?;
        let down = download
            .map(|download| {
                let mut down_opts = opts.clone();
                down_opts.host = download.host;
                down_opts.path = download.path;
                down_opts.headers = download.headers;
                down_opts.reuse = download.reuse;
                down_opts.keep_alive_period = download.keep_alive_period;
                down_opts.http1 = download.http1;
                let down_settings = Settings::resolve(&down_opts)?;
                side(
                    &down_opts,
                    down_settings,
                    &browser,
                    download.http1,
                    download.dial,
                    &tasks,
                )
            })
            .transpose()?;
        Ok(Arc::new(XhttpClient {
            mode,
            settings,
            ids,
            up,
            down,
            tasks,
        }))
    }

    pub async fn dial(&self) -> io::Result<BoxStream> {
        match self.mode {
            Mode::StreamOne => self.dial_stream_one().await,
            Mode::StreamUp => self.dial_stream_up().await,
            Mode::PacketUp => self.dial_packet_up().await,
        }
    }

    pub fn close(&self) {
        if let Some(manager) = &self.up.manager {
            manager.close();
        }
        if let Some(manager) = self.down.as_ref().and_then(|d| d.manager.as_ref()) {
            manager.close();
        }
    }

    async fn dial_stream_one(&self) -> io::Result<BoxStream> {
        let lease = self.up.lease();
        let req = self
            .up
            .factory
            .stream_request(self.up.factory.uplink_method(), "", true);
        let (writer, pending) = lease.stream(&req).await?;
        Ok(Box::new(XhttpConn::new(
            writer,
            checked(pending, "stream-one", |status| (200..300).contains(&status)),
            vec![Box::new(lease)],
        )))
    }

    async fn start_download(&self, session: &str) -> io::Result<(Pending, Lease)> {
        let down = self.down.as_ref().unwrap_or(&self.up);
        let lease = down.lease();
        let req = down.factory.stream_request("GET", session, false);
        let pending = lease.start_download(&req).await?;
        Ok((pending, lease))
    }

    async fn dial_stream_up(&self) -> io::Result<BoxStream> {
        let session = self.ids.generate();
        let (download, down_lease) = self.start_download(&session).await?;
        let (up_lease, same) = self.upload_lease(&down_lease);
        let req = self
            .up
            .factory
            .stream_request(self.up.factory.uplink_method(), &session, true);
        let (writer, response) = up_lease.stream(&req).await?;
        let failure: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let watch = failure.clone();
        let task = self.tasks.spawn(async move {
            let outcome = match response.await {
                Ok((status, mut body)) => {
                    if (200..300).contains(&status) {
                        let mut sink = [0u8; 1024];
                        while matches!(body.read(&mut sink).await, Ok(n) if n > 0) {}
                        None
                    } else {
                        Some(format!("xhttp stream-up upload bad status: {status}"))
                    }
                }
                Err(err) => Some(err.to_string()),
            };
            if let Some(message) = outcome {
                *lock(&watch) = Some(message);
            }
        });
        let writer: BoxWrite = Box::new(Guarded {
            inner: writer,
            failure,
        });
        let mut keep: Vec<Box<dyn Send>> = vec![Box::new(AbortOnDrop(task)), Box::new(down_lease)];
        if !same {
            keep.push(Box::new(up_lease));
        }
        Ok(Box::new(XhttpConn::new(
            writer,
            checked(download, "stream-up download", |status| status == 200),
            keep,
        )))
    }

    fn upload_lease(&self, download: &Lease) -> (Lease, bool) {
        if self.down.is_none() {
            (Lease::owned(download.shared()), true)
        } else {
            (self.up.lease(), false)
        }
    }

    async fn dial_packet_up(&self) -> io::Result<BoxStream> {
        let session = self.ids.generate();
        let (download, down_lease) = self.start_download(&session).await?;
        let (up_lease, _) = self.upload_lease(&down_lease);
        let writer = PacketUp::start(
            self.up.factory.clone(),
            up_lease,
            session,
            self.settings.sc_max_each_post_bytes.rand(),
            self.settings.sc_min_posts_interval_ms,
            &self.tasks,
        );
        Ok(Box::new(XhttpConn::new(
            Box::new(writer),
            checked(download, "packet-up download", |status| status == 200),
            vec![Box::new(down_lease)],
        )))
    }
}

fn checked(pending: Pending, what: &'static str, ok: fn(u16) -> bool) -> Pending {
    Box::pin(async move {
        let (status, body) = pending.await?;
        if !ok(status) {
            return Err(io::Error::other(format!(
                "xhttp {what} bad status: {status}"
            )));
        }
        Ok((status, body))
    })
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Guarded {
    inner: BoxWrite,
    failure: Arc<Mutex<Option<String>>>,
}

impl Guarded {
    fn check(&self) -> io::Result<()> {
        match lock(&self.failure).as_ref() {
            Some(message) => Err(io::Error::other(message.clone())),
            None => Ok(()),
        }
    }
}

impl AsyncWrite for Guarded {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check()?;
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

enum Incoming {
    Waiting(Pending),
    Body(BoxRead),
    Failed(io::ErrorKind, String),
}

/// Keeps the connection leases alive until both halves are gone; never locked.
type Keep = Arc<Mutex<Vec<Box<dyn Send>>>>;

struct XhttpWrite {
    writer: BoxWrite,
    _keep: Keep,
}

struct XhttpRead {
    incoming: Incoming,
    _keep: Keep,
}

/// One xhttp connection: writes go to the uplink requests, reads wait for the
/// download response headers and then stream its body.
struct XhttpConn {
    write: XhttpWrite,
    read: XhttpRead,
}

impl XhttpConn {
    fn new(writer: BoxWrite, pending: Pending, keep: Vec<Box<dyn Send>>) -> XhttpConn {
        let keep = Arc::new(Mutex::new(keep));
        XhttpConn {
            write: XhttpWrite {
                writer,
                _keep: keep.clone(),
            },
            read: XhttpRead {
                incoming: Incoming::Waiting(pending),
                _keep: keep,
            },
        }
    }
}

impl AsyncRead for XhttpRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.incoming {
                Incoming::Waiting(pending) => match ready!(pending.as_mut().poll(cx)) {
                    Ok((_, body)) => this.incoming = Incoming::Body(body),
                    Err(err) => {
                        this.incoming = Incoming::Failed(err.kind(), err.to_string());
                        return Poll::Ready(Err(err));
                    }
                },
                Incoming::Body(body) => return Pin::new(body).poll_read(cx, buf),
                Incoming::Failed(kind, message) => {
                    return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
                }
            }
        }
    }
}

impl AsyncWrite for XhttpWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

impl AsyncRead for XhttpConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpConn {
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

impl Stream for XhttpConn {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (concord_common::BoxRead, concord_common::BoxWrite) {
        let XhttpConn { write, read } = *self;
        (Box::new(read), Box::new(write))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    struct Flag(Arc<AtomicBool>);

    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn split_halves_run_independently_and_share_the_lease() {
        let (up_near, mut up_far) = duplex(1 << 16);
        let (mut down_far, down_near) = duplex(1 << 16);
        let released = Arc::new(AtomicBool::new(false));
        let pending: Pending = Box::pin(async move { Ok((200, Box::new(down_near) as BoxRead)) });
        let conn: BoxStream = Box::new(XhttpConn::new(
            Box::new(up_near),
            pending,
            vec![Box::new(Flag(released.clone()))],
        ));
        let (mut read, mut write) = conn.into_split();
        let writer = tokio::spawn(async move {
            write.write_all(b"up").await.unwrap();
            write.shutdown().await.unwrap();
            write
        });
        let mut sent = Vec::new();
        up_far.read_to_end(&mut sent).await.unwrap();
        assert_eq!(sent, b"up");
        down_far.write_all(b"down").await.unwrap();
        down_far.shutdown().await.unwrap();
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"down");
        drop(writer.await.unwrap());
        assert!(!released.load(Ordering::SeqCst));
        drop(read);
        assert!(released.load(Ordering::SeqCst));
    }
}
