use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use concord_common::{BoxStream, Tasks};
use futures_util::future::BoxFuture;
use h2::client::SendRequest;
use http::{Method, Request, Uri};
use tokio::sync::Mutex;

use super::MuxSession;
use crate::h2io::{Activity, H2Body, Incoming, STREAM_WINDOW, h2_io_error, spawn_connection};

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// sing-mux sets the h2mux transport's `MaxReadFrameSize` to sing's 32 KiB buffer size; the
// connection window is the Go HTTP/2 client's default.
const MAX_FRAME_SIZE: u32 = 32 * 1024;
const CONN_WINDOW: u32 = 65_535 + (1 << 30);

pub(super) fn client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME_SIZE)
        .enable_push(false);
    builder
}

pub(super) struct H2MuxSession {
    sender: Mutex<SendRequest<Bytes>>,
    activity: Arc<Activity>,
    streams: Arc<AtomicUsize>,
    retired: AtomicBool,
}

impl H2MuxSession {
    pub async fn new(io: BoxStream, tasks: &Tasks) -> io::Result<Self> {
        let (sender, conn) = client_builder()
            .handshake::<_, Bytes>(io)
            .await
            .map_err(h2_io_error)?;
        let activity = Activity::new();
        activity.touch();
        spawn_connection(tasks, conn, Some(IDLE_TIMEOUT), activity.clone());
        Ok(H2MuxSession {
            sender: Mutex::new(sender),
            activity,
            streams: Arc::new(AtomicUsize::new(0)),
            retired: AtomicBool::new(false),
        })
    }
}

struct StreamCount(Arc<AtomicUsize>);

impl Drop for StreamCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl MuxSession for H2MuxSession {
    fn open(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(async move {
            let mut sender = self
                .sender
                .lock()
                .await
                .clone()
                .ready()
                .await
                .map_err(h2_io_error)?;
            let uri: Uri = "localhost"
                .parse()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(uri)
                .body(())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            let (response, send) = sender.send_request(request, false).map_err(h2_io_error)?;
            self.streams.fetch_add(1, Ordering::Relaxed);
            let guard = StreamCount(self.streams.clone());
            let body = H2Body::new(send, Incoming::Response(response))
                .with_activity(self.activity.clone())
                .on_drop(move || drop(guard));
            Ok(Box::new(body) as BoxStream)
        })
    }

    fn streams(&self) -> usize {
        self.streams.load(Ordering::Relaxed)
    }

    fn is_closed(&self) -> bool {
        self.retired.load(Ordering::Relaxed) || self.activity.ended()
    }

    fn close(&self) {
        self.retired.store(true, Ordering::Relaxed);
    }
}
