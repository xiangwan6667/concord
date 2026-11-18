mod errors;
mod io;

use std::io as stdio;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::future::BoxFuture;
use tokio::io::AsyncReadExt;

use errors::error;

use super::BoxRead;
use super::request::Built;
use super::transport::Pending;

type Requests = ::h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type RequestStream = ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

pub type QuicDialFn = Arc<
    dyn Fn() -> BoxFuture<'static, stdio::Result<(quinn::Connection, Arc<dyn Send + Sync>)>>
        + Send
        + Sync,
>;

struct Session {
    conn: quinn::Connection,
    requests: Requests,
    driver: tokio::task::JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.conn.close(quinn::VarInt::from_u32(0x100), b"");
        self.driver.abort();
    }
}

pub(crate) struct H3Transport {
    dial: QuicDialFn,
    tasks: concord_common::Tasks,
    session: Arc<tokio::sync::Mutex<Option<Arc<Session>>>>,
}

impl H3Transport {
    pub(super) fn new(dial: QuicDialFn, tasks: concord_common::Tasks) -> Self {
        Self {
            dial,
            tasks,
            session: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    async fn session(&self) -> stdio::Result<Arc<Session>> {
        let mut slot = self.session.lock().await;
        if let Some(session) = slot.as_ref().filter(|s| s.conn.close_reason().is_none()) {
            return Ok(session.clone());
        }
        let (conn, guard) = (self.dial)().await?;
        let (mut driver, requests) = ::h3::client::builder()
            .send_grease(false)
            .build(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(error)?;
        let weak = Arc::downgrade(&self.session);
        let id = conn.stable_id();
        let task = self.tasks.spawn(async move {
            let _ = driver.wait_idle().await;
            if let Some(slot) = weak.upgrade() {
                let mut slot = slot.lock().await;
                if slot.as_ref().is_some_and(|s| s.conn.stable_id() == id) {
                    slot.take();
                }
            }
            drop(guard);
        });
        let session = Arc::new(Session {
            conn,
            requests,
            driver: task,
        });
        *slot = Some(session.clone());
        Ok(session)
    }

    async fn request(&self, req: &Built) -> stdio::Result<(RequestStream, Arc<Session>)> {
        let mut request = http::Request::builder()
            .method(req.method.as_str())
            .version(http::Version::HTTP_3)
            .uri(format!("https://{}{}", req.host, req.path_and_query()));
        for (key, value) in req.headers.iter() {
            if !key.eq_ignore_ascii_case("host") {
                request = request.header(key, value);
            }
        }
        let request = request.body(()).map_err(error)?;
        for retry in [true, false] {
            let session = self.session().await?;
            let result = session.requests.clone().send_request(request.clone()).await;
            match result {
                Ok(stream) => return Ok((stream, session)),
                Err(err) => {
                    let mut slot = self.session.lock().await;
                    if slot
                        .as_ref()
                        .is_some_and(|cached| Arc::ptr_eq(cached, &session))
                    {
                        slot.take();
                    }
                    if !retry
                        || !matches!(
                            err,
                            ::h3::error::StreamError::RemoteClosing { .. }
                                | ::h3::error::StreamError::ConnectionError { .. }
                        )
                    {
                        return Err(error(err));
                    }
                }
            }
        }
        unreachable!()
    }

    fn response(mut recv: io::Receive, session: Arc<Session>) -> Pending {
        Box::pin(async move {
            let response = recv.recv_response().await.map_err(error)?;
            let status = response.status().as_u16();
            Ok((status, Box::new(io::Reader::new(recv, session)) as BoxRead))
        })
    }

    pub(super) async fn fixed(&self, req: &Built, body: Vec<u8>) -> stdio::Result<u16> {
        let (stream, session) = self.request(req).await?;
        let (send, recv) = stream.split();
        let mut upload = io::Upload::new(send);
        if !body.is_empty() {
            upload.send(Bytes::from(body)).await?;
        }
        upload.finish().await?;
        let (status, mut reader) = Self::response(recv, session).await?;
        let mut sink = [0; 1024];
        while reader.read(&mut sink).await? > 0 {}
        Ok(status)
    }

    pub(super) async fn download(&self, req: &Built) -> stdio::Result<Pending> {
        let (stream, session) = self.request(req).await?;
        let (send, recv) = stream.split();
        io::Upload::new(send).finish().await?;
        Ok(Self::response(recv, session))
    }

    pub(super) async fn stream(&self, req: &Built) -> stdio::Result<(super::BoxWrite, Pending)> {
        let (stream, session) = self.request(req).await?;
        let (send, recv) = stream.split();
        Ok((
            Box::new(io::Writer::new(send, session.clone())),
            Self::response(recv, session),
        ))
    }

    pub(super) fn close(&self) {
        if let Ok(mut slot) = self.session.try_lock()
            && let Some(session) = slot.take()
        {
            session.conn.close(quinn::VarInt::from_u32(0x100), b"");
        }
    }
}

#[cfg(test)]
mod tests;
