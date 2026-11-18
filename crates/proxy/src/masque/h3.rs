use std::io;
use std::sync::Arc;

use bytes::Bytes;
use concord_common::{DialCx, Tasks};
use http::{Method, Request};
use tokio::task::JoinHandle;

use super::config::Config;
use crate::quic::{QuicConn, io_error};

pub(super) type Requests = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
pub(super) type Driver = h3::client::Connection<h3_quinn::Connection, Bytes>;
pub(super) type RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub(super) type Send = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub(super) type Recv = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

pub(super) struct Client {
    pub(super) quic: QuicConn,
    pub(super) requests: Requests,
    driver: JoinHandle<()>,
    pub(super) tasks: Tasks,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Client {
    pub(super) async fn connect(config: &Config, cx: &DialCx<'_>) -> io::Result<Arc<Self>> {
        let mut endpoint = quinn::EndpointConfig::default();
        endpoint.cid_generator(|| Box::new(quinn_proto::RandomConnectionIdGenerator::new(20)));
        let quic = config.link.connect_endpoint(cx, endpoint).await?;
        let ip = config.network != "h3-l4proxy";
        let (mut driver, requests) = builder(ip)
            .build(h3_quinn::Connection::new(quic.conn.clone()))
            .await
            .map_err(io_error)?;
        // This owns the driver until peer validation finishes; only then may the task poll it.
        if ip {
            if !std::future::poll_fn(|cx| driver.poll_peer_datagrams(cx))
                .await
                .map_err(io_error)?
            {
                return Err(io::Error::other(
                    "MASQUE server did not enable HTTP datagrams",
                ));
            }
            if quic.conn.max_datagram_size().is_none() {
                return Err(io::Error::other(
                    "MASQUE server did not enable QUIC datagrams",
                ));
            }
        }
        let conn = quic.conn.clone();
        let tasks = config.link.tasks.clone();
        let driver = super::tunnel::spawn_driver(driver, conn, &tasks);
        Ok(Arc::new(Self {
            quic,
            requests,
            driver,
            tasks,
        }))
    }

    pub(super) fn usable(&self) -> bool {
        self.quic.conn.close_reason().is_none()
    }

    pub(super) async fn request(
        &self,
        config: &Config,
        target: Option<&str>,
    ) -> io::Result<RequestStream> {
        let mut request = if let Some(target) = target {
            Request::builder()
                .method(Method::CONNECT)
                .uri(format!("https://{target}"))
                .header("accept-encoding", "gzip")
                .header("user-agent", "quic-go HTTP/3")
                .body(())
        } else {
            Request::builder()
                .method(Method::CONNECT)
                .uri(config.uri.clone())
                .header("capsule-protocol", "?1")
                .body(())
        }
        .map_err(io_error)?;
        if target.is_none() {
            request
                .extensions_mut()
                .insert(h3::ext::Protocol::CF_CONNECT_IP);
        }
        self.send_request(request, target.is_none()).await
    }

    async fn send_request(&self, request: Request<()>, ip: bool) -> io::Result<RequestStream> {
        let mut sender = self.requests.clone();
        let mut stream = match sender.send_request(request).await {
            Ok(stream) => stream,
            Err(error) => {
                if !ip {
                    self.quic.conn.close(
                        quinn::VarInt::from_u32(0),
                        b"HTTP/3 request creation failed",
                    );
                }
                return Err(io_error(error));
            }
        };
        let response = stream.recv_response().await.map_err(io_error)?;
        if !response.status().is_success() || (ip && response.status() != http::StatusCode::OK) {
            return Err(io::Error::other(format!(
                "MASQUE CONNECT rejected: {}",
                response.status()
            )));
        }
        Ok(stream)
    }
}

pub(super) fn builder(ip: bool) -> h3::client::Builder {
    let mut builder = h3::client::builder();
    builder
        .send_grease(false)
        .max_field_section_size(10 << 20)
        .omit_zero_settings(true)
        .enable_datagram(ip)
        .enable_legacy_datagram(ip);
    builder
}
