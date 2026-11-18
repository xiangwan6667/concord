mod frame;

use std::io;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use concord_common::sync::lock;
use concord_common::{BoxStream, Tasks};
use h2::client::SendRequest;
use http::{Method, Request, Uri};

use crate::DialFn;
use crate::h2io::{Activity, H2Body, Incoming, STREAM_WINDOW, h2_io_error, spawn_connection};
pub(crate) use frame::gun_framed;

const DEFAULT_SERVICE: &str = "GunService";
const DEFAULT_USER_AGENT: &str = "grpc-go/1.36.0";
const CONN_WINDOW: u32 = 65_535 + (1 << 30);
const MAX_FRAME_SIZE: u32 = 1 << 20;
const MAX_HEADER_LIST_SIZE: u32 = 10 << 20;

fn client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME_SIZE)
        .max_header_list_size(MAX_HEADER_LIST_SIZE)
        .enable_push(false);
    builder
}

#[derive(Clone, Debug, Default)]
pub struct GrpcOptions {
    pub service_name: String,
    pub user_agent: String,
    /// The request's `:authority`: `servername`, or the node's `host:port` when none is set.
    pub authority: String,
    /// Seconds, 0 for no health check.
    pub ping_interval: u32,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
}

pub fn service_path(service_name: &str) -> String {
    let name = if service_name.is_empty() {
        DEFAULT_SERVICE
    } else {
        service_name
    };
    if name.starts_with('/') {
        name.to_string()
    } else {
        format!("/{name}/Tun")
    }
}

struct Transport {
    streams: Arc<AtomicI64>,
    sender: tokio::sync::Mutex<Option<SendRequest<Bytes>>>,
    activity: Arc<Activity>,
}

impl Transport {
    fn new() -> Arc<Transport> {
        Arc::new(Transport {
            streams: Arc::new(AtomicI64::new(0)),
            sender: tokio::sync::Mutex::new(None),
            activity: Activity::new(),
        })
    }
}

/// One node's gun client. Streams share a small pool of HTTP/2 connections the
/// way `gun.Client` shares `http.Transport`s: `max_connections` bounds the pool,
/// `min_streams` fills a connection before another opens, and without a connection
/// bound `max_streams` caps streams per connection.
pub struct GunClient {
    opts: GrpcOptions,
    max_connections: usize,
    dial: DialFn,
    pool: Mutex<Vec<Arc<Transport>>>,
    tasks: Tasks,
}

impl GunClient {
    /// `dial` returns a stream ready for HTTP/2: TCP, then TLS offering `h2` when the
    /// node uses TLS. Reuse `tls_dial` for the TLS case.
    pub fn new(opts: GrpcOptions, dial: DialFn, tasks: Tasks) -> Arc<GunClient> {
        let mut opts = opts;
        if opts.max_connections == 0 && opts.min_streams == 0 && opts.max_streams == 0 {
            opts.max_connections = 1;
        }
        Arc::new(GunClient {
            max_connections: opts.max_connections,
            opts,
            dial,
            pool: Mutex::new(Vec::new()),
            tasks,
        })
    }

    fn pick(&self) -> Arc<Transport> {
        let mut pool = lock(&self.pool);
        let mut best: Option<&Arc<Transport>> = None;
        for transport in pool.iter() {
            let fewer = best.is_none_or(|b| {
                transport.streams.load(Ordering::Relaxed) < b.streams.load(Ordering::Relaxed)
            });
            if fewer {
                best = Some(transport);
            }
        }
        let chosen = best.cloned();
        let reuse = chosen.filter(|transport| {
            let streams = transport.streams.load(Ordering::Relaxed);
            if streams == 0 {
                return true;
            }
            if self.max_connections > 0 {
                pool.len() >= self.max_connections
                    || usize::try_from(streams).is_ok_and(|s| s < self.opts.min_streams)
            } else {
                self.opts.max_streams > 0
                    && usize::try_from(streams).is_ok_and(|s| s < self.opts.max_streams)
            }
        });
        let transport = reuse.unwrap_or_else(|| {
            let fresh = Transport::new();
            pool.push(fresh.clone());
            fresh
        });
        transport.streams.fetch_add(1, Ordering::Relaxed);
        transport
    }

    async fn sender(&self, transport: &Transport) -> io::Result<SendRequest<Bytes>> {
        let mut slot = transport.sender.lock().await;
        for attempt in 0..2 {
            if slot.is_none() {
                let io = (self.dial)().await?;
                let (sender, conn) = client_builder()
                    .handshake::<_, Bytes>(io)
                    .await
                    .map_err(h2_io_error)?;
                let interval = Duration::from_secs(u64::from(self.opts.ping_interval));
                transport.activity.touch();
                spawn_connection(
                    &self.tasks,
                    conn,
                    Some(interval),
                    transport.activity.clone(),
                );
                *slot = Some(sender);
            }
            let Some(current) = slot.clone() else {
                continue;
            };
            match current.ready().await {
                Ok(ready) => return Ok(ready),
                Err(err) if attempt == 1 => return Err(h2_io_error(err)),
                Err(_) => *slot = None,
            }
        }
        Err(io::ErrorKind::NotConnected.into())
    }

    pub async fn dial(&self) -> io::Result<BoxStream> {
        let transport = self.pick();
        let guard = StreamCount(transport.streams.clone());
        let mut sender = self.sender(&transport).await?;
        let user_agent = if self.opts.user_agent.is_empty() {
            DEFAULT_USER_AGENT
        } else {
            &self.opts.user_agent
        };
        let uri = Uri::builder()
            .scheme("https")
            .authority(self.opts.authority.as_str())
            .path_and_query(service_path(&self.opts.service_name))
            .build()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/grpc")
            .header("user-agent", user_agent)
            .body(())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let (response, send) = sender.send_request(request, false).map_err(h2_io_error)?;
        let body = H2Body::new(send, Incoming::Response(response))
            .with_activity(transport.activity.clone())
            .on_drop(move || drop(guard));
        Ok(gun_framed(body))
    }
}

struct StreamCount(Arc<AtomicI64>);

impl Drop for StreamCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;
