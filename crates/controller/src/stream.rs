//! The pushed routes: newline-separated JSON over a chunked response, or one JSON
//! text message per value over a WebSocket, as mihomo writes both.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use concord_api::{Control, ControlService, Delivery, EventStream};
use concord_proto::types::{
    ConnectionInfo, ConnectionWatchParams, Empty, LogLevel, LogWatchParams, Traffic,
    TrafficWatchParams,
};
use futures_util::stream::{self, BoxStream};
use futures_util::{SinkExt, StreamExt};
use http::header::{self, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};
use tokio_util::sync::CancellationToken;

use crate::http::{Body, is_websocket};
use crate::shapes;

pub type Values = BoxStream<'static, Value>;

/// mihomo's tickers for `/traffic`, `/memory` and the default `/connections` interval.
const TICK: Duration = Duration::from_secs(1);

/// Answers with `values` as a WebSocket when the request asks for one, otherwise
/// as a chunked JSON stream.
pub fn respond(
    request: Request<Incoming>,
    values: Values,
    stop: CancellationToken,
) -> Response<Body> {
    if !is_websocket(request.headers()) {
        let lines = values.map(|value| {
            let mut bytes = serde_json::to_vec(&value).unwrap_or_default();
            bytes.push(b'\n');
            Ok::<_, Infallible>(Frame::data(Bytes::from(bytes)))
        });
        let mut response = Response::new(StreamBody::new(lines).boxed_unsync());
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return response;
    }
    let Some(accept) = accept_key(&request) else {
        return crate::http::error(
            StatusCode::BAD_REQUEST,
            "handshake error: bad Sec-WebSocket-Key header",
        );
    };
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(request).await else {
            return;
        };
        let socket =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
        tokio::select! {
            () = pump(socket, values) => {}
            () = stop.cancelled() => {}
        }
    });
    let mut response = crate::http::empty(StatusCode::SWITCHING_PROTOCOLS);
    let headers = response.headers_mut();
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    if let Ok(value) = HeaderValue::from_str(&accept) {
        headers.insert(header::SEC_WEBSOCKET_ACCEPT, value);
    }
    response
}

fn accept_key(request: &Request<Incoming>) -> Option<String> {
    let headers = request.headers();
    let key = headers.get(header::SEC_WEBSOCKET_KEY)?;
    let version_ok = headers
        .get(header::SEC_WEBSOCKET_VERSION)
        .is_some_and(|version| version == "13");
    (key.len() == 24 && version_ok).then(|| derive_accept_key(key.as_bytes()))
}

/// Ends when the values end, the client closes, or a write fails.
async fn pump<S>(socket: WebSocketStream<S>, mut values: Values)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sink, mut incoming) = socket.split();
    loop {
        tokio::select! {
            value = values.next() => {
                let Some(value) = value else { break };
                let text = serde_json::to_string(&value).unwrap_or_default();
                if sink.send(Message::Text(text.into())).await.is_err() {
                    return;
                }
            }
            message = incoming.next() => match message {
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
    let _ = sink.close().await;
}

fn events<E: Send + 'static>(stream: EventStream<E>) -> BoxStream<'static, E> {
    stream
        .take_while(|delivery| std::future::ready(matches!(delivery, Delivery::Event { .. })))
        .filter_map(|delivery| async move {
            match delivery {
                Delivery::Event { data, .. } => Some(data),
                Delivery::Resync => None,
            }
        })
        .boxed()
}

fn traffic_value(traffic: &Traffic) -> Value {
    json!({
        "up": traffic.up,
        "down": traffic.down,
        "upTotal": traffic.total_up,
        "downTotal": traffic.total_down,
    })
}

pub async fn traffic(control: &Arc<Control>) -> Values {
    let params = TrafficWatchParams {
        interval_ms: Some(1000),
        ..Default::default()
    };
    match control.traffic_watch(params).await {
        Ok(subscription) => events(subscription.events)
            .map(|traffic| traffic_value(&traffic))
            .boxed(),
        Err(_) => stream::empty().boxed(),
    }
}

/// The first value is zero so a chart starts there (`server.go:440-446`).
pub fn memory(control: Arc<Control>) -> Values {
    let mut ticker = interval_at(Instant::now() + TICK, TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    stream::unfold(
        (control, ticker, true),
        |(control, mut ticker, first)| async move {
            ticker.tick().await;
            let inuse = if first {
                0
            } else {
                control
                    .core_stats(Empty {})
                    .await
                    .map_or(0, |stats| stats.rss)
            };
            Some((
                json!({ "inuse": inuse, "oslimit": 0 }),
                (control, ticker, false),
            ))
        },
    )
    .boxed()
}

pub async fn logs(control: &Arc<Control>, level: LogLevel, structured: bool) -> Values {
    let params = LogWatchParams {
        level: Some(level),
        ..Default::default()
    };
    match control.log_watch(params).await {
        Ok(subscription) => events(subscription.events)
            .filter(move |entry| {
                std::future::ready(level != LogLevel::Silent && entry.level >= level)
            })
            .map(move |entry| shapes::log(entry.level, entry.time, &entry.text, structured))
            .boxed(),
        Err(_) => stream::empty().boxed(),
    }
}

/// The connection table as a session sees it: a snapshot, then deltas applied
/// in order. A resync takes a fresh snapshot.
pub struct Table {
    control: Arc<Control>,
    open: BTreeMap<u64, ConnectionInfo>,
    deltas: Option<EventStream<concord_proto::types::ConnectionDelta>>,
}

impl Table {
    pub fn new(control: Arc<Control>) -> Self {
        Table {
            control,
            open: BTreeMap::new(),
            deltas: None,
        }
    }

    async fn subscribe(&mut self) {
        self.open.clear();
        self.deltas = None;
        let params = ConnectionWatchParams {
            counters: Some(true),
            ..Default::default()
        };
        if let Ok(subscription) = self.control.connection_watch(params).await {
            for info in subscription
                .snapshot
                .into_iter()
                .flat_map(|snapshot| snapshot.connections)
            {
                self.open.insert(info.id, info);
            }
            self.deltas = Some(subscription.events);
        }
    }

    /// Applies what has arrived without waiting for more.
    async fn catch_up(&mut self) {
        if self.deltas.is_none() {
            self.subscribe().await;
        }
        loop {
            let Some(deltas) = self.deltas.as_mut() else {
                return;
            };
            let Some(delivery) = futures_util::FutureExt::now_or_never(deltas.next()) else {
                return;
            };
            match delivery {
                Some(Delivery::Event { data, .. }) => {
                    for info in data.opened {
                        self.open.insert(info.id, info);
                    }
                    for id in data.closed {
                        self.open.remove(&id);
                    }
                    for counter in data.counters {
                        if let Some(info) = self.open.get_mut(&counter.id) {
                            info.upload = counter.upload;
                            info.download = counter.download;
                        }
                    }
                }
                Some(Delivery::Resync) | None => {
                    self.subscribe().await;
                    return;
                }
            }
        }
    }

    pub async fn snapshot(&mut self) -> Value {
        self.catch_up().await;
        let (upload, download) = totals(&self.control).await;
        let memory = self
            .control
            .core_stats(Empty {})
            .await
            .map_or(0, |stats| stats.rss);
        shapes::snapshot(self.open.values(), upload, download, memory)
    }
}

async fn totals(control: &Arc<Control>) -> (i64, i64) {
    match control.traffic_watch(TrafficWatchParams::default()).await {
        Ok(subscription) => subscription
            .snapshot
            .map_or((0, 0), |traffic| (traffic.total_up, traffic.total_down)),
        Err(_) => (0, 0),
    }
}

/// A snapshot now, then one every `period` (`connections.go:60-70`).
pub fn connections(control: Arc<Control>, period: Duration) -> Values {
    let mut ticker = interval_at(Instant::now(), period.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    stream::unfold(
        (Table::new(control), ticker),
        |(mut table, mut ticker)| async move {
            ticker.tick().await;
            let value = table.snapshot().await;
            Some((value, (table, ticker)))
        },
    )
    .boxed()
}
