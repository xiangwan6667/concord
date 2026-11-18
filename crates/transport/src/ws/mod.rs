mod disguise;
mod frame;
mod lazy;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use concord_common::layered::{Layered, ReadLayer, WriteLayer};
use concord_common::{BoxStream, Tasks};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::http1::{
    HeadReader, HeaderMap, ResponseHead, escape_path, percent_decode, query_escape, query_unescape,
};
pub(crate) use frame::WsStream;
pub(crate) use lazy::LazyWs;

#[derive(Clone, Debug, Default)]
pub struct WsOptions {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub max_early_data: usize,
    pub early_data_header_name: String,
    pub v2ray_http_upgrade: bool,
    pub v2ray_http_upgrade_fast_open: bool,
    /// Without a Host header, send mihomo's random CDN-like Host and browser User-Agent,
    /// as its vless does over plain websocket.
    pub random_host: bool,
}

struct Resolved {
    path: Vec<u8>,
    query: String,
    max_early_data: usize,
    early_header: String,
}

fn resolve(opts: &WsOptions) -> io::Result<Resolved> {
    let without_fragment = opts.path.split('#').next().unwrap_or_default();
    let (raw_path, raw_query) = match without_fragment.split_once('?') {
        Some((p, q)) => (p, q.to_string()),
        None => (without_fragment, String::new()),
    };
    let mut resolved = Resolved {
        path: percent_decode(raw_path)?,
        query: raw_query,
        max_early_data: opts.max_early_data,
        early_header: opts.early_data_header_name.clone(),
    };
    let pairs = parse_query(&resolved.query);
    let ed = pairs
        .iter()
        .find(|(k, _)| k == "ed")
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty());
    if let Some(ed) = ed.and_then(|v| v.parse::<i64>().ok()) {
        resolved.max_early_data = usize::try_from(ed).unwrap_or(0);
        resolved.early_header = "Sec-WebSocket-Protocol".to_string();
        let mut kept: Vec<(String, String)> =
            pairs.into_iter().filter(|(k, _)| k != "ed").collect();
        kept.sort_by(|a, b| a.0.cmp(&b.0));
        resolved.query = kept
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    query_escape(k.as_bytes()),
                    query_escape(v.as_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join("&");
    }
    if resolved.path.first() != Some(&b'/') {
        resolved.path.insert(0, b'/');
    }
    Ok(resolved)
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.contains(';'))
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = String::from_utf8_lossy(&query_unescape(k).ok()?).into_owned();
            let v = String::from_utf8_lossy(&query_unescape(v).ok()?).into_owned();
            Some((k, v))
        })
        .collect()
}

pub(crate) struct Request {
    pub bytes: Vec<u8>,
}

fn build_request(opts: &WsOptions, host: &str, early: Option<&[u8]>) -> io::Result<Request> {
    let resolved = resolve(opts)?;
    let mut headers = HeaderMap::default();
    for (key, value) in &opts.headers {
        headers.add(key, value);
    }
    headers.set("Connection", "Upgrade");
    headers.set("Upgrade", "websocket");
    let authority = match headers.get("Host") {
        Some(over) if !over.is_empty() => over.to_string(),
        _ if opts.random_host => {
            if headers.get("User-Agent").is_none_or(str::is_empty) {
                headers.set("User-Agent", disguise::user_agent());
            }
            disguise::host()
        }
        _ => host.to_string(),
    };
    headers.remove("Host");
    if !opts.v2ray_http_upgrade {
        let nonce: [u8; 16] = rand::random();
        headers.set("Sec-WebSocket-Version", "13");
        headers.set("Sec-WebSocket-Key", &STANDARD.encode(nonce));
    }
    let mut path = resolved.path;
    if let Some(data) = early {
        let encoded = URL_SAFE_NO_PAD.encode(data);
        if resolved.early_header.is_empty() {
            path.extend_from_slice(encoded.as_bytes());
        } else {
            headers.set(&resolved.early_header, &encoded);
        }
    }
    let mut uri = escape_path(&path);
    if !resolved.query.is_empty() {
        uri.push('?');
        uri.push_str(&resolved.query);
    }
    let user_agent = headers.get("User-Agent").unwrap_or("Go-http-client/1.1");
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(format!("GET {uri} HTTP/1.1\r\nHost: {authority}\r\n").as_bytes());
    if !user_agent.is_empty() {
        bytes.extend_from_slice(format!("User-Agent: {}\r\n", user_agent.trim()).as_bytes());
    }
    headers.write_sorted(
        &mut bytes,
        &[
            "Host",
            "User-Agent",
            "Content-Length",
            "Transfer-Encoding",
            "Trailer",
        ],
    );
    bytes.extend_from_slice(b"\r\n");
    Ok(Request { bytes })
}

fn check_upgrade(head: &ResponseHead) -> io::Result<()> {
    let token = |name: &str, want: &str| {
        head.header(name)
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(want)))
    };
    if head.status != 101 || !token("Connection", "upgrade") || !token("Upgrade", "websocket") {
        return Err(io::Error::other(format!(
            "unexpected status: {} {}",
            head.status, head.reason
        )));
    }
    Ok(())
}

pub(crate) async fn connect(
    mut io: BoxStream,
    opts: &WsOptions,
    host: &str,
    early: Option<&[u8]>,
) -> io::Result<BoxStream> {
    let request = build_request(opts, host, early)?;
    io.write_all(&request.bytes).await?;
    io.flush().await?;
    if opts.v2ray_http_upgrade && opts.v2ray_http_upgrade_fast_open {
        let read = UpgradeHead {
            head: Some(HeadReader::default()),
            rest: Vec::new(),
            rest_off: 0,
        };
        return Ok(Box::new(Layered::new(io, read, Passthrough)));
    }
    let mut reader = HeadReader::default();
    let head = reader.read_head(&mut io).await?;
    check_upgrade(&ResponseHead::parse(&head)?)?;
    let rest = reader.into_rest();
    if opts.v2ray_http_upgrade {
        return Ok(Box::new(concord_common::PeekedStream::new(rest, io)));
    }
    Ok(Box::new(WsStream::new(
        concord_common::PeekedStream::new(rest, io),
        true,
    )))
}

struct UpgradeHead {
    head: Option<HeadReader>,
    rest: Vec<u8>,
    rest_off: usize,
}

impl ReadLayer for UpgradeHead {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(reader) = self.head.as_mut() {
            let head = match reader.poll_head(cx, io) {
                Poll::Ready(Ok(head)) => head,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            };
            check_upgrade(&ResponseHead::parse(&head)?)?;
            self.rest = self
                .head
                .take()
                .map(HeadReader::into_rest)
                .unwrap_or_default();
        }
        if let Some(pending) = self.rest.get(self.rest_off..).filter(|p| !p.is_empty()) {
            let take = pending.len().min(buf.remaining());
            if let Some(chunk) = pending.get(..take) {
                buf.put_slice(chunk);
            }
            self.rest_off += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(io).poll_read(cx, buf)
    }
}

struct Passthrough;

impl WriteLayer for Passthrough {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(io).poll_write(cx, data)
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(io).poll_shutdown(cx)
    }
}

pub(crate) async fn apply(
    io: BoxStream,
    opts: &WsOptions,
    host: &str,
    tasks: &Tasks,
) -> io::Result<BoxStream> {
    let max = resolve(opts)?.max_early_data;
    if max > 0 {
        return Ok(Box::new(LazyWs::new(
            io,
            opts.clone(),
            host.to_string(),
            max,
            tasks.clone(),
        )));
    }
    connect(io, opts, host, None).await
}

#[cfg(test)]
mod tests;
