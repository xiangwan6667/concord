use std::io;
use std::sync::Arc;

use bytes::Bytes;

use http::header::{
    ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use hyper::body::Incoming;
use hyper::upgrade::OnUpgrade;

use crate::body::{Body, Buffered, Tap, buffer_body, empty, failing, full};
use crate::capture::{PHASE_REQUEST, PHASE_RESPONSE};
use crate::exchange::{OutRequest, ReplyError, Sent, Target, has_response_body, set_length};
use crate::headers::{
    head_text, is_grpc, parse_head, remove_hop_by_hop, response_head, text, version_text, with_host,
};
use crate::heads::Heads;
use crate::limits::{BODY_WAIT, PRESSURE_NO_BODIES};
use crate::pattern::Pattern;
use crate::rules::BodyRewrite;
use crate::script::DEFAULT_SCRIPT_TIMEOUT;
use crate::session::{PoolKey, Sender, Session};
use crate::target::TargetUrl;
use http_body_util::BodyExt;

impl Session {
    /// Applies the rules to a request about to go upstream.
    pub(crate) async fn rewrite_request(
        self: &Arc<Self>,
        out: &mut OutRequest,
        target: &mut Target,
    ) {
        self.apply_request_rules(out, target).await;
        let cap = &target.cap;
        if !cap.is_some() {
            return;
        }
        cap.set_request_length(
            out.length
                .and_then(|length| i64::try_from(length).ok())
                .unwrap_or(-1),
        );
        if out.has_body {
            let kept = cap.clone();
            let body = std::mem::replace(&mut out.body, empty());
            out.body = Tap::new(
                body,
                Some(Box::new(move |data| kept.keep_request(data))),
                None,
            )
            .boxed_unsync();
        }
        cap.sent(&out.url.raw, with_host(&out.headers, &out.host_header()));
    }

    async fn apply_request_rules(self: &Arc<Self>, out: &mut OutRequest, target: &mut Target) {
        let rules = &self.core.config.rules;
        let max_body = self.core.config.limits.max_body_size;
        let address = out.url.raw.clone();
        let (header_rules, mock, body_rules, script) = {
            let request = || request_text(out, target.version);
            let heads = Heads::new(Some(&request), None);
            (
                rules.header_rewrites_for(&address, false, &heads),
                rules.request_mock(&address, &heads),
                rules.body_rewrites_for(&address, false, &heads),
                rules.script_for(&address, false, &heads),
            )
        };
        let mut rewritten = false;
        for rule in header_rules {
            rewritten |= match rule.whole_head() {
                Some((pattern, with)) => replace_request_head(out, target.version, pattern, with),
                None => rule.apply(&mut out.headers),
            };
        }
        if rewritten {
            target.cap.note("header-rewrite", PHASE_REQUEST, "");
            tracing::info!("[MITM] rewrite request headers of {address}");
        }
        if let Some(mock) = mock {
            mock_body(out, &mock.header, &mock.body);
            target.cap.note("request-body-mock", PHASE_REQUEST, "");
            tracing::info!("[MITM] mock the request body of {address}");
        }
        let grpc = is_grpc(&out.headers);
        if !body_rules.is_empty()
            && !grpc
            && out.has_body
            && self.core.shared.pressure.level() < PRESSURE_NO_BODIES
            && self
                .reserve_body(target, &address, &out.headers, out.length, max_body)
                .await
        {
            let body = std::mem::replace(&mut out.body, empty());
            match rewrite_body(&mut out.headers, body, out.length, max_body, body_rules).await {
                Ok((body, length)) => {
                    out.set_body(body, length);
                    target.cap.note("body-rewrite", PHASE_REQUEST, "");
                    tracing::info!("[MITM] rewrite request body of {address}");
                }
                Err(err) => {
                    out.body = failing(err);
                    return;
                }
            }
        }
        if let Some(script) = script {
            self.run_request_script(out, target, script).await;
        }
        if !grpc && self.rewrites_response_body(&out.url.raw) {
            out.headers
                .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        }
    }

    fn rewrites_response_body(&self, address: &str) -> bool {
        let rules = &self.core.config.rules;
        let heads = Heads::new(None, None);
        !rules.body_rewrites_for(address, true, &heads).is_empty()
            || rules
                .script_for(address, true, &heads)
                .is_some_and(|script| script.requires_body)
    }

    /// Makes room for a body about to be read whole: its length, or the size
    /// limit when that is unknown or the body is to be decoded. A body that finds
    /// none within a while passes on as it came.
    pub(crate) async fn reserve_body(
        &self,
        target: &mut Target,
        address: &str,
        headers: &HeaderMap,
        length: Option<u64>,
        limit: i64,
    ) -> bool {
        let cap = u64::try_from(limit).unwrap_or(0);
        if length.is_some_and(|length| length > cap) {
            return true;
        }
        let encoding = text(headers, CONTENT_ENCODING).trim().to_ascii_lowercase();
        let size = match length {
            Some(length) if encoding.is_empty() || encoding == "identity" => length,
            _ => cap,
        };
        if size == 0 {
            return true;
        }
        let permits = u32::try_from(size).unwrap_or(u32::MAX);
        let acquired = tokio::time::timeout(
            BODY_WAIT,
            self.core.bodies.clone().acquire_many_owned(permits),
        )
        .await;
        match acquired {
            Ok(Ok(permit)) => {
                target.reserved.push(permit);
                true
            }
            _ => {
                tracing::info!(
                    "[MITM] the body of {address} passes on as it came: the bodies being worked on fill the buffer"
                );
                false
            }
        }
    }

    pub(crate) async fn rewrite_response(
        self: &Arc<Self>,
        head: &mut http::response::Parts,
        body: &mut Body,
        sent: &Sent,
        target: &mut Target,
    ) -> Result<(), ReplyError> {
        let rules = &self.core.config.rules;
        let max_body = self.core.config.limits.max_body_size;
        let address = sent.url.raw.clone();
        let (header_rules, body_rules, script) = {
            let request = || {
                let line = format!(
                    "{} {} {}",
                    sent.method, sent.url.path_and_query, target.version
                );
                head_text(&line, &sent.host, &sent.headers)
            };
            let response = || response_head(head.status, version_text(head.version), &head.headers);
            let heads = Heads::new(Some(&request), Some(&response));
            (
                rules.header_rewrites_for(&address, true, &heads),
                rules.body_rewrites_for(&address, true, &heads),
                rules.script_for(&address, true, &heads),
            )
        };
        let mut rewritten = false;
        for rule in header_rules {
            rewritten |= match rule.whole_head() {
                Some((pattern, with)) => replace_response_head(head, pattern, with),
                None => rule.apply(&mut head.headers),
            };
        }
        if rewritten {
            target.cap.note("header-rewrite", PHASE_RESPONSE, "");
            tracing::info!("[MITM] rewrite response headers of {address}");
        }
        if head.status == StatusCode::SWITCHING_PROTOCOLS {
            return Ok(());
        }
        let length = hyper::body::Body::size_hint(body).exact();
        if !body_rules.is_empty()
            && has_response_body(&sent.method, head.status)
            && !is_grpc(&head.headers)
            && self.core.shared.pressure.level() < PRESSURE_NO_BODIES
            && self
                .reserve_body(target, &address, &head.headers, length, max_body)
                .await
        {
            let source = std::mem::replace(body, empty());
            let (rewritten, length) =
                rewrite_body(&mut head.headers, source, length, max_body, body_rules).await?;
            *body = rewritten;
            set_length(&mut head.headers, length);
            target.cap.note("body-rewrite", PHASE_RESPONSE, "");
            tracing::info!("[MITM] rewrite response body of {address}");
        }
        if let Some(script) = script {
            self.run_response_script(head, body, sent, target, script)
                .await?;
        }
        Ok(())
    }

    /// Sends the request to its server on a connection from the pool, a fresh
    /// one if a reused one turns out to be gone.
    pub(crate) async fn round_trip(
        &self,
        out: OutRequest,
        target: &Target,
    ) -> io::Result<(Response<Incoming>, Option<OnUpgrade>)> {
        let key = PoolKey {
            https: out.url.https,
            host: out.url.host.to_ascii_lowercase(),
            port: out.url.port,
        };
        let cap = &target.cap;
        let authority = out.host_header();
        let path = out.url.path_and_query.clone();
        let https = out.url.https;
        let mut request = build_request(out, target.http1)?;
        let mut attempt = 0;
        loop {
            let (mut conn, reused) = self.connection_for(&key, target.http1, cap).await?;
            adapt(&mut request, conn.is_h2(), https, &authority, &path)?;
            let sent = match &mut conn.sender {
                Sender::H1(sender) => sender.try_send_request(request).await,
                Sender::H2(sender) => {
                    sender.ready().await.map_err(io::Error::other)?;
                    sender.try_send_request(request).await
                }
            };
            match sent {
                Ok(mut response) => {
                    let upgrade = (response.status() == StatusCode::SWITCHING_PROTOCOLS)
                        .then(|| hyper::upgrade::on(&mut response));
                    if upgrade.is_none() {
                        self.give_back(&key, conn);
                    }
                    return Ok((response, upgrade));
                }
                Err(mut err) => match err.take_message() {
                    Some(returned) if reused && attempt == 0 => {
                        request = returned;
                        attempt += 1;
                    }
                    _ => return Err(io::Error::other(err.into_error())),
                },
            }
        }
    }
}

/// Sends `body` in place of the request's own, a request that had none included.
fn mock_body(out: &mut OutRequest, header: &HeaderMap, body: &[u8]) {
    for name in header.keys() {
        out.headers.remove(name);
    }
    for (name, value) in header {
        out.headers.append(name.clone(), value.clone());
    }
    out.headers.remove(CONTENT_ENCODING);
    out.headers.remove(TRANSFER_ENCODING);
    out.set_body(
        full(Bytes::copy_from_slice(body)),
        u64::try_from(body.len()).ok(),
    );
    out.has_body = true;
}

fn request_text(out: &OutRequest, version: &str) -> String {
    let line = format!("{} {} {version}", out.method, out.url.path_and_query);
    head_text(&line, &out.host_header(), &out.headers)
}

/// The rewritten request line moves the request to another method and path on the same
/// host, which a `Host` line cannot change: one that names another host is put back.
fn replace_request_head(
    out: &mut OutRequest,
    version: &str,
    pattern: &Pattern,
    with: &str,
) -> bool {
    let Some((line, mut headers)) = rewritten_head(&request_text(out, version), pattern, with)
    else {
        return false;
    };
    let mut words = line.split(' ');
    let method = words
        .next()
        .and_then(|word| Method::from_bytes(word.as_bytes()).ok());
    let url = words
        .next()
        .filter(|path| path.starts_with('/'))
        .and_then(|path| TargetUrl::from_request(out.url.https, &out.url.authority, path));
    let (Some(method), Some(url)) = (method, url) else {
        tracing::debug!("[MITM] the rewritten request line {line:?} is not one; the head is kept");
        return false;
    };
    let host = out.host_header();
    if let Some(named) = headers.remove(HOST)
        && named.as_bytes() != host.as_bytes()
    {
        tracing::debug!(
            "[MITM] a head rewrite named the host {named:?}; the request keeps going to {host}"
        );
    }
    keep_framing(&out.headers, &mut headers);
    out.method = method;
    out.url = url;
    out.headers = headers;
    true
}

fn replace_response_head(head: &mut http::response::Parts, pattern: &Pattern, with: &str) -> bool {
    let text = response_head(head.status, version_text(head.version), &head.headers);
    let Some((line, mut headers)) = rewritten_head(&text, pattern, with) else {
        return false;
    };
    let Some(status) = line
        .split(' ')
        .nth(1)
        .and_then(|code| StatusCode::from_bytes(code.as_bytes()).ok())
    else {
        tracing::debug!("[MITM] the rewritten status line {line:?} is not one; the head is kept");
        return false;
    };
    keep_framing(&head.headers, &mut headers);
    head.status = status;
    head.headers = headers;
    true
}

/// `None` when the rule changes nothing or leaves what is not a head.
fn rewritten_head(text: &str, pattern: &Pattern, with: &str) -> Option<(String, HeaderMap)> {
    let replaced = pattern
        .replace(text, with, true)
        .filter(|replaced| replaced != text)?;
    let parsed = parse_head(&replaced);
    if parsed.is_none() {
        tracing::debug!("[MITM] a head rewrite gave {replaced:?}, which is not a head; it is kept");
    }
    parsed
}

/// What frames the message stays the body's, as a header rewrite cannot change it.
fn keep_framing(from: &HeaderMap, to: &mut HeaderMap) {
    for name in [CONTENT_LENGTH, TRANSFER_ENCODING] {
        to.remove(&name);
        for value in from.get_all(&name) {
            to.append(name.clone(), value.clone());
        }
    }
}

/// A request with an absolute URI and a `Host` header, which `adapt` fits to the
/// connection it goes out on.
fn build_request(out: OutRequest, upgrading: bool) -> io::Result<Request<Body>> {
    let mut headers = out.headers;
    let upgrade_type = text(&headers, UPGRADE).to_string();
    remove_hop_by_hop(&mut headers, false);
    if upgrading && !upgrade_type.is_empty() {
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        if let Ok(value) = HeaderValue::from_str(&upgrade_type) {
            headers.insert(UPGRADE, value);
        }
    }
    let mut request = Request::new(out.body);
    *request.method_mut() = out.method;
    *request.headers_mut() = headers;
    Ok(request)
}

fn adapt(
    request: &mut Request<Body>,
    h2: bool,
    https: bool,
    authority: &str,
    path: &str,
) -> io::Result<()> {
    let headers = request.headers_mut();
    let uri = if h2 {
        headers.remove(HOST);
        Uri::builder()
            .scheme(if https { "https" } else { "http" })
            .authority(authority)
            .path_and_query(path)
            .build()
    } else {
        let host = HeaderValue::from_str(authority).map_err(io::Error::other)?;
        headers.insert(HOST, host);
        path.parse::<Uri>().map_err(Into::into)
    }
    .map_err(io::Error::other)?;
    *request.uri_mut() = uri;
    *request.version_mut() = if h2 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    Ok(())
}

/// A body over the limit, not UTF-8, or in an encoding it cannot decode is
/// passed on unchanged.
pub(crate) async fn rewrite_body(
    headers: &mut HeaderMap,
    body: Body,
    length: Option<u64>,
    limit: i64,
    rules: Vec<Arc<BodyRewrite>>,
) -> io::Result<(Body, Option<u64>)> {
    match buffer_body(headers, body, length, limit).await? {
        Buffered::Rest { body, length } => Ok((body, length)),
        Buffered::Whole(data) => {
            let data = apply_off_runtime(Bytes::from(data), rules, DEFAULT_SCRIPT_TIMEOUT).await;
            let length = data.len() as u64;
            Ok((full(data), Some(length)))
        }
    }
}

/// Rewrites run on the blocking pool, as a jq filter may run for long or never end. One that
/// outlives `budget` leaves the body as it came; its thread runs on until the filter returns.
pub(crate) async fn apply_off_runtime(
    data: Bytes,
    rules: Vec<Arc<BodyRewrite>>,
    budget: std::time::Duration,
) -> Bytes {
    let input = data.clone();
    let work = tokio::task::spawn_blocking(move || {
        let text = std::str::from_utf8(&input).ok()?.to_owned();
        Some(rules.iter().fold(text, |text, rule| rule.apply(text)))
    });
    match tokio::time::timeout(budget, work).await {
        Ok(Ok(Some(text))) => Bytes::from(text),
        Ok(Ok(None)) => data,
        Ok(Err(err)) => {
            tracing::warn!("[MITM] a body rewrite failed: {err}");
            data
        }
        Err(_) => {
            tracing::warn!(
                "[MITM] a body rewrite ran past {budget:?}, the body passes on as it came"
            );
            data
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse_body_rewrite;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    fn rules(lines: &[&str]) -> Vec<Arc<BodyRewrite>> {
        lines
            .iter()
            .map(|line| Arc::new(parse_body_rewrite(line).unwrap()))
            .collect()
    }

    const SLOW: &str =
        r"http-response-jq ^http:// '.n = (reduce range(3000000) as $i (0; . + $i))'";

    #[tokio::test]
    async fn a_long_rewrite_leaves_the_runtime_free() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let ticker = tokio::spawn({
            let ticks = ticks.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        let started = Instant::now();
        let out = apply_off_runtime(
            Bytes::from_static(b"{}"),
            rules(&[SLOW]),
            Duration::from_secs(600),
        )
        .await;
        ticker.abort();
        assert_eq!(&out[..], br#"{"n":4499998500000}"#);
        assert!(
            ticks.load(Ordering::Relaxed) > 0,
            "the ticker on the same thread never ran in {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_rewrite_past_its_budget_keeps_the_body() {
        let out = apply_off_runtime(
            Bytes::from_static(b"{}"),
            rules(&[SLOW]),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(&out[..], b"{}");
        let out = apply_off_runtime(
            Bytes::from_static(b"{\"ad\":1}"),
            rules(&[
                r"http-response ^http:// ad noad",
                "http-response-jq ^http:// '.x = 1'",
            ]),
            Duration::from_secs(600),
        )
        .await;
        assert_eq!(&out[..], br#"{"noad":1,"x":1}"#);
        let raw = Bytes::from_static(&[0xff, 0xfe]);
        assert_eq!(
            apply_off_runtime(raw.clone(), rules(&[SLOW]), Duration::from_secs(600)).await,
            raw
        );
    }

    #[test]
    fn a_request_adapts_to_http1_and_http2() {
        let mut out = http::Request::new(empty());
        *out.method_mut() = http::Method::GET;
        adapt(&mut out, true, true, "example.test:8443", "/p?q=1").unwrap();
        assert_eq!(out.uri().to_string(), "https://example.test:8443/p?q=1");
        assert!(out.headers().get(HOST).is_none());
        adapt(&mut out, false, true, "example.test:8443", "/p?q=1").unwrap();
        assert_eq!(out.uri().to_string(), "/p?q=1");
        assert_eq!(out.headers().get(HOST).unwrap(), "example.test:8443");
        assert_eq!(out.version(), Version::HTTP_11);
    }
}
