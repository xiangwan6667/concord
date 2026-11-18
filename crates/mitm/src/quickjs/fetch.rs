use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use concord_config::mitm::text::canonical_header;
use concord_tls::TrustStore;
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, HOST};
use http::{HeaderName, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::script::ScriptDial;

const MAX_REDIRECTS: usize = 10;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct Fetch {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, Vec<String>)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
    pub redirect: bool,
    pub insecure: bool,
}

pub(crate) struct Fetched {
    pub status: u16,
    pub headers: Vec<(String, Vec<String>)>,
    pub body: Vec<u8>,
}

pub(crate) struct Client {
    pub dial: Arc<dyn ScriptDial>,
    pub trust: Arc<TrustStore>,
    pub max_body: i64,
}

impl Client {
    pub async fn fetch(&self, request: Fetch) -> Result<Fetched, String> {
        let timeout = request.timeout;
        match tokio::time::timeout(timeout, self.follow(request)).await {
            Ok(result) => result,
            Err(_) => Err("the request timed out".to_string()),
        }
    }

    async fn follow(&self, request: Fetch) -> Result<Fetched, String> {
        let mut method =
            Method::from_bytes(request.method.as_bytes()).map_err(|err| err.to_string())?;
        let mut url =
            Url::parse(&request.url).map_err(|err| format!("{:?}: {err}", request.url))?;
        let mut body = request.body.clone();
        let mut headers = request.headers.clone();
        for hop in 0..=MAX_REDIRECTS {
            let fetched = self
                .once(&method, &url, &headers, body.as_deref(), request.insecure)
                .await?;
            let moved = matches!(fetched.status, 301 | 302 | 303 | 307 | 308);
            let location = fetched
                .headers
                .iter()
                .find(|(name, _)| name == "Location")
                .and_then(|(_, values)| values.first().cloned());
            let (true, true, Some(location)) = (request.redirect, moved, location) else {
                return Ok(fetched);
            };
            if hop == MAX_REDIRECTS {
                return Err(format!("stopped after {MAX_REDIRECTS} redirects"));
            }
            let next = url
                .join(&location)
                .map_err(|err| format!("{location:?}: {err}"))?;
            if matches!(fetched.status, 301..=303) && method != Method::HEAD {
                method = Method::GET;
                body = None;
                headers.retain(|(name, _)| !name.starts_with("Content-"));
            }
            if next.host_str() != url.host_str()
                || next.port_or_known_default() != url.port_or_known_default()
            {
                headers.retain(|(name, _)| {
                    !matches!(name.as_str(), "Authorization" | "Cookie" | "Host")
                });
            }
            url = next;
        }
        Err(format!("stopped after {MAX_REDIRECTS} redirects"))
    }

    async fn once(
        &self,
        method: &Method,
        url: &Url,
        headers: &[(String, Vec<String>)],
        body: Option<&[u8]>,
        insecure: bool,
    ) -> Result<Fetched, String> {
        let https = match url.scheme() {
            "http" => false,
            "https" => true,
            _ => return Err(format!("{:?} is not an http or https URL", url.as_str())),
        };
        let host = url
            .host_str()
            .ok_or_else(|| format!("{:?} has no host", url.as_str()))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = url
            .port_or_known_default()
            .unwrap_or(if https { 443 } else { 80 });
        let stream = self
            .dial
            .dial(host, port)
            .await
            .map_err(|err| err.to_string())?;
        if https {
            let config =
                concord_tls::http_client_config(self.trust.clone(), insecure, &["http/1.1"])
                    .map_err(|err| err.to_string())?;
            let name = ServerName::try_from(host.to_string()).map_err(|err| err.to_string())?;
            let tls = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                TlsConnector::from(config).connect(name, stream),
            )
            .await
            .map_err(|_| "the TLS handshake timed out".to_string())?
            .map_err(|err| err.to_string())?;
            self.talk(tls, method, url, headers, body).await
        } else {
            self.talk(stream, method, url, headers, body).await
        }
    }

    async fn talk<S>(
        &self,
        io: S,
        method: &Method,
        url: &Url,
        headers: &[(String, Vec<String>)],
        body: Option<&[u8]>,
    ) -> Result<Fetched, String>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) = http1::handshake(TokioIo::new(io))
            .await
            .map_err(|err| err.to_string())?;
        let driver = tokio::spawn(conn);
        let outcome = self.exchange(&mut sender, method, url, headers, body).await;
        driver.abort();
        outcome
    }

    async fn exchange(
        &self,
        sender: &mut http1::SendRequest<Full<Bytes>>,
        method: &Method,
        url: &Url,
        headers: &[(String, Vec<String>)],
        body: Option<&[u8]>,
    ) -> Result<Fetched, String> {
        let mut path = url.path().to_string();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        let mut request = Request::builder().method(method.clone()).uri(path);
        let mut has_host = false;
        let mut has_encoding = false;
        for (name, values) in headers {
            let Ok(header) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            has_host |= header == HOST;
            has_encoding |= header == ACCEPT_ENCODING;
            for value in values {
                if let Ok(value) = HeaderValue::from_str(value) {
                    request = request.header(header.clone(), value);
                }
            }
        }
        if !has_host {
            let authority = match url.port() {
                Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
                None => url.host_str().unwrap_or_default().to_string(),
            };
            request = request.header(HOST, authority);
        }
        if !has_encoding {
            request = request.header(ACCEPT_ENCODING, "gzip");
        }
        let data = Bytes::copy_from_slice(body.unwrap_or_default());
        let request = request
            .body(Full::new(data))
            .map_err(|err| err.to_string())?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|err| err.to_string())?;
        let (parts, mut incoming) = response.into_parts();
        let limit = usize::try_from(self.max_body).unwrap_or(0);
        let mut data = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|err| err.to_string())?;
            if let Ok(chunk) = frame.into_data() {
                data.extend_from_slice(&chunk);
                if data.len() > limit {
                    return Err(format!("the response is larger than {limit} bytes"));
                }
            }
        }
        let mut headers = parts.headers;
        if headers
            .get(CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"))
            && !has_encoding
        {
            let mut plain = Vec::new();
            let mut reader =
                flate2::read::MultiGzDecoder::new(data.as_slice()).take(limit as u64 + 1);
            reader
                .read_to_end(&mut plain)
                .map_err(|err| err.to_string())?;
            if plain.len() > limit {
                return Err(format!("the response is larger than {limit} bytes"));
            }
            data = plain;
            headers.remove(CONTENT_ENCODING);
            headers.remove(CONTENT_LENGTH);
        }
        Ok(Fetched {
            status: parts.status.as_u16(),
            headers: group(&headers),
            body: data,
        })
    }
}

fn group(headers: &http::HeaderMap) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for (name, value) in headers {
        let name = canonical_header(name.as_str());
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        match out.iter_mut().find(|(have, _)| *have == name) {
            Some((_, values)) => values.push(value),
            None => out.push((name, vec![value])),
        }
    }
    out
}
