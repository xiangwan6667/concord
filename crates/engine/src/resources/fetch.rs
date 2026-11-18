use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use concord_common::{CoreError, CoreOptions};
use concord_group::http::{HttpError, Target, TlsSettings, connect};
use concord_group::{FetchError, FetchErrorKind, FetchRequest, FetchResponse, Fetcher};
use concord_tls::TrustStore;
use concord_tunnel::Tunnel;
use tokio::time::Instant;

use crate::error::ResourceError;

const MAX_REDIRECTS: usize = 10;

/// Everything the core downloads goes through the tunnel as an inner flow, so a
/// provider can name the proxy it is fetched through.
pub(crate) struct TunnelFetcher {
    pub tunnel: Tunnel,
    pub trust: ArcSwap<TrustStore>,
    pub options: Arc<ArcSwap<CoreOptions>>,
    pub user_agent: ArcSwap<String>,
}

fn fetch_error(kind: FetchErrorKind, message: impl Into<String>) -> FetchError {
    FetchError {
        kind,
        message: message.into(),
    }
}

fn dial_error(err: &std::io::Error) -> FetchError {
    let kind = match (CoreError::of(err), err.kind()) {
        (Some(CoreError::IpNotFound(_)), _) => FetchErrorKind::Dns,
        (_, std::io::ErrorKind::TimedOut) => FetchErrorKind::Timeout,
        _ => FetchErrorKind::Connection,
    };
    fetch_error(kind, err.to_string())
}

fn http_error(err: HttpError) -> FetchError {
    let kind = match &err {
        HttpError::Tls(_) => FetchErrorKind::Tls,
        HttpError::Protocol(_) => FetchErrorKind::Connection,
        HttpError::Url(_) => FetchErrorKind::Other,
    };
    fetch_error(kind, err.to_string())
}

#[async_trait]
impl Fetcher for TunnelFetcher {
    async fn get(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let deadline = Instant::now() + request.timeout;
        let mut url = request.url.clone();
        let mut headers = request.headers.clone();
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        {
            headers.push(("User-Agent".to_string(), self.user_agent.load().to_string()));
        }
        let limit = request
            .size_limit
            .and_then(|limit| usize::try_from(limit).ok())
            .unwrap_or(usize::MAX);
        let tls = TlsSettings {
            trust: self.trust.load_full(),
            skip_cert_verify: self.options.load().skip_cert_verify,
            offer_h2: true,
        };
        for _ in 0..MAX_REDIRECTS {
            let target = Target::parse(&url).map_err(http_error)?;
            let exchange = async {
                let stream = self
                    .tunnel
                    .dial_inner(&target.address(), request.via_proxy.as_deref())
                    .await
                    .map_err(|err| dial_error(&err))?;
                let mut connection = connect(stream, &target, &tls).await.map_err(http_error)?;
                connection
                    .send(http::Method::GET, &headers, Bytes::new(), limit)
                    .await
                    .map_err(http_error)
            };
            let response = tokio::time::timeout_at(deadline, exchange)
                .await
                .map_err(|_| fetch_error(FetchErrorKind::Timeout, "context deadline exceeded"))??;
            if response.status / 100 == 3
                && let Some(location) = response
                    .headers
                    .get(http::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
            {
                url = url::Url::parse(&url)
                    .and_then(|base| base.join(location))
                    .map_err(|err| fetch_error(FetchErrorKind::Other, err.to_string()))?
                    .to_string();
                continue;
            }
            return Ok(FetchResponse {
                status: response.status,
                headers: response
                    .headers
                    .iter()
                    .filter_map(|(name, value)| {
                        Some((name.to_string(), value.to_str().ok()?.to_string()))
                    })
                    .collect(),
                body: response.body.to_vec(),
            });
        }
        Err(fetch_error(
            FetchErrorKind::Other,
            format!("stopped after {MAX_REDIRECTS} redirects"),
        ))
    }
}

/// A plain GET that treats anything but 2xx as a failure, as `HTTPVehicle.Read` does.
pub(crate) async fn download(
    fetcher: &dyn Fetcher,
    request: FetchRequest,
) -> Result<Vec<u8>, ResourceError> {
    let response = fetcher.get(request).await.map_err(ResourceError::Fetch)?;
    if !(200..=299).contains(&response.status) {
        return Err(ResourceError::Status(response.status));
    }
    Ok(response.body)
}

pub(super) fn touch(path: &Path) {
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(SystemTime::now()));
}
