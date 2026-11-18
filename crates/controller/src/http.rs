use std::convert::Infallible;

use bytes::Bytes;
use concord_api::ControllerCors;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use percent_encoding::percent_decode_str;
use serde::Serialize;
use serde_json::{Value, json};

pub type Body = UnsyncBoxBody<Bytes, Infallible>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).boxed_unsync()
}

pub fn empty(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(full(Bytes::new()));
    *response.status_mut() = status;
    response
}

pub fn json(value: &impl Serialize) -> Response<Body> {
    json_status(StatusCode::OK, value)
}

/// As chi's `render.JSON`: a trailing newline, as `json.Encoder` writes.
pub fn json_status(status: StatusCode, value: &impl Serialize) -> Response<Body> {
    let mut bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes.push(b'\n');
    let mut response = Response::new(full(bytes));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

pub fn error(status: StatusCode, message: &str) -> Response<Body> {
    json_status(status, &json!({ "message": message }))
}

pub fn bad_request() -> Response<Body> {
    error(StatusCode::BAD_REQUEST, "Body invalid")
}

pub fn not_found() -> Response<Body> {
    error(StatusCode::NOT_FOUND, "Resource not found")
}

pub fn unauthorized() -> Response<Body> {
    error(StatusCode::UNAUTHORIZED, "Unauthorized")
}

/// A route mihomo has and Concord deliberately leaves out.
pub fn unsupported() -> Response<Body> {
    error(StatusCode::NOT_IMPLEMENTED, "not supported by Concord")
}

/// The path as segments, each percent-decoded as chi's `getEscapeParam` does.
pub fn segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match percent_decode_str(segment).decode_utf8() {
            Ok(decoded) => decoded.into_owned(),
            Err(_) => segment.to_string(),
        })
        .collect()
}

pub fn query(uri: &http::Uri, key: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        (decode_component(name) == key).then(|| decode_component(value))
    })
}

fn decode_component(text: &str) -> String {
    let spaced = text.replace('+', " ");
    percent_decode_str(&spaced)
        .decode_utf8()
        .map_or_else(|_| spaced.clone(), |decoded| decoded.into_owned())
}

pub fn is_websocket(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "websocket")
}

pub fn parse_body(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes).ok()
}

/// Constant-time comparison, so the secret cannot be found byte by byte.
fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// mihomo's `authentication`: a browser WebSocket cannot set headers, so it may
/// pass the secret as `token`; everything else sends `Authorization: Bearer`.
pub fn authorized(secret: &str, headers: &HeaderMap, uri: &http::Uri) -> bool {
    if secret.is_empty() {
        return true;
    }
    if is_websocket(headers)
        && let Some(token) = query(uri, "token").filter(|token| !token.is_empty())
    {
        return same(&token, secret);
    }
    let header = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    match header.split_once(' ') {
        Some(("Bearer", token)) => same(token, secret),
        _ => false,
    }
}

const ALLOWED_METHODS: [&str; 6] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const ALLOWED_HEADERS: [&str; 3] = ["content-type", "authorization", "origin"];

pub fn is_preflight(method: &Method, headers: &HeaderMap) -> bool {
    method == Method::OPTIONS
        && headers.contains_key(header::ORIGIN)
        && headers
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .is_some_and(|value| !value.is_empty())
}

/// The origin the response names, as `metacubex/chi/cors`: `*` when every origin
/// is allowed, else the request's own; none when it is not allowed. An entry may
/// hold one `*`, and case does not count.
fn allowed_origin(cors: &ControllerCors, headers: &HeaderMap) -> Option<HeaderValue> {
    if cors.allow_origins.iter().any(|allowed| allowed == "*") {
        return Some(HeaderValue::from_static("*"));
    }
    let origin = headers.get(header::ORIGIN)?;
    let text = origin.to_str().ok()?.to_ascii_lowercase();
    cors.allow_origins
        .iter()
        .map(|allowed| allowed.to_ascii_lowercase())
        .any(|allowed| match allowed.split_once('*') {
            Some((prefix, suffix)) => {
                text.len() >= prefix.len() + suffix.len()
                    && text.starts_with(prefix)
                    && text.ends_with(suffix)
            }
            None => allowed == text,
        })
        .then(|| origin.clone())
}

/// mihomo's CORS: the allowed origins, private network when allowed, five
/// methods, two headers, five minutes.
pub fn preflight(headers: &HeaderMap, cors: &ControllerCors) -> Response<Body> {
    let mut response = empty(StatusCode::OK);
    let out = response.headers_mut();
    for vary in [
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
    ] {
        out.append(header::VARY, HeaderValue::from_static(vary));
    }
    let method = headers
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_uppercase();
    let Some(origin) = allowed_origin(cors, headers) else {
        return response;
    };
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return response;
    }
    let requested: Vec<String> = headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(',')
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    if !requested
        .iter()
        .all(|name| ALLOWED_HEADERS.contains(&name.as_str()))
    {
        return response;
    }
    out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    if let Ok(value) = HeaderValue::from_str(&method) {
        out.insert(header::ACCESS_CONTROL_ALLOW_METHODS, value);
    }
    if !requested.is_empty()
        && let Ok(value) = HeaderValue::from_str(&requested.join(", "))
    {
        out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value);
    }
    if cors.allow_private_network
        && headers
            .get("access-control-request-private-network")
            .is_some_and(|value| value == "true")
    {
        out.insert(
            "access-control-allow-private-network",
            HeaderValue::from_static("true"),
        );
    }
    out.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("300"),
    );
    response
}

/// The headers an actual request gets, whatever the route answers.
pub fn cors(
    request: &HeaderMap,
    method: &Method,
    cors: &ControllerCors,
    response: &mut Response<Body>,
) {
    let out = response.headers_mut();
    out.append(header::VARY, HeaderValue::from_static("Origin"));
    if request.contains_key(header::ORIGIN)
        && ALLOWED_METHODS.contains(&method.as_str())
        && let Some(origin) = allowed_origin(cors, request)
    {
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn a_secret_is_checked_by_bearer_or_by_token_on_a_websocket() {
        let uri: http::Uri = "/logs?token=s3".parse().unwrap();
        assert!(authorized("", &HeaderMap::new(), &uri));
        assert!(authorized(
            "s3",
            &headers(&[("authorization", "Bearer s3")]),
            &"/".parse().unwrap()
        ));
        assert!(!authorized(
            "s3",
            &headers(&[("authorization", "Bearer s4")]),
            &"/".parse().unwrap()
        ));
        assert!(!authorized(
            "s3",
            &headers(&[("authorization", "Basic s3")]),
            &"/".parse().unwrap()
        ));
        assert!(authorized(
            "s3",
            &headers(&[("upgrade", "websocket")]),
            &uri
        ));
        assert!(!authorized("s3", &HeaderMap::new(), &uri));
    }

    #[test]
    fn segments_and_queries_are_unescaped() {
        assert_eq!(
            segments("/proxies/%F0%9F%87%AF%F0%9F%87%B5%20JP/"),
            ["proxies", "🇯🇵 JP"]
        );
        let uri: http::Uri = "/x?url=http%3A%2F%2Fa%2Fb&timeout=500".parse().unwrap();
        assert_eq!(query(&uri, "url").as_deref(), Some("http://a/b"));
        assert_eq!(query(&uri, "timeout").as_deref(), Some("500"));
        assert_eq!(query(&uri, "none"), None);
    }

    #[test]
    fn a_preflight_answers_with_mihomos_defaults() {
        let request = headers(&[
            ("origin", "http://board"),
            ("access-control-request-method", "PATCH"),
            (
                "access-control-request-headers",
                "Authorization, Content-Type",
            ),
            ("access-control-request-private-network", "true"),
        ]);
        assert!(is_preflight(&Method::OPTIONS, &request));
        let response = preflight(&request, &ControllerCors::default());
        let out = response.headers();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(out["access-control-allow-origin"], "*");
        assert_eq!(out["access-control-allow-methods"], "PATCH");
        assert_eq!(
            out["access-control-allow-headers"],
            "authorization, content-type"
        );
        assert_eq!(out["access-control-allow-private-network"], "true");
        assert_eq!(out["access-control-max-age"], "300");
    }

    #[test]
    fn a_preflight_for_a_header_outside_the_list_gets_no_allowance() {
        let request = headers(&[
            ("origin", "http://board"),
            ("access-control-request-method", "GET"),
            ("access-control-request-headers", "x-custom"),
        ]);
        let response = preflight(&request, &ControllerCors::default());
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }

    #[test]
    fn only_the_listed_origins_are_allowed() {
        let listed = ControllerCors {
            allow_origins: vec!["https://Board.example".into(), "https://*.zash.test".into()],
            allow_private_network: false,
        };
        let asked = |origin: &'static str| {
            preflight(
                &headers(&[
                    ("origin", origin),
                    ("access-control-request-method", "GET"),
                    ("access-control-request-private-network", "true"),
                ]),
                &listed,
            )
        };
        for origin in ["https://board.example", "https://a.zash.test"] {
            let response = asked(origin);
            let out = response.headers();
            assert_eq!(out["access-control-allow-origin"], origin);
            assert!(!out.contains_key("access-control-allow-private-network"));
        }
        let refused = asked("https://evil.test");
        assert!(
            !refused
                .headers()
                .contains_key("access-control-allow-origin")
        );

        let mut actual = empty(StatusCode::OK);
        cors(
            &headers(&[("origin", "https://evil.test")]),
            &Method::GET,
            &listed,
            &mut actual,
        );
        assert!(!actual.headers().contains_key("access-control-allow-origin"));
        let mut actual = empty(StatusCode::OK);
        cors(
            &headers(&[("origin", "https://board.example")]),
            &Method::GET,
            &listed,
            &mut actual,
        );
        assert_eq!(
            actual.headers()["access-control-allow-origin"],
            "https://board.example"
        );

        let none = ControllerCors {
            allow_origins: Vec::new(),
            allow_private_network: false,
        };
        let mut actual = empty(StatusCode::OK);
        cors(
            &headers(&[("origin", "https://board.example")]),
            &Method::GET,
            &none,
            &mut actual,
        );
        assert!(!actual.headers().contains_key("access-control-allow-origin"));
    }
}
