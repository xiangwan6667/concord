use serde_json::{Value, json};

use crate::Map;

const TEXT_FIELDS: &[(&str, &str)] = &[
    ("xPaddingBytes", "x-padding-bytes"),
    ("xPaddingKey", "x-padding-key"),
    ("xPaddingHeader", "x-padding-header"),
    ("xPaddingPlacement", "x-padding-placement"),
    ("xPaddingMethod", "x-padding-method"),
    ("uplinkHTTPMethod", "uplink-http-method"),
    ("sessionIDPlacement", "session-placement"),
    ("sessionIDKey", "session-key"),
    ("sessionIDTable", "session-table"),
    ("seqPlacement", "seq-placement"),
    ("seqKey", "seq-key"),
    ("uplinkDataPlacement", "uplink-data-placement"),
    ("uplinkDataKey", "uplink-data-key"),
];

const NUMBER_FIELDS: &[(&str, &str)] = &[
    ("uplinkChunkSize", "uplink-chunk-size"),
    ("scMaxEachPostBytes", "sc-max-each-post-bytes"),
    ("scMinPostsIntervalMs", "sc-min-posts-interval-ms"),
];

fn non_empty(extra: &Map, key: &str) -> Option<String> {
    match extra.get(key) {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

fn whole(value: &Value) -> Option<i64> {
    value.as_f64().map(|f| f as i64)
}

fn reuse(xmux: &Map) -> Map {
    let mut out = Map::new();
    for (src, dst) in [
        ("maxConnections", "max-connections"),
        ("maxConcurrency", "max-concurrency"),
        ("cMaxReuseTimes", "c-max-reuse-times"),
        ("hMaxRequestTimes", "h-max-request-times"),
        ("hMaxReusableSecs", "h-max-reusable-secs"),
    ] {
        match xmux.get(src) {
            Some(Value::String(text)) if !text.is_empty() => {
                out.insert(dst.into(), json!(text));
            }
            Some(number @ Value::Number(_)) => {
                if let Some(n) = whole(number) {
                    out.insert(dst.into(), json!(n.to_string()));
                }
            }
            _ => {}
        }
    }
    if let Some(n) = xmux.get("hKeepAlivePeriod").and_then(whole) {
        out.insert("h-keep-alive-period".into(), json!(n));
    }
    out
}

pub fn apply_extra(extra: &Map, opts: &mut Map) {
    if let Some(Value::Object(headers)) = extra
        .get("headers")
        .filter(|v| v.as_object().is_some_and(|m| !m.is_empty()))
    {
        opts.insert("headers".into(), Value::Object(headers.clone()));
    }
    if extra.get("noGRPCHeader") == Some(&Value::Bool(true)) {
        opts.insert("no-grpc-header".into(), Value::Bool(true));
    }
    if let Some(Value::Bool(mode)) = extra.get("xPaddingObfsMode") {
        opts.insert("x-padding-obfs-mode".into(), Value::Bool(*mode));
    }
    for (src, dst) in TEXT_FIELDS {
        let value = non_empty(extra, src).or_else(|| match *src {
            "sessionIDPlacement" => non_empty(extra, "sessionPlacement"),
            "sessionIDKey" => non_empty(extra, "sessionKey"),
            _ => None,
        });
        if let Some(value) = value {
            opts.insert((*dst).into(), json!(value));
        }
    }
    match extra.get("sessionIDLength") {
        Some(Value::String(text)) if !text.is_empty() => {
            opts.insert("session-length".into(), json!(text));
        }
        Some(number @ Value::Number(_)) => {
            if let Some(n) = whole(number) {
                opts.insert("session-length".into(), json!(n.to_string()));
            }
        }
        _ => {}
    }
    for (src, dst) in NUMBER_FIELDS {
        if let Some(n) = extra.get(*src).filter(|v| v.is_number()).and_then(whole) {
            opts.insert((*dst).into(), json!(n));
        }
    }
    if let Some(Value::Object(xmux)) = extra.get("xmux") {
        let reuse = reuse(xmux);
        if !reuse.is_empty() {
            opts.insert("reuse-settings".into(), Value::Object(reuse));
        }
    }
    if let Some(Value::Object(settings)) = extra.get("downloadSettings") {
        let mut download = Map::new();
        if let Some(address) = non_empty(settings, "address") {
            download.insert("server".into(), json!(address));
        }
        if let Some(port) = settings.get("port").and_then(whole) {
            download.insert("port".into(), json!(port));
        }
        if let Some(Value::Object(xhttp)) = settings.get("xhttpSettings") {
            for key in ["path", "host"] {
                if let Some(value) = non_empty(xhttp, key) {
                    download.insert(key.into(), json!(value));
                }
            }
        }
        if settings.get("security").and_then(Value::as_str) == Some("reality")
            && let Some(Value::Object(reality)) = settings.get("realitySettings")
        {
            download.insert("tls".into(), json!(true));
            let mut auth = Map::new();
            if let Some(key) =
                non_empty(reality, "publicKey").or_else(|| non_empty(reality, "password"))
            {
                auth.insert("public-key".into(), json!(key));
            }
            for (source, target) in [("shortId", "short-id"), ("mldsa65Verify", "mldsa65-verify")] {
                if let Some(value) = non_empty(reality, source) {
                    auth.insert(target.into(), json!(value));
                }
            }
            for (source, target) in [
                ("serverName", "servername"),
                ("fingerprint", "client-fingerprint"),
            ] {
                if let Some(value) = non_empty(reality, source) {
                    download.insert(target.into(), json!(value));
                }
            }
            if !auth.is_empty() {
                download.insert("reality-opts".into(), Value::Object(auth));
            }
        }
        if !download.is_empty() {
            opts.insert("download-settings".into(), Value::Object(download));
        }
    }
}
