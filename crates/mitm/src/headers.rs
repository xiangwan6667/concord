use concord_config::mitm::text::canonical_header;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{StatusCode, Version};

use crate::script::HeaderList;

pub(crate) fn to_list(map: &HeaderMap) -> HeaderList {
    let mut list = HeaderList::new();
    for (name, value) in map {
        list.entry(canonical_header(name.as_str()))
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    list
}

pub(crate) fn with_host(map: &HeaderMap, host: &str) -> HeaderList {
    let mut list = to_list(map);
    list.insert("Host".to_string(), vec![host.to_string()]);
    list
}

/// Names and values that cannot be put on the wire are left out.
pub(crate) fn from_list(list: &HeaderList) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, values) in list {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        for value in values {
            if let Ok(value) = HeaderValue::from_str(value) {
                map.append(name.clone(), value);
            }
        }
    }
    map
}

/// What frames the message is the body sent's to decide.
pub(crate) fn script_header(list: &HeaderList) -> HeaderMap {
    let mut map = from_list(list);
    for name in [
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
    ] {
        map.remove(name);
    }
    map
}

/// The head of a request as Quantumult X's `url-and-header` reads it: the request line, the
/// host, then every header as `Name: value`, each line ending in CRLF, and the blank line.
pub(crate) fn request_head(parts: &http::request::Parts, host: &str, version: &str) -> String {
    let target = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    head_text(
        &format!("{} {target} {version}", parts.method),
        host,
        &parts.headers,
    )
}

/// The head of a response in the same form: the status line, then every header.
pub(crate) fn response_head(status: StatusCode, version: &str, headers: &HeaderMap) -> String {
    let line = match status.canonical_reason() {
        Some(reason) => format!("{version} {} {reason}", status.as_u16()),
        None => format!("{version} {}", status.as_u16()),
    };
    head_text(&line, "", headers)
}

pub(crate) fn head_text(first_line: &str, host: &str, headers: &HeaderMap) -> String {
    let mut head = format!("{first_line}\r\n");
    if !host.is_empty() {
        head.push_str(&format!("Host: {host}\r\n"));
    }
    for (name, value) in headers {
        if name == http::header::HOST {
            continue;
        }
        head.push_str(&canonical_header(name.as_str()));
        head.push_str(": ");
        head.push_str(&String::from_utf8_lossy(value.as_bytes()));
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    head
}

/// A head [head_text] wrote and a rule then rewrote: its first line and its headers, or
/// nothing when a line is not `Name: value` or names what cannot be put on the wire.
pub(crate) fn parse_head(text: &str) -> Option<(String, HeaderMap)> {
    let mut lines = text.split("\r\n");
    let first = lines.next().filter(|line| !line.trim().is_empty())?;
    let mut headers = HeaderMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':')?;
        headers.append(
            HeaderName::from_bytes(name.trim().as_bytes()).ok()?,
            HeaderValue::from_str(value.trim()).ok()?,
        );
    }
    Some((first.to_string(), headers))
}

pub(crate) fn version_text(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

pub(crate) fn text(map: &HeaderMap, name: impl http::header::AsHeaderName) -> &str {
    map.get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

pub(crate) fn is_grpc(map: &HeaderMap) -> bool {
    text(map, http::header::CONTENT_TYPE)
        .to_ascii_lowercase()
        .starts_with("application/grpc")
}

const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

/// Removes the headers that describe one hop, as a reverse proxy does; `upgrade`
/// stays when the exchange is a protocol switch, and `te: trailers` for gRPC.
pub(crate) fn remove_hop_by_hop(map: &mut HeaderMap, keep_upgrade: bool) {
    let named: Vec<String> = map
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    let trailers = map
        .get_all(http::header::TE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("trailers"));
    for name in HOP_BY_HOP
        .iter()
        .copied()
        .chain(named.iter().map(String::as_str))
    {
        if keep_upgrade && name == "connection" {
            continue;
        }
        map.remove(name);
    }
    if !keep_upgrade {
        map.remove(http::header::UPGRADE);
    }
    if trailers {
        map.insert(http::header::TE, HeaderValue::from_static("trailers"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_reads_back_as_it_was_written() {
        let mut map = HeaderMap::new();
        map.append("cache-control", "max-age=60".parse().unwrap());
        map.append("set-cookie", "a=1".parse().unwrap());
        map.append("set-cookie", "b=2".parse().unwrap());
        let head = response_head(StatusCode::NOT_FOUND, "HTTP/1.1", &map);
        assert_eq!(
            head,
            "HTTP/1.1 404 Not Found\r\nCache-Control: max-age=60\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
        );
        let (line, read) = parse_head(&head).unwrap();
        assert_eq!((line.as_str(), read), ("HTTP/1.1 404 Not Found", map));
        assert!(parse_head("HTTP/1.1 200 OK\r\nNo colon\r\n\r\n").is_none());
        assert!(parse_head("HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n").is_none());
        assert!(parse_head("\r\n").is_none());
    }

    #[test]
    fn lists_use_canonical_names_and_keep_every_value() {
        let mut map = HeaderMap::new();
        map.append("set-cookie", "a=1".parse().unwrap());
        map.append("set-cookie", "b=2".parse().unwrap());
        map.append("x-mitm", "yes".parse().unwrap());
        let list = to_list(&map);
        assert_eq!(list["Set-Cookie"], ["a=1", "b=2"]);
        assert_eq!(list["X-Mitm"], ["yes"]);
        assert_eq!(from_list(&list).get_all("set-cookie").iter().count(), 2);
    }

    #[test]
    fn script_headers_drop_what_frames_the_message() {
        let list = HeaderList::from([
            ("Content-Length".to_string(), vec!["9".to_string()]),
            ("Connection".to_string(), vec!["close".to_string()]),
            ("X-A".to_string(), vec!["b".to_string()]),
        ]);
        let map = script_header(&list);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("x-a"));
    }

    #[test]
    fn hop_by_hop_headers_go_unless_the_exchange_upgrades() {
        let build = || {
            let mut map = HeaderMap::new();
            map.insert("connection", "keep-alive, x-private".parse().unwrap());
            map.insert("x-private", "1".parse().unwrap());
            map.insert("upgrade", "websocket".parse().unwrap());
            map.insert("te", "trailers".parse().unwrap());
            map.insert("x-keep", "1".parse().unwrap());
            map
        };
        let mut plain = build();
        remove_hop_by_hop(&mut plain, false);
        assert!(plain.contains_key("x-keep") && plain.contains_key("te"));
        assert!(
            !plain.contains_key("connection")
                && !plain.contains_key("x-private")
                && !plain.contains_key("upgrade")
        );
        let mut switching = build();
        remove_hop_by_hop(&mut switching, true);
        assert!(switching.contains_key("upgrade") && switching.contains_key("connection"));
    }
}
