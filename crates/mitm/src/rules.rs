use std::path::{Component, Path};

use concord_config::mitm::text::{decode_base64, quote};
use concord_config::mitm::{
    BodyActionDef, BodyRewriteDef, HeaderEditDef, HeaderRewriteDef, LineError, MapLocalBody,
    MapLocalDef, UrlRewriteDef,
};
use http::StatusCode;
use http::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};

use crate::heads::{HeadConditions, Heads};
use crate::jq::{Jq, JqOutcome};
use crate::pattern::Pattern;
use crate::script::{Script, ScriptKind};
use crate::view::LineView;

pub(crate) use concord_config::mitm::UrlAction;

mod views;

const TINY_GIF_BASE64: &str = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

#[derive(Debug)]
pub struct UrlRewrite {
    pattern: Pattern,
    /// Quantumult X's `url-and-header`: matched against the request head once the URL matches.
    head: Option<Pattern>,
    pub replacement: String,
    pub action: UrlAction,
}

#[derive(Debug)]
enum HeaderEdit {
    Add(HeaderName, HeaderValue),
    Del(HeaderName),
    Replace(HeaderName, HeaderValue),
    ReplaceRegex(HeaderName, Pattern, String),
    /// Quantumult X's `request-header` and `response-header`: a replacement over the whole
    /// head, its first line included.
    Text(Pattern, String),
}

#[derive(Debug)]
pub struct HeaderRewrite {
    response: bool,
    pattern: Pattern,
    conditions: HeadConditions,
    edit: HeaderEdit,
}

#[derive(Debug)]
struct BodyReplacement {
    pattern: Pattern,
    with: String,
}

#[derive(Debug)]
enum BodyAction {
    Replace(Vec<BodyReplacement>),
    Jq(Jq),
}

#[derive(Debug)]
pub struct BodyRewrite {
    response: bool,
    pattern: Pattern,
    conditions: HeadConditions,
    action: BodyAction,
}

#[derive(Debug)]
pub struct MapLocal {
    pattern: Pattern,
    conditions: HeadConditions,
    pub status: StatusCode,
    pub header: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Rules {
    pub(crate) url_rewrites: Vec<UrlRewrite>,
    pub(crate) header_rewrites: Vec<HeaderRewrite>,
    pub(crate) body_rewrites: Vec<std::sync::Arc<BodyRewrite>>,
    pub(crate) map_locals: Vec<MapLocal>,
    /// Loon's `mock-request-body`: bodies a request goes upstream with instead of its own.
    pub(crate) request_mocks: Vec<MapLocal>,
    pub(crate) scripts: Vec<std::sync::Arc<Script>>,
}

pub fn tiny_gif() -> Vec<u8> {
    decode_base64(TINY_GIF_BASE64).unwrap_or_default()
}

pub(crate) fn compile_url_rewrite(def: &UrlRewriteDef) -> Result<UrlRewrite, LineError> {
    Ok(UrlRewrite {
        pattern: Pattern::new(&def.pattern)?,
        head: def.head.as_deref().map(Pattern::new).transpose()?,
        replacement: def.replacement.clone(),
        action: def.action,
    })
}

pub(crate) fn compile_header_rewrite(def: &HeaderRewriteDef) -> Result<HeaderRewrite, LineError> {
    let edit = match &def.edit {
        HeaderEditDef::Add(name, value) => HeaderEdit::Add(name.clone(), value.clone()),
        HeaderEditDef::Del(name) => HeaderEdit::Del(name.clone()),
        HeaderEditDef::Replace(name, value) => HeaderEdit::Replace(name.clone(), value.clone()),
        HeaderEditDef::ReplaceRegex(name, pattern, with) => {
            HeaderEdit::ReplaceRegex(name.clone(), Pattern::new(pattern)?, with.clone())
        }
        HeaderEditDef::Text(pattern, with) => {
            HeaderEdit::Text(Pattern::new(pattern)?, with.clone())
        }
    };
    Ok(HeaderRewrite {
        response: def.response,
        pattern: Pattern::new(&def.pattern)?,
        conditions: HeadConditions::compile(&def.conditions)?,
        edit,
    })
}

impl HeaderRewrite {
    /// The pattern and replacement of a rule that rewrites the whole head, which its caller
    /// applies as only it knows the first line.
    pub(crate) fn whole_head(&self) -> Option<(&Pattern, &str)> {
        match &self.edit {
            HeaderEdit::Text(pattern, replacement) => Some((pattern, replacement)),
            _ => None,
        }
    }

    pub(crate) fn apply(&self, header: &mut HeaderMap) -> bool {
        match &self.edit {
            HeaderEdit::Add(name, value) => {
                header.append(name.clone(), value.clone());
            }
            HeaderEdit::Del(name) => return header.remove(name).is_some(),
            HeaderEdit::Replace(name, value) => {
                if !header.contains_key(name) {
                    return false;
                }
                header.insert(name.clone(), value.clone());
            }
            HeaderEdit::ReplaceRegex(name, regex, replacement) => {
                if !header.contains_key(name) {
                    return false;
                }
                let values: Vec<HeaderValue> = header
                    .get_all(name)
                    .iter()
                    .map(|value| {
                        value
                            .to_str()
                            .ok()
                            .and_then(|text| regex.replace(text, replacement, true))
                            .and_then(|text| HeaderValue::from_str(&text).ok())
                            .unwrap_or_else(|| value.clone())
                    })
                    .collect();
                header.remove(name);
                for value in values {
                    header.append(name.clone(), value);
                }
            }
            HeaderEdit::Text(..) => return false,
        }
        true
    }
}

pub(crate) fn compile_body_rewrite(def: &BodyRewriteDef) -> Result<BodyRewrite, LineError> {
    let action = match &def.action {
        BodyActionDef::Replace(pairs) => BodyAction::Replace(
            pairs
                .iter()
                .map(|(pattern, with)| {
                    Ok(BodyReplacement {
                        pattern: Pattern::multiline(pattern)?,
                        with: with.clone(),
                    })
                })
                .collect::<Result<_, LineError>>()?,
        ),
        BodyActionDef::Jq(expression) => BodyAction::Jq(Jq::compile(expression)?),
    };
    Ok(BodyRewrite {
        response: def.response,
        pattern: Pattern::new(&def.pattern)?,
        conditions: HeadConditions::compile(&def.conditions)?,
        action,
    })
}

impl BodyRewrite {
    pub(crate) fn apply(&self, body: String) -> String {
        match &self.action {
            BodyAction::Replace(replacements) => {
                replacements.iter().fold(body, |body, replacement| {
                    replacement
                        .pattern
                        .replace(&body, &replacement.with, true)
                        .unwrap_or(body)
                })
            }
            BodyAction::Jq(jq) => match jq.run(&body) {
                JqOutcome::Rewritten(rewritten) => rewritten,
                JqOutcome::NotJson => {
                    tracing::debug!("[MITM] jq rewrite skipped: the body is not JSON");
                    body
                }
                JqOutcome::Empty => body,
                JqOutcome::Failed(err) => {
                    tracing::warn!("[MITM] jq rewrite failed: {err}");
                    body
                }
            },
        }
    }
}

fn is_local(name: &str) -> bool {
    if name.is_empty() || name.contains('\\') {
        return false;
    }
    let mut depth: i32 = 0;
    for component in Path::new(name).components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::CurDir => {}
            _ => return false,
        }
    }
    true
}

pub(crate) fn read_resource(dir: &Path, param: &str, name: &str) -> Result<Vec<u8>, LineError> {
    if !is_local(name) {
        return Err(LineError::resource(format!(
            "{param} {} is not a file in the resources directory",
            quote(name)
        )));
    }
    let path = dir.join(name);
    let info = std::fs::symlink_metadata(&path).map_err(|err| {
        let reason = match err.kind() {
            std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
            std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
            _ => "cannot be read".to_string(),
        };
        LineError::resource(format!("{param} {}: {reason}", quote(name)))
    })?;
    if !info.file_type().is_file() {
        return Err(LineError::resource(format!(
            "{param} {} is not a regular file",
            quote(name)
        )));
    }
    std::fs::read(&path)
        .map_err(|_| LineError::resource(format!("{param} {} cannot be read", quote(name))))
}

/// A `map-local` or `request-body-mock` line's rule, its body read from the resources
/// directory when the line names a file.
pub(crate) fn compile_map_local(
    def: &MapLocalDef,
    resources: &Path,
) -> Result<(MapLocal, LineView), LineError> {
    let body = match &def.body {
        MapLocalBody::Text => def.data.as_bytes().to_vec(),
        MapLocalBody::TinyGif => tiny_gif(),
        MapLocalBody::Base64(bytes) => bytes.clone(),
        MapLocalBody::File => read_resource(resources, "data", &def.data)?,
    };
    let mut header = def.header.clone();
    if !header.contains_key(CONTENT_TYPE) {
        header.insert(CONTENT_TYPE, HeaderValue::from_static(def.content_type));
    }
    let rule = MapLocal {
        pattern: Pattern::new(&def.pattern)?,
        conditions: HeadConditions::compile(&def.conditions)?,
        status: def.status,
        header,
        body,
    };
    let data = match def.body {
        MapLocalBody::TinyGif => "",
        _ => &def.data,
    };
    let view = views::map_local_view(&rule, def.body.data_type(), data, def.request, &def.header);
    Ok((rule, view))
}

#[cfg(test)]
pub(crate) fn parse_url_rewrite(line: &str) -> Result<UrlRewrite, LineError> {
    compile_url_rewrite(&concord_config::mitm::parse_url_rewrite(line)?)
}

#[cfg(test)]
pub(crate) fn parse_header_rewrite(line: &str) -> Result<HeaderRewrite, LineError> {
    compile_header_rewrite(&concord_config::mitm::parse_header_rewrite(line)?)
}

#[cfg(test)]
pub(crate) fn parse_body_rewrite(line: &str) -> Result<BodyRewrite, LineError> {
    compile_body_rewrite(&concord_config::mitm::parse_body_rewrite(line)?)
}

#[cfg(test)]
pub(crate) fn parse_map_local(
    line: &str,
    resources: &Path,
    request: bool,
) -> Result<(MapLocal, LineView), LineError> {
    compile_map_local(
        &concord_config::mitm::parse_map_local(line, request)?,
        resources,
    )
}

fn first_local<'r>(rules: &'r [MapLocal], url: &str, heads: &Heads<'_>) -> Option<&'r MapLocal> {
    rules
        .iter()
        .find(|rule| rule.pattern.is_match(url) && heads.allow(&rule.conditions))
}

impl Rules {
    pub(crate) fn acts_on_requests(&self) -> bool {
        !self.url_rewrites.is_empty()
            || !self.header_rewrites.is_empty()
            || !self.body_rewrites.is_empty()
            || !self.map_locals.is_empty()
            || !self.request_mocks.is_empty()
            || self.scripts.iter().any(|script| {
                matches!(
                    script.kind,
                    ScriptKind::HttpRequest | ScriptKind::HttpResponse
                )
            })
    }

    pub(crate) fn rewrite_url(
        &self,
        url: &str,
        heads: &Heads<'_>,
    ) -> Option<(&UrlRewrite, String)> {
        for rule in &self.url_rewrites {
            if !rule.pattern.is_match(url) || !heads.request_allows(rule.head.as_ref()) {
                continue;
            }
            if rule.action.rejects() {
                return Some((rule, String::new()));
            }
            let replaced = rule.pattern.replace(url, &rule.replacement, false)?;
            return Some((rule, replaced));
        }
        None
    }

    pub(crate) fn map_local(&self, url: &str, heads: &Heads<'_>) -> Option<&MapLocal> {
        first_local(&self.map_locals, url, heads)
    }

    pub(crate) fn request_mock(&self, url: &str, heads: &Heads<'_>) -> Option<&MapLocal> {
        first_local(&self.request_mocks, url, heads)
    }

    /// The header rewrites for an exchange, picked before any of them runs so that each
    /// condition reads the head as the phase began.
    pub(crate) fn header_rewrites_for(
        &self,
        url: &str,
        response: bool,
        heads: &Heads<'_>,
    ) -> Vec<&HeaderRewrite> {
        self.header_rewrites
            .iter()
            .filter(|rule| rule.response == response && rule.pattern.is_match(url))
            .filter(|rule| heads.allow(&rule.conditions))
            .collect()
    }

    pub(crate) fn body_rewrites_for(
        &self,
        url: &str,
        response: bool,
        heads: &Heads<'_>,
    ) -> Vec<std::sync::Arc<BodyRewrite>> {
        self.body_rewrites
            .iter()
            .filter(|rule| rule.response == response && rule.pattern.is_match(url))
            .filter(|rule| heads.allow(&rule.conditions))
            .cloned()
            .collect()
    }

    /// The first script whose URL and conditions match; one whose conditions do not
    /// leaves the turn to the next.
    pub(crate) fn script_for(
        &self,
        url: &str,
        response: bool,
        heads: &Heads<'_>,
    ) -> Option<&std::sync::Arc<Script>> {
        self.scripts
            .iter()
            .find(|script| script.matches_http(url, response) && heads.allow(&script.conditions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(line: &str) -> (UrlAction, String) {
        let rule = parse_url_rewrite(line).unwrap_or_else(|err| panic!("{line}: {err}"));
        (rule.action, rule.replacement)
    }

    #[test]
    fn url_rewrite_reads_surge_loon_and_quantumult_x() {
        let cases = [
            (r"^https?://ad\.com/ _ reject", UrlAction::Reject, ""),
            (r"^https?://ad\.com/ reject-dict", UrlAction::RejectDict, ""),
            (
                r"^https?://ad\.com/ url reject-img",
                UrlAction::RejectImg,
                "",
            ),
            (
                r"^https?://ad\.com/ url 302 https://b.com/",
                UrlAction::Redirect302,
                "https://b.com/",
            ),
            (
                r"^https?://ad\.com/ 302 https://b.com/",
                UrlAction::Redirect302,
                "https://b.com/",
            ),
            (
                r"^http://a\.com/(.*) http://b.com/$1 307",
                UrlAction::Redirect307,
                "http://b.com/$1",
            ),
            (
                r"^http://a\.com http://b.com",
                UrlAction::Header,
                "http://b.com",
            ),
            (
                r"^http://a\.com http://b.com header",
                UrlAction::Header,
                "http://b.com",
            ),
        ];
        for (line, action, replacement) in cases {
            assert_eq!(rewrite(line), (action, replacement.to_string()), "{line}");
        }
    }

    #[test]
    fn url_rewrite_rejects_bad_lines() {
        for line in [
            "^a",
            "^a b c d",
            "^a b nope",
            "^a _ 302",
            "(unclosed b",
            "^a \"b",
        ] {
            assert!(parse_url_rewrite(line).is_err(), "{line}");
        }
    }

    fn rewrite_with<'r>(
        rules: &'r Rules,
        url: &str,
        head: impl Fn() -> String,
    ) -> Option<(&'r UrlRewrite, String)> {
        rules.rewrite_url(url, &Heads::new(Some(&head), None))
    }

    fn local(line: &str, resources: &Path) -> Result<MapLocal, LineError> {
        parse_map_local(line, resources, false).map(|(rule, _)| rule)
    }

    fn rules_with(urls: &[&str]) -> Rules {
        let mut rules = Rules::default();
        for line in urls {
            rules.url_rewrites.push(parse_url_rewrite(line).unwrap());
        }
        rules
    }

    #[test]
    fn rewrite_url_replaces_the_match_and_stops_at_the_first_rule() {
        let rules = rules_with(&[
            r"^http://www\.google\.cn http://www.google.com",
            r"^http://www\.google\.cn _ reject",
            r"^https://a\.com/(\w+)/(\d+) https://b.com/$2/$1 302",
        ]);
        let (rule, replaced) =
            rewrite_with(&rules, "http://www.google.cn/search?q=x", String::new).unwrap();
        assert_eq!(rule.action, UrlAction::Header);
        assert_eq!(replaced, "http://www.google.com/search?q=x");
        let (_, replaced) = rewrite_with(&rules, "https://a.com/item/42", String::new).unwrap();
        assert_eq!(replaced, "https://b.com/42/item");
        assert!(rewrite_with(&rules, "https://c.com/", String::new).is_none());
    }

    #[test]
    fn url_and_header_checks_the_head_after_the_url() {
        let rules = rules_with(&[
            r"^http:\/\/.+\/amdc\/mobileDispatch %E8%8F%9C%E9%B8%9F%E8%A3%B9%E8%A3%B9* url-and-header reject",
            r#"^http://example\.com/resource1/1/ "\r\nUser-Agent: example-agent" url-and-header reject-dict"#,
            r"^http://example\.com/resource1/1/ ^POST url-and-header 302 http://example.com/post",
        ]);
        let head = |method: &str, agent: &str| {
            let text = format!(
                "{method} /amdc/mobileDispatch HTTP/1.1\r\nHost: a.test\r\nUser-Agent: {agent}\r\n\r\n"
            );
            move || text.clone()
        };
        let cainiao = "%E8%8F%9C%E9%B8%9F%E8%A3%B9%E8%A3%B9/8.8.1 CFNetwork/1410";
        let (rule, _) = rewrite_with(
            &rules,
            "http://1.2.3.4/amdc/mobileDispatch",
            head("GET", cainiao),
        )
        .unwrap();
        assert_eq!(rule.action, UrlAction::Reject);
        assert!(
            rewrite_with(
                &rules,
                "http://1.2.3.4/amdc/mobileDispatch",
                head("GET", "Other/1")
            )
            .is_none()
        );
        let url = "http://example.com/resource1/1/x";
        let (rule, _) = rewrite_with(&rules, url, head("GET", "example-agent")).unwrap();
        assert_eq!(rule.action, UrlAction::RejectDict);
        let (rule, replaced) = rewrite_with(&rules, url, head("POST", "curl")).unwrap();
        assert_eq!(
            (rule.action, replaced.as_str()),
            (UrlAction::Redirect302, "http://example.com/postx")
        );
        assert!(rewrite_with(&rules, url, head("GET", "curl")).is_none());
        let unbuilt = || -> String { panic!("the head is built only after the URL matches") };
        assert!(rewrite_with(&rules, "https://other.test/", unbuilt).is_none());
        for line in [r"^a ^POST url-and-header", r"^a (bad url-and-header reject"] {
            assert!(parse_url_rewrite(line).is_err(), "{line}");
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn header_rewrite_actions() {
        let lines = [
            r"http-request ^https://a\.com header-add X-Added one",
            r"^https://a\.com header-add User-Agent Mozilla/5.0 (iPhone; CPU OS 18_0)",
            r"http-request ^https://a\.com header-del Cookie",
            r"http-request ^https://a\.com header-replace Accept text/html",
            r"http-request ^https://a\.com header-replace Missing value",
            r"http-request ^https://a\.com header-replace-regex Referer http https",
            r"http-response ^https://a\.com header-del Set-Cookie",
        ];
        let mut rules = Rules::default();
        for line in lines {
            rules
                .header_rewrites
                .push(parse_header_rewrite(line).unwrap_or_else(|e| panic!("{line}: {e}")));
        }
        let mut header = headers(&[
            ("cookie", "a=b"),
            ("accept", "*/*"),
            ("referer", "http://a.com/x"),
            ("set-cookie", "c=d"),
        ]);
        let picked = rules.header_rewrites_for("https://a.com/", false, &Heads::new(None, None));
        assert_eq!(
            picked
                .into_iter()
                .filter(|rule| rule.apply(&mut header))
                .count(),
            5
        );
        let get = |name: &str| {
            header
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        assert_eq!(get("x-added").as_deref(), Some("one"));
        assert_eq!(
            get("user-agent").as_deref(),
            Some("Mozilla/5.0 (iPhone; CPU OS 18_0)")
        );
        assert_eq!(get("accept").as_deref(), Some("text/html"));
        assert_eq!(get("referer").as_deref(), Some("https://a.com/x"));
        assert_eq!(get("set-cookie").as_deref(), Some("c=d"));
        assert_eq!(get("cookie"), None);
        assert_eq!(header.len(), 5);
    }

    #[test]
    fn head_conditions_read_each_head_once_and_only_past_the_url() {
        let lines = [
            r"http-response ^https://a\.com/ response-head ^HTTP/\S+\s200\s request-head ^POST\s header-add X-A 1",
            r"http-response ^https://a\.com/ request-head ^POST\s header-add X-B 1",
            r"http-response ^https://b\.com/ request-head ^GET header-add X-C 1",
            r"http-response ^https://a\.com/ header-del X-D",
        ];
        let mut rules = Rules::default();
        for line in lines {
            rules
                .header_rewrites
                .push(parse_header_rewrite(line).unwrap_or_else(|e| panic!("{line}: {e}")));
        }
        let built = std::cell::Cell::new(0);
        let picked = |request: &str, response: &str| {
            let request = || {
                built.set(built.get() + 1);
                request.to_string()
            };
            let response = || response.to_string();
            rules
                .header_rewrites_for(
                    "https://a.com/x",
                    true,
                    &Heads::new(Some(&request), Some(&response)),
                )
                .len()
        };
        assert_eq!(
            picked("POST /x HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"),
            3
        );
        assert_eq!(
            built.get(),
            1,
            "two conditions on the request head read it once"
        );
        assert_eq!(
            picked("POST /x HTTP/1.1\r\n\r\n", "HTTP/2.0 404 Not Found\r\n\r\n"),
            2
        );
        assert_eq!(
            picked("GET /x HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"),
            1
        );
        assert_eq!(
            rules
                .header_rewrites_for("https://a.com/x", true, &Heads::new(None, None))
                .len(),
            3,
            "a head not known yet lets its condition pass"
        );
        built.set(0);
        let request = || {
            built.set(built.get() + 1);
            String::new()
        };
        rules.header_rewrites_for("https://c.com/", true, &Heads::new(Some(&request), None));
        assert_eq!(
            built.get(),
            0,
            "no rule matched the URL, so no head is written"
        );
    }

    #[test]
    fn head_conditions_and_whole_head_rewrites_parse() {
        let rule = parse_header_rewrite(
            r#"^https://a\.com/ header-text-replace "(\r\n)User-Agent:[^\r]*(\r\n)" "$1User-Agent: app$2""#,
        )
        .unwrap();
        assert!(rule.whole_head().is_some());
        assert!(!rule.apply(&mut HeaderMap::new()));
        for line in [
            r"http-request ^a response-head x header-add X 1",
            r"http-response ^a request-head",
            r"http-response ^a request-head a request-head b header-del X",
            r"http-response ^a request-head ( header-del X",
            r"^a header-text-replace only",
            r"^a header-text-replace a b c",
        ] {
            assert!(parse_header_rewrite(line).is_err(), "{line}");
        }
        let body = parse_body_rewrite(r"http-response ^a request-head ^POST\s a b").unwrap();
        assert!(body.conditions.request.is_some());
        let jq = parse_body_rewrite(
            r#"http-response-jq ^a response-head "^HTTP/\S+ 200 " request-head ^POST '.ad = false'"#,
        )
        .unwrap();
        assert!(jq.conditions.response.is_some() && jq.conditions.request.is_some());
        assert_eq!(jq.apply(r#"{"ad":true}"#.to_string()), r#"{"ad":false}"#);
        for line in [
            r"http-request ^a response-head x a b",
            r"http-response ^a request-head x",
            r"http-request-jq ^a response-head x '.a'",
        ] {
            assert!(parse_body_rewrite(line).is_err(), "{line}");
        }
    }

    #[test]
    fn local_answers_read_a_request_head_condition() {
        let nowhere = Path::new("/nonexistent-resources");
        let mut rules = Rules::default();
        rules.map_locals.push(
            local(
                r#"^https://a\.com/ request-head ^POST\s data-type=text data="{}""#,
                nowhere,
            )
            .unwrap(),
        );
        let post = || "POST / HTTP/1.1\r\n\r\n".to_string();
        let get = || "GET / HTTP/1.1\r\n\r\n".to_string();
        assert!(
            rules
                .map_local("https://a.com/", &Heads::new(Some(&post), None))
                .is_some()
        );
        assert!(
            rules
                .map_local("https://a.com/", &Heads::new(Some(&get), None))
                .is_none()
        );
        for line in [
            r"^a response-head x data-type=text data=x",
            r"^a request-head x",
        ] {
            assert!(local(line, nowhere).is_err(), "{line}");
        }
        assert!(
            parse_map_local(r"^a data-type=text data=x status-code=500", nowhere, true).is_err()
        );
        assert!(parse_map_local(r"^a data-type=text data=x", nowhere, true).is_ok());
    }

    #[test]
    fn header_rewrite_keeps_framing_headers() {
        for line in [
            r"^https://a\.com header-del Content-Length",
            r"http-response ^https://a\.com header-replace transfer-encoding chunked",
        ] {
            assert!(parse_header_rewrite(line).is_err(), "{line}");
        }
    }

    #[test]
    fn body_rewrite_chains_pairs() {
        let rule = parse_body_rewrite(
            r#"http-response ^https://a\.com "\"ad\":true" "\"ad\":false" ^line$ replaced"#,
        )
        .unwrap();
        let got = rule.apply("{\"ad\":true}\nline\nkeep line".to_string());
        assert_eq!(got, "{\"ad\":false}\nreplaced\nkeep line");
        for line in [
            "http-response ^a only",
            "http-response-jq ^a '.a ='",
            "http-response-jq ^a",
            "sideways ^a b c",
        ] {
            assert!(parse_body_rewrite(line).is_err(), "{line}");
        }
    }

    #[test]
    fn map_local_parameters() {
        let nowhere = Path::new("/nonexistent-resources");
        let rule = local(
            r#"^https://a\.com/json data-type=text data="{\"ok\":1}" status-code=500 header="Content-Type:application/json|X-A:b""#,
            nowhere,
        )
        .unwrap();
        assert_eq!(rule.body, br#"{"ok":1}"#);
        assert_eq!(rule.status.as_u16(), 500);
        assert_eq!(rule.header.get("content-type").unwrap(), "application/json");
        assert_eq!(rule.header.get("x-a").unwrap(), "b");
        let gif = local(r"^https://a\.com/gif data-type=tiny-gif", nowhere).unwrap();
        assert_eq!(gif.header.get("content-type").unwrap(), "image/gif");
        assert!(!gif.body.is_empty());
        let encoded = local(
            r#"^https://a\.com/b data-type=base64 data="dGVzdA==" header=WC1COiBj"#,
            nowhere,
        )
        .unwrap();
        assert_eq!(encoded.body, b"test");
        assert_eq!(encoded.header.get("x-b").unwrap(), "c");
        for line in [
            r#"^https://a\.com/x data="missing.json""#,
            r"^https://a\.com/x data-type=text status-code=99",
            r"^https://a\.com/x data-type=base64 data=%%%",
            r"^https://a\.com/x novalue",
        ] {
            assert!(local(line, nowhere).is_err(), "{line}");
        }
    }

    #[test]
    fn map_local_serves_files_from_the_resources_directory_only() {
        let home = tempfile::tempdir().unwrap();
        let resources = home.path().join("resources");
        std::fs::create_dir_all(resources.join("sub")).unwrap();
        std::fs::write(resources.join("a.json"), br#"{"ok":1}"#).unwrap();
        std::fs::write(resources.join("sub/b"), b"raw").unwrap();
        std::fs::write(home.path().join("secret.txt"), b"secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(home.path().join("secret.txt"), resources.join("link.txt"))
            .unwrap();

        let rule = local(r#"^https://a\.com/x data="a.json""#, &resources).unwrap();
        assert_eq!(rule.body, br#"{"ok":1}"#);
        assert_eq!(rule.header.get("content-type").unwrap(), "application/json");
        let rule = local(
            r#"^https://a\.com/x data-type=file data="sub/b" header="Content-Type:text/x""#,
            &resources,
        )
        .unwrap();
        assert_eq!(rule.body, b"raw");
        assert_eq!(rule.header.get("content-type").unwrap(), "text/x");

        let secret = home.path().join("secret.txt").display().to_string();
        for data in [
            "../secret.txt",
            "sub/../../secret.txt",
            &secret,
            r"sub\b",
            "link.txt",
            "sub",
            "",
        ] {
            let line = format!(r#"^https://a\.com/x data-type=file data="{data}""#);
            let err = local(&line, &resources).expect_err(data);
            assert!(
                !err.message.contains(&resources.display().to_string()),
                "{data}: {err}"
            );
            assert_eq!(
                err.kind,
                concord_config::mitm::IssueKind::Resource,
                "{data}"
            );
        }
    }
}
