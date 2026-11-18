use concord_config::mitm::MULTILINE;
use concord_config::mitm::text::canonical_header;
use http::header::HeaderMap;

use super::{BodyAction, BodyRewrite, HeaderEdit, HeaderRewrite, MapLocal, UrlRewrite};
use crate::heads::HeadConditions;
use crate::pattern::Pattern;
use crate::view::{
    BodyReplacementView, BodyRewriteView, HeaderRewriteView, HeaderView, LineView, MapLocalView,
    Phase, UrlRewriteView,
};

fn source(pattern: &Pattern) -> String {
    pattern.source().to_string()
}

impl HeadConditions {
    pub(crate) fn sources(&self) -> (Option<String>, Option<String>) {
        (
            self.request.as_ref().map(source),
            self.response.as_ref().map(source),
        )
    }
}

impl UrlRewrite {
    pub(crate) fn view(&self) -> LineView {
        LineView::UrlRewrite(UrlRewriteView {
            pattern: source(&self.pattern),
            action: self.action.name(),
            replacement: (!self.action.rejects()).then(|| self.replacement.clone()),
            request_head: self.head.as_ref().map(source),
        })
    }
}

impl HeaderRewrite {
    pub(crate) fn view(&self) -> LineView {
        let (request_head, response_head) = self.conditions.sources();
        let mut view = HeaderRewriteView {
            phase: Phase::of(self.response),
            pattern: source(&self.pattern),
            request_head,
            response_head,
            action: "",
            name: None,
            value: None,
            regex: None,
            replacement: None,
        };
        let value =
            |value: &http::HeaderValue| String::from_utf8_lossy(value.as_bytes()).into_owned();
        match &self.edit {
            HeaderEdit::Add(name, text) | HeaderEdit::Replace(name, text) => {
                view.action = if matches!(self.edit, HeaderEdit::Add(..)) {
                    "header-add"
                } else {
                    "header-replace"
                };
                view.name = Some(canonical_header(name.as_str()));
                view.value = Some(value(text));
            }
            HeaderEdit::Del(name) => {
                view.action = "header-del";
                view.name = Some(canonical_header(name.as_str()));
            }
            HeaderEdit::ReplaceRegex(name, regex, replacement) => {
                view.action = "header-replace-regex";
                view.name = Some(canonical_header(name.as_str()));
                view.regex = Some(source(regex));
                view.replacement = Some(replacement.clone());
            }
            HeaderEdit::Text(regex, replacement) => {
                view.action = "header-text-replace";
                view.regex = Some(source(regex));
                view.replacement = Some(replacement.clone());
            }
        }
        LineView::HeaderRewrite(view)
    }
}

impl BodyRewrite {
    pub(crate) fn view(&self) -> LineView {
        let (request_head, response_head) = self.conditions.sources();
        let (replacements, jq) = match &self.action {
            BodyAction::Replace(pairs) => (
                pairs
                    .iter()
                    .map(|pair| BodyReplacementView {
                        regex: pair
                            .pattern
                            .source()
                            .strip_prefix(MULTILINE)
                            .unwrap_or(pair.pattern.source())
                            .to_string(),
                        replacement: pair.with.clone(),
                    })
                    .collect(),
                None,
            ),
            BodyAction::Jq(jq) => (Vec::new(), Some(jq.code().to_string())),
        };
        LineView::BodyRewrite(BodyRewriteView {
            phase: Phase::of(self.response),
            pattern: source(&self.pattern),
            request_head,
            response_head,
            replacements,
            jq,
        })
    }
}

/// `data_type` and `data` as the line gave them; `header` holds the line's own headers, without
/// the content type the data implies.
pub(super) fn map_local_view(
    rule: &MapLocal,
    data_type: &'static str,
    data: &str,
    request: bool,
    header: &HeaderMap,
) -> LineView {
    let content_type = rule
        .header
        .get(http::header::CONTENT_TYPE)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .unwrap_or_default();
    LineView::MapLocal(MapLocalView {
        pattern: source(&rule.pattern),
        request_head: rule.conditions.request.as_ref().map(source),
        data_type,
        data: data.to_string(),
        status: (!request).then(|| rule.status.as_u16()),
        headers: header
            .iter()
            .map(|(name, value)| HeaderView {
                name: canonical_header(name.as_str()),
                value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
            })
            .collect(),
        content_type,
    })
}
