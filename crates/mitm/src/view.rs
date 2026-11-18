//! How each line of the section reads once parsed, for a host that shows the lists; the
//! wire types are `concord-proto`'s `MitmLineView` and its parts.

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum LineView {
    UrlRewrite(UrlRewriteView),
    HeaderRewrite(HeaderRewriteView),
    BodyRewrite(BodyRewriteView),
    MapLocal(MapLocalView),
    Script(ScriptView),
    Hosts(HostsView),
    Sources(SourcesView),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Request,
    Response,
}

impl Phase {
    pub(crate) fn of(response: bool) -> Phase {
        if response {
            Phase::Response
        } else {
            Phase::Request
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlRewriteView {
    pub pattern: String,
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_head: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderRewriteView {
    pub phase: Phase,
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_head: Option<String>,
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyRewriteView {
    pub phase: Phase,
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_head: Option<String>,
    pub replacements: Vec<BodyReplacementView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BodyReplacementView {
    pub regex: String,
    pub replacement: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MapLocalView {
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_head: Option<String>,
    pub data_type: &'static str,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub headers: Vec<HeaderView>,
    pub content_type: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HeaderView {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptView {
    pub name: String,
    pub kind: ScriptViewKind,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cronexp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    pub requires_body: bool,
    pub binary_body: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<i64>,
    pub timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptViewKind {
    HttpRequest,
    HttpResponse,
    Cron,
    Event,
    Generic,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HostsView {
    pub entries: Vec<HostEntryView>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HostEntryView {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub exclude: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SourcesView {
    pub entries: Vec<SourceEntryView>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SourceEntryView {
    pub network: String,
    pub exclude: bool,
}
