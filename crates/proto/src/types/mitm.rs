use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

dto! {
    /// A line of a list that cannot be read, or of whose items some cannot. `index` is
    /// the line's place in its list, blank lines and comments counted.
    pub struct MitmIssue {
        pub index: u32,
        pub kind: MitmIssueKind,
        pub message: String,
    }

    pub struct MitmLineEntry {
        pub index: u32,
        pub view: MitmLineView,
    }

    pub struct MitmUrlRewrite {
        pub pattern: String,
        pub action: MitmUrlAction,
        /// Absent for the reject actions.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub replacement: Option<String>,
        /// The request-head pattern of Quantumult X's `url-and-header`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request_head: Option<String>,
    }

    pub struct MitmHeaderRewrite {
        pub phase: MitmPhase,
        pub pattern: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request_head: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub response_head: Option<String>,
        pub action: MitmHeaderAction,
        /// In canonical case; absent for `header-text-replace`, which rewrites the whole head.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub regex: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub replacement: Option<String>,
    }

    pub struct MitmBodyRewrite {
        pub phase: MitmPhase,
        pub pattern: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request_head: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub response_head: Option<String>,
        pub replacements: Vec<MitmBodyReplacement>,
        /// The expression as compiled, without the quotes around it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jq: Option<String>,
    }

    pub struct MitmBodyReplacement {
        pub regex: String,
        pub replacement: String,
    }

    pub struct MitmMapLocal {
        pub pattern: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request_head: Option<String>,
        pub data_type: MitmDataType,
        /// The `data` parameter as written: a file name, text or base64; empty for `tiny-gif`.
        pub data: String,
        /// Present for `map-local` only, 200 unless the line sets it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<u16>,
        pub headers: Vec<MitmHeader>,
        pub content_type: String,
    }

    pub struct MitmHeader {
        pub name: String,
        pub value: String,
    }

    pub struct MitmScript {
        /// The name `mitm.runScript` takes; the file name when the line gives none.
        pub name: String,
        pub kind: MitmScriptKind,
        pub path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pattern: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request_head: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub response_head: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cronexp: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event: Option<String>,
        pub requires_body: bool,
        pub binary_body: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_size: Option<i64>,
        /// The timeout in force, capped as the core caps it.
        pub timeout_ms: u64,
    }

    /// The entries of a line in force, without those that could not be read.
    pub struct MitmHosts {
        pub entries: Vec<MitmHostEntry>,
    }

    pub struct MitmHostEntry {
        /// Lower case, without a trailing dot or IPv6 brackets; may hold `*` and `?`.
        pub host: String,
        /// Absent when the entry names none, which covers 443 and 80.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub port: Option<u16>,
        pub exclude: bool,
    }

    /// The entries of a line in force: those before the first that could not be read.
    pub struct MitmSources {
        pub entries: Vec<MitmSourceEntry>,
    }

    pub struct MitmSourceEntry {
        /// A CIDR; a single address has its full prefix length.
        pub network: String,
        pub exclude: bool,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MitmIssueKind {
    Syntax,
    Missing,
    Unknown,
    Unsupported,
    Invalid,
    Pattern,
    Jq,
    Resource,
    Script,
}

/// One per list: `url-rewrite`, `header-rewrite`, `body-rewrite`, `map-local` (also
/// `request-body-mock`), `script`, `hosts` (`hostname` and
/// `skip-server-cert-verify-hostname`) and `sources` (`client-source-address`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum MitmLineView {
    UrlRewrite(MitmUrlRewrite),
    HeaderRewrite(MitmHeaderRewrite),
    BodyRewrite(MitmBodyRewrite),
    MapLocal(MitmMapLocal),
    Script(MitmScript),
    Hosts(MitmHosts),
    Sources(MitmSources),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum MitmUrlAction {
    #[serde(rename = "header")]
    Header,
    #[serde(rename = "302")]
    Redirect302,
    #[serde(rename = "307")]
    Redirect307,
    #[serde(rename = "reject")]
    Reject,
    #[serde(rename = "reject-200")]
    Reject200,
    #[serde(rename = "reject-img")]
    RejectImg,
    #[serde(rename = "reject-dict")]
    RejectDict,
    #[serde(rename = "reject-array")]
    RejectArray,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MitmHeaderAction {
    HeaderAdd,
    HeaderDel,
    HeaderReplace,
    HeaderReplaceRegex,
    HeaderTextReplace,
}

/// A line without `data-type` reads a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MitmDataType {
    Text,
    TinyGif,
    Base64,
    File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MitmPhase {
    Request,
    Response,
}

/// Loon's `network-changed` script is an `event` one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MitmScriptKind {
    HttpRequest,
    HttpResponse,
    Cron,
    Event,
    Generic,
}
