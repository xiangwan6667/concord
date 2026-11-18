use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{IndexedIssue, Json, Output, ProfileRef, WatchOptions};

dto! {
    pub struct NodeInfo {
        pub name: String,
        #[serde(rename = "type")]
        pub kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
    }

    pub struct GroupInfo {
        pub name: String,
        #[serde(rename = "type")]
        pub kind: String,
        /// Absent for load balancing, which has no single current member.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub now: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub all: Option<Vec<String>>,
        pub test_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expected_status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fixed: Option<String>,
        pub hidden: bool,
        pub icon: String,
        pub empty_fallback: String,
    }

    /// Group names in display order with `GLOBAL` first, the groups, and every
    /// node a group can name.
    pub struct ProxyGroups {
        pub order: Vec<String>,
        pub groups: Vec<GroupInfo>,
        pub nodes: Vec<NodeInfo>,
    }

    /// What changed since the last batch of this subscription. A group or node is
    /// sent whole; `removed` names those that are gone.
    pub struct ProxyDelta {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub order: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub groups: Vec<GroupInfo>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub nodes: Vec<NodeInfo>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub removed: Vec<String>,
    }

    #[derive(Default)]
    pub struct ProxyWatchParams {
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct ProxySelectParams {
        pub group: String,
        /// An empty name clears the pick.
        pub proxy: String,
    }

    pub struct ProxySelectResult {
        pub changed: bool,
        /// The change this select made, or the last change when it made none.
        #[serde(default)]
        pub seq: u64,
    }

    /// `time` is Unix milliseconds; `delay` 0 is a failed test.
    pub struct DelayRecord {
        pub time: i64,
        pub delay: u16,
    }

    pub struct UrlHealth {
        pub url: String,
        pub alive: bool,
        pub history: Vec<DelayRecord>,
    }

    /// The last ten results, overall and for each URL a node was tested at.
    pub struct ProxyState {
        pub name: String,
        pub udp: bool,
        pub alive: bool,
        pub history: Vec<DelayRecord>,
        pub extra: Vec<UrlHealth>,
    }

    #[derive(Default)]
    pub struct ProxyStatesParams {
        /// Absent lists every name `proxy.groups` lists; unknown names are left out.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub names: Option<Vec<String>>,
    }

    pub struct ProxyStates {
        pub proxies: Vec<ProxyState>,
    }

    pub struct ProxyDefinitionParams {
        pub name: String,
    }

    pub struct ProxyDefinition {
        pub proxy: Json,
    }

    pub struct DelayTestParams {
        pub proxy: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        /// Milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<u64>,
        /// Status ranges such as `200/204/300-399` that count as a success. Default any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expected: Option<String>,
    }

    /// `value` is milliseconds when positive, -1 for a timeout and -2 for a failure.
    pub struct DelayResult {
        pub name: String,
        pub url: String,
        pub value: i32,
    }

    pub struct DelayRunParams {
        pub proxies: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<u64>,
        /// Tests running at once. Default: every proxy at once, as the Clash API tests a group.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub concurrency: Option<u32>,
        /// As in `delay.test`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expected: Option<String>,
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct ValidateProxiesParams {
        pub proxies: Vec<Json>,
    }

    pub struct ValidateFiltersParams {
        pub filters: Vec<String>,
    }

    pub struct IssueList {
        pub issues: Vec<IndexedIssue>,
    }

    pub struct ConvertSubscriptionParams {
        pub profile: ProfileRef,
    }

    pub struct ProxyList {
        pub proxies: Vec<Json>,
    }

    pub struct EncodeLinksParams {
        pub proxies: Vec<Json>,
    }

    pub struct LinkList {
        pub links: Vec<String>,
    }

    pub struct DecodeLinksParams {
        pub lines: Vec<String>,
    }

    pub struct DecodedLinks {
        /// One entry per input line, empty when the line is not a link.
        pub results: Vec<Vec<Json>>,
    }

    pub struct SubscriptionInfo {
        pub upload: i64,
        pub download: i64,
        pub total: i64,
        pub expire: i64,
    }

    pub struct ProviderInfo {
        pub name: String,
        #[serde(rename = "type")]
        pub kind: ProviderKind,
        pub vehicle_type: String,
        pub count: u64,
        pub path: String,
        /// Absent while the provider has never loaded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub updated_at: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subscription_info: Option<SubscriptionInfo>,
        /// Proxy providers: the health check's URL and expected statuses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub test_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expected_status: Option<String>,
        /// Rule providers: `domain`, `ipcidr` or `classical`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub behavior: Option<String>,
        /// Rule providers: `yaml`, `text` or `mrs`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
    }

    pub struct ProviderList {
        pub providers: Vec<ProviderInfo>,
    }

    pub struct ProviderNameParams {
        pub name: String,
    }

    pub struct ProviderSideLoadParams {
        pub name: String,
        pub data: String,
    }

    pub struct RuleSetDumpParams {
        pub profile: ProfileRef,
        #[serde(default)]
        pub output: Output,
    }

    pub struct RuleSetCompileParams {
        pub name: String,
        /// Empty compiles the file already stored under that name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
    }

    pub struct RuleSetInfo {
        pub behavior: String,
        pub format: String,
    }

    pub struct GeoUpdateParams {
        #[serde(rename = "type")]
        pub kind: String,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Proxy,
    Rule,
}
