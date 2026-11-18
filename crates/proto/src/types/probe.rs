use std::collections::BTreeMap;

use super::{Json, MitmIssue, MitmLineEntry, RouteHit};

dto! {
    pub struct RouteCheckParams {
        pub routes: Vec<Vec<RouteHit>>,
    }

    /// `held[i]` says route `i` still leaves where it did; `epoch` and `version`
    /// are the stamp the answers were checked against.
    pub struct RouteCheckResult {
        pub epoch: u64,
        pub version: u64,
        pub held: Vec<bool>,
    }

    pub struct OutboundIpParams {
        pub proxy: String,
        pub urls: Vec<String>,
        /// Milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<u64>,
    }

    pub struct OutboundIp {
        pub url: String,
        pub body: String,
        pub delay: i64,
        pub chains: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(alias = "core-epoch")]
        pub epoch: u64,
        #[serde(alias = "route-version")]
        pub version: u64,
        pub hits: Vec<RouteHit>,
        #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "node-hits")]
        pub node_hits: Vec<RouteHit>,
    }

    pub struct ServicesParams {
        pub proxy: String,
        pub names: Vec<String>,
        /// Milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<u64>,
    }

    pub struct ServiceItem {
        pub name: String,
        pub status: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub region: String,
        #[serde(default, skip_serializing_if = "is_zero")]
        pub delay: i64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub chains: Vec<String>,
        #[serde(alias = "checked-at")]
        pub checked_at: i64,
        #[serde(alias = "core-epoch")]
        pub epoch: u64,
        #[serde(alias = "route-version")]
        pub version: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub hits: Vec<RouteHit>,
    }

    pub struct ServiceList {
        pub items: Vec<ServiceItem>,
    }

    pub struct MitmCertificate {
        /// Absent while no certificate authority exists.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<Json>,
    }

    pub struct MitmValidateParams {
        pub config: Json,
    }

    /// Both keyed by list, as the section names it (`hostname`, `url-rewrite`, ...), in
    /// line order. A line in force has a view; one that cannot be read has an issue; a
    /// `hostname` or `client-source-address` line some of whose items apply has both.
    pub struct MitmValidateResult {
        pub issues: BTreeMap<String, Vec<MitmIssue>>,
        #[serde(default)]
        pub views: BTreeMap<String, Vec<MitmLineEntry>>,
    }

    pub struct MitmIssueParams {
        pub host: String,
    }

    pub struct MitmPem {
        pub pem: String,
    }

    pub struct MitmScriptParams {
        pub name: String,
    }

    pub struct MitmResult {
        pub result: Json,
    }

    pub struct MitmExchangesParams {
        /// A connection id from `connection.watch`, open or closed since, as long as
        /// the capture still holds its exchanges.
        pub connection: u64,
    }

    pub struct MitmExchangeParams {
        pub id: i64,
    }

    pub struct MitmBodyParams {
        pub id: i64,
        #[serde(default)]
        pub response: bool,
    }
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}
