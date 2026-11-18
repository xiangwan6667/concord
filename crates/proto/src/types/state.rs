use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::LogLevel;

dto! {
    /// The fields of a general patch that changed, with their new values.
    #[derive(Default)]
    pub struct GeneralChange {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub log_level: Option<LogLevel>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allow_lan: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ipv6: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mixed_port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tcp_concurrent: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub find_process_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unified_delay: Option<bool>,
        /// User names only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentication: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geo_auto_update: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geo_update_interval: Option<u32>,
        /// Keyed `mmdb`, `asn` and `geosite`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geox_url: Option<BTreeMap<String, String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tun_enable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tun_device: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tun_stack: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tun_auto_route: Option<bool>,
    }

    /// The order of a change among all changes of state a host keeps.
    pub struct ChangeSeq {
        pub seq: u64,
    }

    pub struct TunState {
        pub enable: bool,
        pub device: String,
        pub stack: String,
        pub auto_route: bool,
        pub auto_detect_interface: bool,
        pub dns_hijack: Vec<String>,
        pub mtu: u32,
    }

    /// The general settings in force. `seq` is the last change reflected here and
    /// in `selections`, so `events.watch` with `state` continues after it.
    pub struct GeneralState {
        pub seq: u64,
        pub port: u16,
        pub socks_port: u16,
        pub redir_port: u16,
        pub tproxy_port: u16,
        pub mixed_port: u16,
        pub allow_lan: bool,
        pub bind_address: String,
        pub lan_allowed_ips: Vec<String>,
        pub lan_disallowed_ips: Vec<String>,
        /// User names only.
        pub authentication: Vec<String>,
        pub skip_auth_prefixes: Vec<String>,
        pub mode: String,
        pub log_level: LogLevel,
        pub ipv6: bool,
        pub tcp_concurrent: bool,
        pub unified_delay: bool,
        pub find_process_mode: String,
        pub interface_name: String,
        pub routing_mark: u32,
        pub sniffing: bool,
        pub global_ua: String,
        pub keep_alive_idle: u32,
        pub keep_alive_interval: u32,
        pub disable_keep_alive: bool,
        pub geo_auto_update: bool,
        pub geo_update_interval: u32,
        /// Keyed `mmdb`, `asn` and `geosite`.
        pub geox_url: BTreeMap<String, String>,
        pub tun: TunState,
        /// The pick of each group that has one.
        pub selections: BTreeMap<String, String>,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ChangeOrigin {
    Host,
    Controller,
    /// A fallback group dropped a pick whose node died.
    Core,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum StateChangeKind {
    /// An empty `proxy` clears the pick.
    Selected {
        group: String,
        proxy: String,
    },
    General(GeneralChange),
    /// A config apply replaced the picks with the ones it was given.
    Applied,
}
