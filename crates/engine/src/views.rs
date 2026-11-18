use concord_common::{FindProcessMode, LogLevel, TunnelMode};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryStats {
    pub rss: u64,
    pub heap_inuse: u64,
    pub heap_idle: u64,
    pub stack_inuse: u64,
    pub runtime_other: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Capabilities {
    #[serde(rename = "impl")]
    pub implementation: &'static str,
    pub version: &'static str,
    #[serde(rename = "proxy-types")]
    pub proxy_types: Vec<&'static str>,
    pub transports: Vec<&'static str>,
    #[serde(rename = "rule-types")]
    pub rule_types: Vec<&'static str>,
    #[serde(rename = "ss-plugins")]
    pub ss_plugins: Vec<&'static str>,
    #[serde(rename = "congestion-controllers")]
    pub congestion_controllers: Vec<&'static str>,
    pub features: Features,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Features {
    pub mitm: bool,
    pub ech: bool,
    #[serde(rename = "system-stack")]
    pub system_stack: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct WarningView {
    pub level: &'static str,
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

/// `seq` is the change this select made, or the last change when it made none.
#[derive(Clone, Debug, Default)]
pub struct SelectOutcome {
    pub message: String,
    pub changed: bool,
    pub seq: u64,
}

#[derive(Clone, Debug)]
pub struct TunView {
    pub enable: bool,
    pub device: String,
    pub stack: String,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub dns_hijack: Vec<String>,
    pub mtu: u32,
}

/// The general settings in force; `seq` is the last change they reflect.
#[derive(Clone, Debug)]
pub struct GeneralView {
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
    pub users: Vec<String>,
    pub skip_auth_prefixes: Vec<String>,
    pub mode: TunnelMode,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub tcp_concurrent: bool,
    pub unified_delay: bool,
    pub find_process_mode: FindProcessMode,
    pub interface_name: String,
    pub routing_mark: u32,
    pub sniffing: bool,
    pub global_ua: String,
    pub keep_alive_idle: u32,
    pub keep_alive_interval: u32,
    pub disable_keep_alive: bool,
    pub geo_auto_update: bool,
    pub geo_update_interval: u32,
    pub geox_url: Vec<(&'static str, String)>,
    pub tun: TunView,
    pub selections: Vec<(String, String)>,
}

/// One rule of the route program in force, in match order.
#[derive(Clone, Debug)]
pub struct RuleView {
    pub kind: String,
    pub payload: String,
    pub target: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidationIssue {
    pub index: usize,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleSetInfo {
    pub behavior: &'static str,
    pub format: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderView {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    #[serde(rename = "vehicle-type")]
    pub vehicle_type: &'static str,
    pub count: usize,
    pub path: String,
    #[serde(rename = "update-at")]
    pub update_at: String,
    #[serde(rename = "subscription-info")]
    pub subscription_info: Option<SubscriptionInfo>,
    /// Proxy providers: the health check's URL and expected statuses.
    pub test_url: String,
    pub expected_status: String,
    /// Rule providers: `domain`, `ipcidr` or `classical`, and `yaml`, `text` or `mrs`.
    pub behavior: &'static str,
    pub format: &'static str,
}

/// The PascalCase keys come from a mihomo struct with no tags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SubscriptionInfo {
    #[serde(rename = "Upload")]
    pub upload: i64,
    #[serde(rename = "Download")]
    pub download: i64,
    #[serde(rename = "Total")]
    pub total: i64,
    #[serde(rename = "Expire")]
    pub expire: i64,
}
