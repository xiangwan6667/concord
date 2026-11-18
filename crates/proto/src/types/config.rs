use std::collections::BTreeMap;

use super::{EngineStatus, Issue, Json, LogLevel, Output, ProfileRef, Warning};

dto! {
    pub struct ClientInfo {
        pub name: String,
        pub version: String,
    }

    pub struct ProtocolRange {
        pub min: u32,
        pub max: u32,
    }

    pub struct HelloParams {
        pub protocol: ProtocolRange,
        pub client: ClientInfo,
        /// `debug` unlocks the debug methods on a build that has them.
        #[serde(default)]
        pub capabilities: Vec<String>,
    }

    pub struct ServerInfo {
        pub implementation: String,
        pub version: String,
        pub build: String,
    }

    pub struct PlatformInfo {
        pub os: String,
        pub privileged: bool,
        /// What the host lets the core do, such as `tun.inherited`. Clients test
        /// these, never the operating system name.
        pub capabilities: Vec<String>,
    }

    pub struct Limits {
        pub max_message: u64,
        pub max_batch_bytes: u32,
    }

    pub struct Features {
        pub mitm: bool,
        pub ech: bool,
        pub system_stack: bool,
    }

    pub struct HelloResult {
        pub protocol: u32,
        pub server: ServerInfo,
        pub platform: PlatformInfo,
        pub limits: Limits,
        pub methods: Vec<String>,
        pub features: Features,
        pub engine: EngineStatus,
    }

    pub struct CoreInitParams {
        pub home: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sdk_int: Option<i32>,
    }

    pub struct CoreStats {
        pub rss: u64,
    }

    pub struct SetPressureParams {
        pub level: i32,
    }

    pub struct Capabilities {
        pub implementation: String,
        pub version: String,
        pub proxy_types: Vec<String>,
        pub transports: Vec<String>,
        pub rule_types: Vec<String>,
        pub ss_plugins: Vec<String>,
        pub congestion_controllers: Vec<String>,
        pub features: Features,
    }

    pub struct WarningList {
        pub warnings: Vec<Warning>,
    }

    #[derive(Default)]
    pub struct Options {
        /// An empty value keeps the URL in force.
        #[serde(default)]
        pub test_url: String,
        #[serde(default)]
        pub skip_cert_verify: bool,
        /// Milliseconds; zero keeps the timeout in force.
        #[serde(default)]
        pub delay_test_timeout: i64,
        #[serde(default)]
        pub mitm_capture: bool,
    }

    #[derive(Default)]
    pub struct ConfigApplyParams {
        /// Absent applies the `config.yaml` already in the home directory.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<ProfileRef>,
        /// The profile gives only `proxies`, `proxy-groups`, `sub-rules` and `rules`; every other
        /// key, the listeners included, comes from here. Rules listed here go before the profile's.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub overlay: Option<Json>,
        #[serde(default)]
        pub selection: BTreeMap<String, String>,
        #[serde(default)]
        pub options: Options,
    }

    /// One rule of the main list in force, in match order.
    pub struct RuleEntry {
        #[serde(rename = "type")]
        pub kind: String,
        pub payload: String,
        pub target: String,
    }

    pub struct RuleList {
        pub rules: Vec<RuleEntry>,
    }

    pub struct ConfigApplyResult {
        pub warnings: Vec<Warning>,
    }

    pub struct TunPatch {
        pub enable: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stack: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub auto_route: Option<bool>,
    }

    /// Which browser origins may call the external controller. An absent field takes mihomo's
    /// default: every origin, and private-network preflights allowed. No origin refuses them all.
    #[derive(Default)]
    pub struct ControllerCorsPatch {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allow_origins: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allow_private_network: Option<bool>,
    }

    /// An absent field keeps the value in force.
    #[derive(Default)]
    pub struct ConfigPatchParams {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tun: Option<TunPatch>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allow_lan: Option<bool>,
        /// `*` binds every address; read only while the LAN is allowed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bind_address: Option<String>,
        /// CIDR prefixes admitted to the mixed, HTTP and SOCKS listeners.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lan_allowed_ips: Option<Vec<String>>,
        /// CIDR prefixes refused there even when the allowed list admits them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lan_disallowed_ips: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mixed_port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub find_process_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub log_level: Option<LogLevel>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ipv6: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tcp_concurrent: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub external_controller: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub secret: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub external_controller_cors: Option<ControllerCorsPatch>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unified_delay: Option<bool>,
        /// `user:password` lines.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentication: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geo_auto_update: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geo_update_interval: Option<i64>,
        #[serde(default)]
        pub geox_url: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<Options>,
    }

    pub struct ConfigValidateParams {
        pub profile: ProfileRef,
    }

    pub struct ConfigValidateResult {
        pub issues: Vec<Issue>,
    }

    pub struct ConfigDecryptParams {
        pub profile: ProfileRef,
        pub key: String,
        #[serde(default)]
        pub output: Output,
    }

    pub struct ConfigReadParams {
        pub profile: ProfileRef,
        #[serde(default)]
        pub output: Output,
    }

    pub struct ConfigReadResult {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub config: Option<Json>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<String>,
        /// Bytes written, for a file output.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub size: Option<u64>,
    }

    pub struct ProfileParams {
        pub profile: ProfileRef,
    }

    pub struct ProfileInspect {
        pub config: Json,
        pub digest: String,
        #[serde(alias = "match-rules")]
        pub match_rules: Vec<String>,
        pub proxies: u64,
        #[serde(alias = "proxy-groups")]
        pub proxy_groups: u64,
        pub rules: u64,
    }

    pub struct OutboundRef {
        pub name: String,
        #[serde(rename = "type")]
        pub kind: String,
    }

    pub struct ProfileOutbounds {
        pub proxies: Vec<OutboundRef>,
        #[serde(alias = "proxy-groups")]
        pub proxy_groups: Vec<OutboundRef>,
    }

    pub struct ProfileBuildParams {
        pub profile: ProfileRef,
        pub overlay: Json,
        #[serde(default)]
        pub output: Output,
    }

    pub struct ClearEffectParams {
        pub profile_id: i64,
    }
}
