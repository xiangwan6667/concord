#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exec {
    /// Runs on the task that reads frames, so it keeps arrival order: opening and
    /// cancelling a subscription must not queue behind a long apply.
    Inline,
    /// One queue per connection: these calls change the running config and must not overlap.
    Serial,
    Concurrent,
}

impl Exec {
    pub fn name(self) -> &'static str {
        match self {
            Exec::Inline => "inline",
            Exec::Serial => "serial",
            Exec::Concurrent => "concurrent",
        }
    }
}

/// What a stream does with events its consumer has no credit for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamPolicy {
    /// Coalesce: only the newest value is kept.
    Latest,
    /// A bounded queue evicts the oldest; the next event says how many went.
    DropOldest,
    /// A bounded queue that never drops silently: on overflow the stream sends
    /// `resync` and ends, and the client subscribes again for a fresh snapshot.
    Resync,
}

impl StreamPolicy {
    pub fn name(self) -> &'static str {
        match self {
            StreamPolicy::Latest => "latest",
            StreamPolicy::DropOldest => "drop_oldest",
            StreamPolicy::Resync => "resync",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    None,
    /// Listed in `core.hello` only when the engine has MITM.
    Mitm,
    /// Listed only when the build has debug methods and the client asked for them.
    Debug,
}

impl Cap {
    pub fn name(self) -> Option<&'static str> {
        match self {
            Cap::None => None,
            Cap::Mitm => Some("mitm"),
            Cap::Debug => Some("debug"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Unary,
    /// The response carries `sub` and an optional `snapshot`; events follow as
    /// `$/event` notifications.
    Stream,
    /// Answered by the RPC layer itself.
    Rpc,
}

pub struct MethodSpec {
    pub name: &'static str,
    pub kind: Kind,
    pub exec: Exec,
    pub policy: Option<StreamPolicy>,
    pub capability: Cap,
}

macro_rules! policy_of {
    (None) => {
        ::core::option::Option::None
    };
    ($policy:ident) => {
        ::core::option::Option::Some($crate::StreamPolicy::$policy)
    };
}

macro_rules! build_table {
    ($({ kind: $kind:ident, fun: $fun:ident, name: $name:literal, exec: $exec:ident, params: $params:ty, result: $result:ty, event: $event:ty, policy: $policy:ident, cap: $cap:ident })*) => {
        pub static METHODS: &[MethodSpec] = &[$(MethodSpec {
            name: $name,
            kind: kind_of!($kind),
            exec: Exec::$exec,
            policy: policy_of!($policy),
            capability: Cap::$cap,
        },)*];
    };
}

macro_rules! kind_of {
    (unary) => {
        $crate::Kind::Unary
    };
    (stream) => {
        $crate::Kind::Stream
    };
    (rpc) => {
        $crate::Kind::Rpc
    };
}

/// Every method, declared once. Consumers pass a macro that is called with the
/// whole list, so the service trait, the dispatcher and the schema cannot drift
/// apart.
#[macro_export]
macro_rules! with_methods {
    ($callback:ident) => {
        $callback! {
            { kind: rpc, fun: core_hello, name: "core.hello", exec: Inline, params: $crate::types::HelloParams, result: $crate::types::HelloResult, event: (), policy: None, cap: None }
            { kind: unary, fun: core_init, name: "core.init", exec: Serial, params: $crate::types::CoreInitParams, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: core_release_memory, name: "core.releaseMemory", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: core_stats, name: "core.stats", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::CoreStats, event: (), policy: None, cap: None }
            { kind: unary, fun: core_capabilities, name: "core.capabilities", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::Capabilities, event: (), policy: None, cap: None }
            { kind: unary, fun: core_set_pressure, name: "core.setPressure", exec: Concurrent, params: $crate::types::SetPressureParams, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: core_last_warnings, name: "core.lastWarnings", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::WarningList, event: (), policy: None, cap: None }
            { kind: unary, fun: debug_crash, name: "debug.crash", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::Empty, event: (), policy: None, cap: Debug }

            { kind: unary, fun: config_apply, name: "config.apply", exec: Serial, params: $crate::types::ConfigApplyParams, result: $crate::types::ConfigApplyResult, event: (), policy: None, cap: None }
            { kind: unary, fun: config_patch, name: "config.patch", exec: Serial, params: $crate::types::ConfigPatchParams, result: $crate::types::ChangeSeq, event: (), policy: None, cap: None }
            { kind: unary, fun: config_general, name: "config.general", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::GeneralState, event: (), policy: None, cap: None }
            { kind: unary, fun: config_validate, name: "config.validate", exec: Concurrent, params: $crate::types::ConfigValidateParams, result: $crate::types::ConfigValidateResult, event: (), policy: None, cap: None }
            { kind: unary, fun: config_decrypt, name: "config.decrypt", exec: Concurrent, params: $crate::types::ConfigDecryptParams, result: $crate::types::TextResult, event: (), policy: None, cap: None }
            { kind: unary, fun: config_read, name: "config.read", exec: Concurrent, params: $crate::types::ConfigReadParams, result: $crate::types::ConfigReadResult, event: (), policy: None, cap: None }

            { kind: unary, fun: profile_inspect, name: "profile.inspect", exec: Concurrent, params: $crate::types::ProfileParams, result: $crate::types::ProfileInspect, event: (), policy: None, cap: None }
            { kind: unary, fun: profile_outbounds, name: "profile.outbounds", exec: Concurrent, params: $crate::types::ProfileParams, result: $crate::types::ProfileOutbounds, event: (), policy: None, cap: None }
            { kind: unary, fun: profile_build, name: "profile.build", exec: Concurrent, params: $crate::types::ProfileBuildParams, result: $crate::types::TextResult, event: (), policy: None, cap: None }
            { kind: unary, fun: profile_clear_effect, name: "profile.clearEffect", exec: Concurrent, params: $crate::types::ClearEffectParams, result: $crate::types::Empty, event: (), policy: None, cap: None }

            { kind: unary, fun: proxy_groups, name: "proxy.groups", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::ProxyGroups, event: (), policy: None, cap: None }
            { kind: stream, fun: proxy_watch, name: "proxy.watch", exec: Inline, params: $crate::types::ProxyWatchParams, result: $crate::types::ProxyGroups, event: $crate::types::ProxyDelta, policy: Latest, cap: None }
            { kind: unary, fun: proxy_select, name: "proxy.select", exec: Concurrent, params: $crate::types::ProxySelectParams, result: $crate::types::ProxySelectResult, event: (), policy: None, cap: None }
            { kind: unary, fun: proxy_definition, name: "proxy.definition", exec: Concurrent, params: $crate::types::ProxyDefinitionParams, result: $crate::types::ProxyDefinition, event: (), policy: None, cap: None }
            { kind: unary, fun: proxy_states, name: "proxy.states", exec: Concurrent, params: $crate::types::ProxyStatesParams, result: $crate::types::ProxyStates, event: (), policy: None, cap: None }

            { kind: unary, fun: delay_test, name: "delay.test", exec: Concurrent, params: $crate::types::DelayTestParams, result: $crate::types::DelayResult, event: (), policy: None, cap: None }
            { kind: stream, fun: delay_run, name: "delay.run", exec: Inline, params: $crate::types::DelayRunParams, result: $crate::types::Empty, event: $crate::types::DelayRunEvent, policy: Resync, cap: None }

            { kind: unary, fun: validate_proxies, name: "validate.proxies", exec: Concurrent, params: $crate::types::ValidateProxiesParams, result: $crate::types::IssueList, event: (), policy: None, cap: None }
            { kind: unary, fun: validate_filters, name: "validate.filters", exec: Concurrent, params: $crate::types::ValidateFiltersParams, result: $crate::types::IssueList, event: (), policy: None, cap: None }
            { kind: unary, fun: convert_subscription, name: "convert.subscription", exec: Concurrent, params: $crate::types::ConvertSubscriptionParams, result: $crate::types::ProxyList, event: (), policy: None, cap: None }
            { kind: unary, fun: convert_encode_links, name: "convert.encodeLinks", exec: Concurrent, params: $crate::types::EncodeLinksParams, result: $crate::types::LinkList, event: (), policy: None, cap: None }
            { kind: unary, fun: convert_decode_links, name: "convert.decodeLinks", exec: Concurrent, params: $crate::types::DecodeLinksParams, result: $crate::types::DecodedLinks, event: (), policy: None, cap: None }

            { kind: unary, fun: provider_list, name: "provider.list", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::ProviderList, event: (), policy: None, cap: None }
            { kind: unary, fun: provider_get, name: "provider.get", exec: Concurrent, params: $crate::types::ProviderNameParams, result: $crate::types::ProviderInfo, event: (), policy: None, cap: None }
            { kind: unary, fun: provider_update, name: "provider.update", exec: Concurrent, params: $crate::types::ProviderNameParams, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: provider_side_load, name: "provider.sideLoad", exec: Concurrent, params: $crate::types::ProviderSideLoadParams, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: provider_health_check, name: "provider.healthCheck", exec: Concurrent, params: $crate::types::ProviderNameParams, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: rule_list, name: "rule.list", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::RuleList, event: (), policy: None, cap: None }
            { kind: unary, fun: rule_set_dump, name: "ruleSet.dump", exec: Concurrent, params: $crate::types::RuleSetDumpParams, result: $crate::types::TextResult, event: (), policy: None, cap: None }
            { kind: unary, fun: rule_set_compile, name: "ruleSet.compile", exec: Concurrent, params: $crate::types::RuleSetCompileParams, result: $crate::types::RuleSetInfo, event: (), policy: None, cap: None }
            { kind: unary, fun: geo_update, name: "geo.update", exec: Concurrent, params: $crate::types::GeoUpdateParams, result: $crate::types::Empty, event: (), policy: None, cap: None }

            { kind: stream, fun: traffic_watch, name: "traffic.watch", exec: Inline, params: $crate::types::TrafficWatchParams, result: $crate::types::Traffic, event: $crate::types::Traffic, policy: Latest, cap: None }
            { kind: unary, fun: traffic_reset, name: "traffic.reset", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: stream, fun: connection_watch, name: "connection.watch", exec: Inline, params: $crate::types::ConnectionWatchParams, result: $crate::types::ConnectionSnapshot, event: $crate::types::ConnectionDelta, policy: Resync, cap: None }
            { kind: unary, fun: connection_close, name: "connection.close", exec: Concurrent, params: $crate::types::ConnectionCloseParams, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: network_reset, name: "network.reset", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: network_update, name: "network.update", exec: Serial, params: $crate::types::NetworkUpdateParams, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: dns_clear_cache, name: "dns.clearCache", exec: Serial, params: $crate::types::Empty, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: dns_flush_fake_ip, name: "dns.flushFakeIp", exec: Serial, params: $crate::types::Empty, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: dns_query, name: "dns.query", exec: Concurrent, params: $crate::types::DnsQueryParams, result: $crate::types::DnsQueryResult, event: (), policy: None, cap: None }

            { kind: stream, fun: log_watch, name: "log.watch", exec: Inline, params: $crate::types::LogWatchParams, result: $crate::types::Empty, event: $crate::types::LogEntry, policy: DropOldest, cap: None }
            { kind: stream, fun: dns_watch, name: "dns.watch", exec: Inline, params: $crate::types::DnsWatchParams, result: $crate::types::Empty, event: $crate::types::DnsEntry, policy: DropOldest, cap: None }
            { kind: stream, fun: route_watch, name: "route.watch", exec: Inline, params: $crate::types::RouteWatchParams, result: $crate::types::RouteStamp, event: $crate::types::RouteStamp, policy: Latest, cap: None }
            { kind: stream, fun: events_watch, name: "events.watch", exec: Inline, params: $crate::types::EventsWatchParams, result: $crate::types::Empty, event: $crate::types::CoreEvent, policy: Resync, cap: None }
            { kind: stream, fun: engine_state, name: "engine.state", exec: Inline, params: $crate::types::EngineStateParams, result: $crate::types::EngineStatus, event: $crate::types::EngineStatus, policy: Latest, cap: None }

            { kind: unary, fun: engine_start, name: "engine.start", exec: Serial, params: $crate::types::Empty, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: engine_stop, name: "engine.stop", exec: Serial, params: $crate::types::Empty, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: tun_start, name: "tun.start", exec: Serial, params: $crate::types::TunStartParams, result: $crate::types::Empty, event: (), policy: None, cap: None }
            { kind: unary, fun: tun_stop, name: "tun.stop", exec: Serial, params: $crate::types::Empty, result: $crate::types::Empty, event: (), policy: None, cap: None }

            { kind: unary, fun: route_check, name: "route.check", exec: Concurrent, params: $crate::types::RouteCheckParams, result: $crate::types::RouteCheckResult, event: (), policy: None, cap: None }
            { kind: unary, fun: probe_outbound_ip, name: "probe.outboundIp", exec: Concurrent, params: $crate::types::OutboundIpParams, result: $crate::types::OutboundIp, event: (), policy: None, cap: None }
            { kind: unary, fun: probe_services, name: "probe.services", exec: Concurrent, params: $crate::types::ServicesParams, result: $crate::types::ServiceList, event: (), policy: None, cap: None }

            { kind: unary, fun: mitm_certificate, name: "mitm.certificate", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::MitmCertificate, event: (), policy: None, cap: Mitm }
            { kind: unary, fun: mitm_generate_certificate, name: "mitm.generateCertificate", exec: Concurrent, params: $crate::types::Empty, result: $crate::types::MitmCertificate, event: (), policy: None, cap: Mitm }
            { kind: unary, fun: mitm_validate, name: "mitm.validate", exec: Concurrent, params: $crate::types::MitmValidateParams, result: $crate::types::MitmValidateResult, event: (), policy: None, cap: Mitm }
            { kind: unary, fun: mitm_issue_certificate, name: "mitm.issueCertificate", exec: Concurrent, params: $crate::types::MitmIssueParams, result: $crate::types::MitmPem, event: (), policy: None, cap: Mitm }
            { kind: unary, fun: mitm_run_script, name: "mitm.runScript", exec: Concurrent, params: $crate::types::MitmScriptParams, result: $crate::types::MitmResult, event: (), policy: None, cap: Mitm }
            { kind: unary, fun: mitm_exchanges, name: "mitm.exchanges", exec: Concurrent, params: $crate::types::MitmExchangesParams, result: $crate::types::MitmResult, event: (), policy: None, cap: Mitm }
            { kind: unary, fun: mitm_exchange, name: "mitm.exchange", exec: Concurrent, params: $crate::types::MitmExchangeParams, result: $crate::types::MitmResult, event: (), policy: None, cap: Mitm }
            { kind: unary, fun: mitm_body, name: "mitm.body", exec: Concurrent, params: $crate::types::MitmBodyParams, result: $crate::types::MitmResult, event: (), policy: None, cap: Mitm }
        }
    };
}

with_methods!(build_table);

pub fn method(name: &str) -> Option<&'static MethodSpec> {
    METHODS.iter().find(|spec| spec.name == name)
}
