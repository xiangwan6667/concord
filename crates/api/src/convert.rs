use std::io;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use concord_common::{
    Change, ConnRecord, DnsRecord, GeneralChange as EngineChange, LogLevel as EngineLevel, Origin,
    StateChange,
};
use concord_engine::{
    DelayRecord as EngineDelay, Failure, GeneralView, GroupView, NodeStateView, NodeView,
    ProviderView, QueryView, RecordView, Service,
};
use concord_proto::ApiError;
use concord_proto::types::{
    Capabilities, ChangeOrigin, ConnectionInfo, CoreEvent, DelayRecord, DnsEntry, DnsQueryResult,
    DnsQuestion, DnsRecord as WireRecord, FaultReason, FaultService, Features, GeneralChange,
    GeneralState, GroupInfo, LogLevel, Network, NodeInfo, ProviderInfo, ProviderKind, ProxyState,
    ServiceFault, StateChangeKind, SubscriptionInfo, TunState, UrlHealth, Warning,
};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub fn unix_millis(at: SystemTime) -> i64 {
    at.duration_since(UNIX_EPOCH).map_or(0, |elapsed| {
        i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
    })
}

pub fn log_level(level: EngineLevel) -> LogLevel {
    match level {
        EngineLevel::Debug => LogLevel::Debug,
        EngineLevel::Info => LogLevel::Info,
        EngineLevel::Warning => LogLevel::Warning,
        EngineLevel::Error => LogLevel::Error,
        EngineLevel::Silent => LogLevel::Silent,
    }
}

pub fn fault(fault: concord_engine::ServiceFault) -> ServiceFault {
    ServiceFault {
        service: match fault.service {
            Service::Mixed => FaultService::Mixed,
            Service::Http => FaultService::Http,
            Service::Socks => FaultService::Socks,
            Service::Redir => FaultService::Redir,
            Service::TProxy => FaultService::Tproxy,
            Service::Tun => FaultService::Tun,
            Service::Dns => FaultService::Dns,
        },
        address: fault.address,
        reason: match fault.kind {
            io::ErrorKind::AddrInUse => FaultReason::AddressInUse,
            io::ErrorKind::AddrNotAvailable => FaultReason::AddressNotAvailable,
            io::ErrorKind::PermissionDenied => FaultReason::PermissionDenied,
            _ => FaultReason::Other,
        },
        message: fault.message,
    }
}

pub fn route_stamp(view: concord_common::RouteView) -> concord_proto::types::RouteStamp {
    concord_proto::types::RouteStamp {
        epoch: view.stamp.epoch,
        version: view.stamp.version,
        running: view.running,
    }
}

pub fn engine_level(level: LogLevel) -> EngineLevel {
    match level {
        LogLevel::Debug => EngineLevel::Debug,
        LogLevel::Info => EngineLevel::Info,
        LogLevel::Warning => EngineLevel::Warning,
        LogLevel::Error => EngineLevel::Error,
        LogLevel::Silent => EngineLevel::Silent,
    }
}

pub fn dns_entry(record: &DnsRecord) -> DnsEntry {
    DnsEntry {
        domain: record.domain.clone(),
        query_type: record.qtype.clone(),
        initiator: record.initiator.as_str().to_string(),
        upstream: record.upstream.clone(),
        cached: record.cached,
        answers: record.answers.clone(),
        rcode: record.rcode.clone(),
        error: record.error.clone(),
        delay: record.delay_ms,
        time: unix_millis(record.time),
    }
}

fn some(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_string())
}

fn some_list(list: &Option<Vec<String>>) -> Option<Vec<String>> {
    list.clone().filter(|list| !list.is_empty())
}

/// The sparse form of a connection: what clients read, with empty values left out.
/// The counters are read now, so an `opened` entry is already current.
pub fn connection_info(record: &ConnRecord) -> ConnectionInfo {
    let meta = &record.meta;
    ConnectionInfo {
        id: record.seq,
        start: unix_millis(record.start),
        network: match meta.network {
            concord_common::Network::Tcp => Network::Tcp,
            concord_common::Network::Udp => Network::Udp,
        },
        source_ip: meta.src.ip().to_string(),
        source_port: meta.src.port(),
        destination_ip: meta.dst_ip.map(|ip| ip.to_string()),
        destination_port: meta.dst_port,
        host: some(&meta.host),
        sniff_host: some(&meta.sniff_host),
        inbound_type: meta.inbound.kind.wire_name().to_string(),
        inbound_ip: meta.inbound.addr.map(|addr| addr.ip().to_string()),
        inbound_port: meta.inbound.addr.map(|addr| addr.port()),
        inbound_name: some(&meta.inbound.name),
        inbound_user: meta.inbound.user.as_deref().and_then(some),
        dns_mode: meta.dns_mode.map(|mode| mode.wire_name().to_string()),
        uid: meta.uid,
        process: some(&meta.process),
        process_path: some(&meta.process_path),
        remote_destination: some(&meta.remote_destination),
        source_geo_ip: some_list(&meta.src_geoip),
        destination_geo_ip: some_list(&meta.dst_geoip),
        source_asn: some(&meta.src_asn),
        destination_asn: some(&meta.dst_asn),
        rematch_name: some(&meta.rematch_name),
        special_rules: some(&meta.special_rules),
        special_proxy: some(&meta.special_proxy),
        mitm: record.mitm.load(Ordering::Relaxed),
        mitm_refused: record.mitm_refused.load(Ordering::Relaxed),
        chains: record.chains.iter().map(ToString::to_string).collect(),
        provider_chains: record
            .provider_chains
            .iter()
            .map(ToString::to_string)
            .collect(),
        rule: record.rule.to_string(),
        rule_payload: record.rule_payload.to_string(),
        upload: record.upload.load(Ordering::Relaxed),
        download: record.download.load(Ordering::Relaxed),
    }
}

pub fn node_info(view: &NodeView) -> NodeInfo {
    NodeInfo {
        name: view.name.to_string(),
        kind: view.kind.to_string(),
        provider: view.provider.as_ref().map(ToString::to_string),
    }
}

pub fn group_info(view: &GroupView) -> GroupInfo {
    GroupInfo {
        name: view.name.to_string(),
        kind: view.kind.to_string(),
        now: view.now.clone(),
        all: view
            .all
            .as_ref()
            .map(|all| all.iter().map(ToString::to_string).collect()),
        test_url: view.test_url.clone(),
        expected_status: view.expected_status.clone(),
        fixed: view.fixed.clone(),
        hidden: view.hidden,
        icon: view.icon.clone(),
        empty_fallback: view.empty_fallback.to_string(),
    }
}

pub fn provider_info(view: ProviderView) -> ProviderInfo {
    ProviderInfo {
        name: view.name,
        kind: if view.kind == "Rule" {
            ProviderKind::Rule
        } else {
            ProviderKind::Proxy
        },
        vehicle_type: view.vehicle_type.to_string(),
        count: view.count as u64,
        path: view.path,
        updated_at: OffsetDateTime::parse(&view.update_at, &Rfc3339)
            .ok()
            .map(|at| i64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap_or(0))
            .filter(|millis| *millis > 0),
        subscription_info: view.subscription_info.map(|info| SubscriptionInfo {
            upload: info.upload,
            download: info.download,
            total: info.total,
            expire: info.expire,
        }),
        test_url: (view.kind != "Rule").then_some(view.test_url),
        expected_status: (view.kind != "Rule").then_some(view.expected_status),
        behavior: (!view.behavior.is_empty()).then(|| view.behavior.to_string()),
        format: (!view.format.is_empty()).then(|| view.format.to_string()),
    }
}

pub fn resource_event(update: concord_common::ResourceUpdate) -> CoreEvent {
    use concord_common::{ResourceKind as Kind, ResourcePhase as Phase};
    use concord_proto::types::{ResourceKind, ResourcePhase};
    let kind = match update.kind {
        Kind::ProxyProvider => ResourceKind::ProxyProvider,
        Kind::RuleProvider => ResourceKind::RuleProvider,
        Kind::Geo => ResourceKind::Geo,
    };
    let (phase, error) = match update.phase {
        Phase::Updating => (ResourcePhase::Updating, String::new()),
        Phase::Updated => (ResourcePhase::Updated, String::new()),
        Phase::Unchanged => (ResourcePhase::Unchanged, String::new()),
        Phase::Failed(error) => (ResourcePhase::Failed, error),
    };
    CoreEvent::ResourceUpdate {
        kind,
        name: update.name.to_string(),
        phase,
        error,
    }
}

pub fn state_event(change: StateChange) -> CoreEvent {
    CoreEvent::StateChanged {
        seq: change.seq,
        origin: match change.origin {
            Origin::Host => ChangeOrigin::Host,
            Origin::Controller => ChangeOrigin::Controller,
            Origin::Core => ChangeOrigin::Core,
        },
        change: match change.change {
            Change::Selected { group, proxy } => StateChangeKind::Selected { group, proxy },
            Change::General(general) => StateChangeKind::General(general_change(general)),
            Change::Applied => StateChangeKind::Applied,
        },
    }
}

fn general_change(change: EngineChange) -> GeneralChange {
    GeneralChange {
        mode: change.mode.map(|mode| mode.as_str().to_string()),
        log_level: change.log_level.map(log_level),
        allow_lan: change.allow_lan,
        ipv6: change.ipv6,
        mixed_port: change.mixed_port,
        tcp_concurrent: change.tcp_concurrent,
        find_process_mode: change
            .find_process_mode
            .map(|mode| mode.as_str().to_string()),
        unified_delay: change.unified_delay,
        authentication: change.authentication,
        geo_auto_update: change.geo_auto_update,
        geo_update_interval: change.geo_update_interval,
        geox_url: change.geox_url,
        tun_enable: change.tun_enable,
        tun_device: change.tun_device,
        tun_stack: change.tun_stack,
        tun_auto_route: change.tun_auto_route,
    }
}

pub fn general_state(view: GeneralView) -> GeneralState {
    GeneralState {
        seq: view.seq,
        port: view.port,
        socks_port: view.socks_port,
        redir_port: view.redir_port,
        tproxy_port: view.tproxy_port,
        mixed_port: view.mixed_port,
        allow_lan: view.allow_lan,
        bind_address: view.bind_address,
        lan_allowed_ips: view.lan_allowed_ips,
        lan_disallowed_ips: view.lan_disallowed_ips,
        authentication: view.users,
        skip_auth_prefixes: view.skip_auth_prefixes,
        mode: view.mode.as_str().to_string(),
        log_level: log_level(view.log_level),
        ipv6: view.ipv6,
        tcp_concurrent: view.tcp_concurrent,
        unified_delay: view.unified_delay,
        find_process_mode: view.find_process_mode.as_str().to_string(),
        interface_name: view.interface_name,
        routing_mark: view.routing_mark,
        sniffing: view.sniffing,
        global_ua: view.global_ua,
        keep_alive_idle: view.keep_alive_idle,
        keep_alive_interval: view.keep_alive_interval,
        disable_keep_alive: view.disable_keep_alive,
        geo_auto_update: view.geo_auto_update,
        geo_update_interval: view.geo_update_interval,
        geox_url: view
            .geox_url
            .into_iter()
            .map(|(kind, url)| (kind.to_string(), url))
            .collect(),
        tun: TunState {
            enable: view.tun.enable,
            device: view.tun.device,
            stack: view.tun.stack,
            auto_route: view.tun.auto_route,
            auto_detect_interface: view.tun.auto_detect_interface,
            dns_hijack: view.tun.dns_hijack,
            mtu: view.tun.mtu,
        },
        selections: view.selections.into_iter().collect(),
    }
}

fn delays(history: Vec<EngineDelay>) -> Vec<DelayRecord> {
    history
        .into_iter()
        .map(|record| DelayRecord {
            time: unix_millis(record.time),
            delay: record.delay,
        })
        .collect()
}

pub fn proxy_state(view: NodeStateView) -> ProxyState {
    ProxyState {
        name: view.name.to_string(),
        udp: view.udp,
        alive: view.health.alive,
        history: delays(view.health.history),
        extra: view
            .health
            .extra
            .into_iter()
            .map(|url| UrlHealth {
                url: url.url,
                alive: url.alive,
                history: delays(url.history),
            })
            .collect(),
    }
}

fn wire_records(records: Vec<RecordView>) -> Vec<WireRecord> {
    records
        .into_iter()
        .map(|record| WireRecord {
            name: record.name,
            rtype: record.rtype,
            ttl: record.ttl,
            data: record.data,
        })
        .collect()
}

pub fn dns_query(view: QueryView) -> DnsQueryResult {
    DnsQueryResult {
        rcode: view.rcode,
        questions: view
            .questions
            .into_iter()
            .map(|question| DnsQuestion {
                name: question.name,
                qtype: question.qtype,
                qclass: question.qclass,
            })
            .collect(),
        truncated: view.truncated,
        recursion_desired: view.recursion_desired,
        recursion_available: view.recursion_available,
        authentic_data: view.authentic_data,
        checking_disabled: view.checking_disabled,
        answers: wire_records(view.answers),
        authorities: wire_records(view.authorities),
        additionals: wire_records(view.additionals),
    }
}

pub fn warning(view: concord_engine::WarningView) -> Warning {
    Warning {
        level: view.level.to_string(),
        code: Some(view.code.to_string()),
        path: view.path,
        message: view.message,
    }
}

pub fn capabilities(source: concord_engine::Capabilities) -> Capabilities {
    let strings = |list: Vec<&'static str>| list.into_iter().map(str::to_string).collect();
    Capabilities {
        implementation: source.implementation.to_string(),
        version: source.version.to_string(),
        proxy_types: strings(source.proxy_types),
        transports: strings(source.transports),
        rule_types: strings(source.rule_types),
        ss_plugins: strings(source.ss_plugins),
        congestion_controllers: strings(source.congestion_controllers),
        features: Features {
            mitm: source.features.mitm,
            ech: source.features.ech,
            system_stack: source.features.system_stack,
        },
    }
}

/// Who is at fault when an engine call fails with a plain `core_error`: the data
/// the caller named, or the core.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Blame {
    Data,
    Core,
}

fn detail<'a>(failure: &'a Failure, key: &str) -> Option<&'a str> {
    failure.details.as_ref()?.get(key)?.as_str()
}

/// Reads the codes the engine has always used. The message text is only passed
/// through for people; nothing here depends on it, except the one file-missing
/// phrase `ops::read_file` writes.
pub fn api_error(failure: Failure, blame: Blame) -> ApiError {
    let message = failure.message.clone();
    match failure.code.as_str() {
        "config_rejected" => ApiError::rejected(message, true),
        "invalid_arguments" => ApiError::invalid_params(message),
        "provider_not_found" => ApiError::not_found(
            "provider",
            detail(&failure, "providerName").unwrap_or_default(),
        ),
        "provider_updating" => ApiError::conflict("updating", message),
        "rule_set_empty" | "rule_set_mixed" | "rule_set_invalid" => {
            ApiError::rejected_because(&failure.code, message)
        }
        "provider_update_error" => ApiError::rejected(message, false),
        "request_error" => match detail(&failure, "reason") {
            Some("timeout") => {
                ApiError::new(concord_proto::ErrorData::Timeout { after: None }, message)
            }
            _ => ApiError::unavailable(
                detail(&failure, "providerName")
                    .unwrap_or_default()
                    .to_string(),
                message,
            ),
        },
        "request_bad_response" => ApiError::unavailable(
            detail(&failure, "providerName")
                .unwrap_or_default()
                .to_string(),
            message,
        ),
        _ if message.ends_with(": no such file or directory") => {
            let name = message
                .strip_prefix("open ")
                .and_then(|rest| rest.strip_suffix(": no such file or directory"))
                .unwrap_or_default();
            ApiError::not_found("file", name)
        }
        _ if blame == Blame::Data => ApiError::rejected(message, false),
        _ => ApiError::internal(message),
    }
}

pub fn value_to_object(value: Value) -> Option<serde_json::Map<String, Value>> {
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use concord_common::{
        ConnMeta, DnsMode, Host, InboundInfo, InboundKind, Network as CommonNetwork,
    };
    use concord_proto::ErrorData;
    use serde_json::json;

    use super::*;

    fn record(host: &str, geoip: Option<Vec<String>>) -> ConnRecord {
        let meta = ConnMeta {
            network: CommonNetwork::Tcp,
            inbound: InboundInfo::new(InboundKind::Socks5),
            src: "127.0.0.1:1000".parse().unwrap(),
            dst_ip: None,
            dst_port: 443,
            host: Host::from(host),
            sniff_host: Host::default(),
            dns_mode: Some(DnsMode::FakeIp),
            uid: None,
            process: String::new(),
            process_path: String::new(),
            remote_destination: String::new(),
            src_geoip: None,
            dst_geoip: geoip,
            src_asn: String::new(),
            dst_asn: String::new(),
            rematch_name: String::new(),
            special_rules: String::new(),
            special_proxy: String::new(),
        };
        ConnRecord::new(
            meta,
            vec![Arc::from("exit"), Arc::from("group")].into_boxed_slice(),
            Box::new([]),
            Arc::from("DOMAIN"),
            Arc::from(""),
            false,
            7,
        )
    }

    #[test]
    fn a_connection_is_sparse_numeric_and_camel_case() {
        let record = record("example.com", Some(Vec::new()));
        let value = serde_json::to_value(connection_info(&record)).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(value["id"], record.seq);
        assert_eq!(value["sourcePort"], 1000);
        assert_eq!(value["destinationPort"], 443);
        assert_eq!(value["network"], "tcp");
        assert_eq!(value["dnsMode"], "fake-ip");
        assert_eq!(value["chains"], json!(["exit", "group"]));
        assert_eq!(value["upload"], 7);
        assert!(value["start"].is_i64(), "times are Unix milliseconds");
        for absent in [
            "destinationIp",
            "uid",
            "process",
            "processPath",
            "sourceGeoIp",
            "destinationGeoIp",
            "rulePayload",
            "providerChains",
            "remoteDestination",
            "rematchName",
        ] {
            assert!(
                !object.contains_key(absent),
                "{absent} is empty and must be left out"
            );
        }
        for padding in ["dscp", "metadata"] {
            assert!(!object.contains_key(padding), "{padding}");
        }
        assert!(
            value["inboundType"].is_string(),
            "the inbound kind is real data"
        );
    }

    #[test]
    fn rematch_name_is_real_sparse_connection_metadata() {
        let mut record = record("example.com", None);
        record.meta.rematch_name = "Next".into();
        let value = serde_json::to_value(connection_info(&record)).unwrap();
        assert_eq!(value["rematchName"], "Next");
        record.meta.rematch_name.clear();
        let value = serde_json::to_value(connection_info(&record)).unwrap();
        assert!(value.get("rematchName").is_none());
    }

    #[test]
    fn a_connection_is_much_smaller_than_the_old_tracker() {
        let record = record("example.com", None);
        let sparse = serde_json::to_vec(&connection_info(&record)).unwrap();
        assert!(sparse.len() < 450, "{} bytes", sparse.len());
    }

    #[test]
    fn rule_set_failures_keep_their_reason() {
        let error = api_error(
            Failure::new("rule_set_mixed", "mixed behaviours"),
            Blame::Core,
        );
        let ErrorData::Rejected { reason, .. } = error.data else {
            panic!("{error:?}");
        };
        assert_eq!(reason.as_deref(), Some("rule_set_mixed"));
    }

    #[test]
    fn connection_ids_count_up() {
        let (first, second) = (record("a", None), record("b", None));
        assert!(second.seq > first.seq);
    }

    fn failure(code: &str, message: &str, details: Option<Value>) -> Failure {
        let mut failure = Failure::new(code, message);
        failure.details = details;
        failure
    }

    #[test]
    fn engine_codes_become_error_kinds() {
        let kind = |failure, blame| api_error(failure, blame).data.kind();
        assert_eq!(
            kind(failure("config_rejected", "bad", None), Blame::Core),
            "rejected"
        );
        assert_eq!(
            kind(failure("invalid_arguments", "x", None), Blame::Core),
            "invalid_params"
        );
        assert_eq!(
            kind(failure("provider_updating", "x", None), Blame::Core),
            "conflict"
        );
        assert_eq!(
            kind(failure("provider_update_error", "x", None), Blame::Core),
            "rejected"
        );
        assert_eq!(
            kind(failure("rule_set_mixed", "x", None), Blame::Core),
            "rejected"
        );
        assert_eq!(
            kind(failure("request_bad_response", "x", None), Blame::Core),
            "unavailable"
        );
        assert_eq!(
            kind(failure("core_error", "boom", None), Blame::Core),
            "internal"
        );
        assert_eq!(
            kind(failure("core_error", "bad yaml", None), Blame::Data),
            "rejected"
        );
        assert_eq!(
            api_error(
                failure(
                    "provider_not_found",
                    "x",
                    Some(json!({"providerName": "p"}))
                ),
                Blame::Core
            )
            .data,
            ErrorData::NotFound {
                entity: "provider".into(),
                name: "p".into()
            }
        );
        assert_eq!(
            api_error(
                failure("request_error", "x", Some(json!({"reason": "timeout"}))),
                Blame::Core
            )
            .data,
            ErrorData::Timeout { after: None }
        );
        assert_eq!(
            api_error(
                failure("core_error", "open /a/b: no such file or directory", None),
                Blame::Data
            )
            .data,
            ErrorData::NotFound {
                entity: "file".into(),
                name: "/a/b".into()
            }
        );
    }

    #[test]
    fn provider_times_are_milliseconds_and_an_unset_time_is_absent() {
        let view = |at: &str| ProviderView {
            name: "p".into(),
            kind: "Rule",
            vehicle_type: "HTTP",
            count: 3,
            path: "x".into(),
            update_at: at.into(),
            subscription_info: None,
            test_url: String::new(),
            expected_status: String::new(),
            behavior: "",
            format: "",
        };
        assert_eq!(provider_info(view("0001-01-01T00:00:00Z")).updated_at, None);
        assert_eq!(
            provider_info(view("2026-11-01T00:00:00Z")).updated_at,
            Some(1_793_491_200_000)
        );
        assert_eq!(
            provider_info(view("2026-11-01T00:00:00Z")).kind,
            ProviderKind::Rule
        );
    }
}
