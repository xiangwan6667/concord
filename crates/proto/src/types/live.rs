use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{ChangeOrigin, LogLevel, Network, RouteStamp, StateChangeKind, WatchOptions};

dto! {
    #[derive(Default)]
    pub struct TrafficWatchParams {
        /// Default 1000.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub interval_ms: Option<u32>,
        #[serde(default)]
        pub only_proxy: bool,
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    /// Rates are bytes per second; totals count from the last `traffic.reset`.
    pub struct Traffic {
        pub up: i64,
        pub down: i64,
        pub total_up: i64,
        pub total_down: i64,
    }

    #[derive(Default)]
    pub struct ConnectionWatchParams {
        /// Send `counters` in the deltas. Default true; a client that shows no
        /// traffic figures turns them off and the stream carries only opens and
        /// closes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counters: Option<bool>,
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct ConnectionInfo {
        pub id: u64,
        pub start: i64,
        pub network: Network,
        pub source_ip: String,
        pub source_port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destination_ip: Option<String>,
        pub destination_port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        /// The host the sniffer read from the traffic.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sniff_host: Option<String>,
        /// The kind of inbound that accepted the connection, such as `socks5` or `tun`.
        pub inbound_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inbound_ip: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inbound_port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inbound_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inbound_user: Option<String>,
        /// `normal`, `fake-ip`, `redir-host` or `hosts`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dns_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub uid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub process: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub process_path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remote_destination: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source_geo_ip: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destination_geo_ip: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source_asn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destination_asn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rematch_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub special_rules: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub special_proxy: Option<String>,
        #[serde(default)]
        pub mitm: bool,
        #[serde(default)]
        pub mitm_refused: bool,
        /// The exit first.
        pub chains: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub provider_chains: Vec<String>,
        pub rule: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub rule_payload: String,
        pub upload: u64,
        pub download: u64,
    }

    pub struct ConnectionSnapshot {
        pub connections: Vec<ConnectionInfo>,
    }

    pub struct ConnectionCounter {
        pub id: u64,
        pub upload: u64,
        pub download: u64,
    }

    /// An `opened` entry that a client already has is a repeat and replaces it.
    /// A connection that opened and closed between two batches is in both lists,
    /// so apply `opened` first and `closed` after.
    pub struct ConnectionDelta {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub opened: Vec<ConnectionInfo>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub closed: Vec<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub counters: Vec<ConnectionCounter>,
    }

    pub struct ConnectionCloseParams {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ids: Option<Vec<u64>>,
        /// Closes every connection.
        #[serde(default)]
        pub all: bool,
    }

    #[derive(Default)]
    pub struct LogWatchParams {
        /// Entries below this level are left out of this subscription.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<LogLevel>,
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct LogEntry {
        pub level: LogLevel,
        pub time: i64,
        pub text: String,
    }

    #[derive(Default)]
    pub struct DnsWatchParams {
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct DnsEntry {
        pub domain: String,
        #[serde(rename = "type")]
        pub query_type: String,
        pub initiator: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub upstream: String,
        #[serde(default)]
        pub cached: bool,
        pub answers: Vec<String>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub rcode: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub error: String,
        pub delay: i64,
        pub time: i64,
    }

    #[derive(Default)]
    pub struct RouteWatchParams {
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    #[derive(Default)]
    pub struct EventsWatchParams {
        /// Also report every URL test result, the automatic ones of the groups included.
        #[serde(default)]
        pub delays: bool,
        /// Also report `stateChanged`: every change of a pick or of the general
        /// settings a host keeps, from any origin, in the order it took effect.
        #[serde(default)]
        pub state: bool,
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct DnsQueryParams {
        pub name: String,
        /// A record type such as `A` or `AAAA`. Default `A`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub qtype: Option<String>,
    }

    pub struct DnsQuestion {
        pub name: String,
        pub qtype: u16,
        pub qclass: u16,
    }

    /// `data` is the record's data in presentation format.
    pub struct DnsRecord {
        pub name: String,
        pub rtype: u16,
        pub ttl: u32,
        pub data: String,
    }

    pub struct DnsQueryResult {
        pub rcode: u16,
        pub questions: Vec<DnsQuestion>,
        pub truncated: bool,
        pub recursion_desired: bool,
        pub recursion_available: bool,
        pub authentic_data: bool,
        pub checking_disabled: bool,
        pub answers: Vec<DnsRecord>,
        pub authorities: Vec<DnsRecord>,
        pub additionals: Vec<DnsRecord>,
    }

    #[derive(Default)]
    pub struct EngineStateParams {
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct EngineStatus {
        pub state: EngineState,
        /// Why the engine is `failed`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        /// Requested services that did not start, as of the last apply, patch, start or stop.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub faults: Vec<ServiceFault>,
    }

    pub struct ServiceFault {
        pub service: FaultService,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub address: String,
        pub reason: FaultReason,
        pub message: String,
    }

    pub struct TunStartParams {
        pub source: TunSource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stack: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mtu: Option<u32>,
        #[serde(default)]
        pub address: Vec<String>,
        #[serde(default)]
        pub dns: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub congestion_controller: Option<String>,
    }

    pub struct NetworkUpdateParams {
        /// Socket addresses of the resolvers the system now uses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dns_servers: Option<Vec<String>>,
        /// The default network changed: connections over the old one are closed.
        #[serde(default)]
        pub interface_changed: bool,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FaultService {
    Mixed,
    Http,
    Socks,
    Redir,
    Tproxy,
    Tun,
    Dns,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FaultReason {
    AddressInUse,
    AddressNotAvailable,
    PermissionDenied,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EngineState {
    Created,
    Initialized,
    Configured,
    Running,
    Failed,
}

/// A device the core creates itself, or a descriptor the host opened and
/// registered beforehand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TunSource {
    Device {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Inherited {
        handle: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ResourceKind {
    ProxyProvider,
    RuleProvider,
    Geo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ResourcePhase {
    Updating,
    Updated,
    /// Fetched, and the same as the content in force.
    Unchanged,
    Failed,
}

/// One entry of `events.watch`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CoreEvent {
    /// One step of a fetch of a provider or a geo database, whatever started
    /// it: its first load, a retry, its interval, its file changing, or a
    /// caller. A geo database is named `MMDB`, `ASN` or `GEOSITE`, as
    /// `geo.update` names it. Every step of a provider's first load waits
    /// until the `config.apply` that made it has finished. A fetch cut short by
    /// a newer apply or by shutdown ends `failed` with the error `superseded`.
    ResourceUpdate {
        kind: ResourceKind,
        name: String,
        phase: ResourcePhase,
        /// Set when `phase` is `failed`.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        error: String,
    },
    DialerLoop {
        name: String,
    },
    Delay {
        name: String,
        url: String,
        value: i32,
    },
    Fatal {
        message: String,
    },
    /// Sent only to a watch that asked for `state`.
    StateChanged {
        seq: u64,
        origin: ChangeOrigin,
        change: StateChangeKind,
    },
}

/// One entry of `delay.run`: a result for each proxy, then `done`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DelayRunEvent {
    Result {
        name: String,
        url: String,
        value: i32,
    },
    Done,
}

pub type RouteSnapshot = RouteStamp;
