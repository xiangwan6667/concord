use indexmap::IndexMap;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IpVersionPref {
    #[default]
    Dual,
    V4,
    V6,
    V4Prefer,
    V6Prefer,
}

impl IpVersionPref {
    pub fn parse(text: &str) -> IpVersionPref {
        match text.to_ascii_lowercase().as_str() {
            "ipv4" => IpVersionPref::V4,
            "ipv6" => IpVersionPref::V6,
            "ipv4-prefer" => IpVersionPref::V4Prefer,
            "ipv6-prefer" => IpVersionPref::V6Prefer,
            _ => IpVersionPref::Dual,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            IpVersionPref::Dual => "dual",
            IpVersionPref::V4 => "ipv4",
            IpVersionPref::V6 => "ipv6",
            IpVersionPref::V4Prefer => "ipv4-prefer",
            IpVersionPref::V6Prefer => "ipv6-prefer",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommonOpts {
    pub tfo: bool,
    pub mptcp: bool,
    pub interface_name: String,
    pub routing_mark: u32,
    pub ip_version: IpVersionPref,
    pub dialer_proxy: String,
    pub udp: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealityOpts {
    pub public_key: String,
    pub short_id: String,
    pub support_x25519_mlkem768: bool,
    pub client_version: Option<[u8; 3]>,
    pub mldsa65_verify: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EchOpts {
    pub enable: bool,
    pub config: String,
    pub query_server_name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JlsOpts {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JlsPlugin {
    pub host: String,
    pub auth: JlsOpts,
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsOpts {
    pub enabled: bool,
    pub server_name: String,
    pub alpn: Vec<String>,
    /// `alpn` was written, even as `[]`, which trojan keeps apart from its default.
    pub alpn_set: bool,
    pub skip_cert_verify: bool,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub name_cert_verify: String,
    pub client_fingerprint: String,
    pub reality: Option<RealityOpts>,
    pub jls: Option<JlsOpts>,
    pub ech: Option<EchOpts>,
    pub shadow_tls: Option<ShadowTlsLayer>,
}

/// `shadow-tls-opts`: the ShadowTLS handshake takes the place of the node's TLS, which supplies
/// the decoy's name, certificate checks and fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowTlsLayer {
    pub password: String,
    pub version: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BrutalOpts {
    pub enabled: bool,
    pub up: String,
    pub down: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmuxOpts {
    pub enabled: bool,
    pub protocol: String,
    pub max_connections: u32,
    pub min_streams: u32,
    pub max_streams: u32,
    pub padding: bool,
    pub statistic: bool,
    pub only_tcp: bool,
    pub brutal: Option<BrutalOpts>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsOpts {
    pub path: String,
    pub headers: IndexMap<String, String>,
    pub max_early_data: u32,
    pub early_data_header_name: String,
    pub v2ray_http_upgrade: bool,
    pub v2ray_http_upgrade_fast_open: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrpcOpts {
    pub service_name: String,
    pub user_agent: String,
    pub ping_interval: u32,
    pub max_connections: u32,
    pub min_streams: u32,
    pub max_streams: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct H2Opts {
    pub host: Vec<String>,
    pub path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpOpts {
    pub method: String,
    pub path: Vec<String>,
    pub headers: IndexMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XhttpReuse {
    pub max_concurrency: String,
    pub max_connections: String,
    pub c_max_reuse_times: String,
    pub h_max_request_times: String,
    pub h_max_reusable_secs: String,
    pub h_keep_alive_period: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XhttpDownload {
    pub path: Option<String>,
    pub host: Option<String>,
    pub headers: Option<IndexMap<String, String>>,
    pub reuse: Option<XhttpReuse>,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub tls: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub reality: Option<RealityOpts>,
    pub jls: Option<JlsOpts>,
    pub skip_cert_verify: Option<bool>,
    pub name_cert_verify: Option<String>,
    pub fingerprint: Option<String>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub server_name: Option<String>,
    pub client_fingerprint: Option<String>,
    pub ech: Option<EchOpts>,
    /// `Some(None)` turns off the node's ShadowTLS for this side.
    pub shadow_tls: Option<Option<ShadowTlsLayer>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XhttpOpts {
    pub path: String,
    pub host: String,
    pub mode: String,
    pub headers: IndexMap<String, String>,
    pub no_grpc_header: bool,
    pub x_padding_bytes: String,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: String,
    pub x_padding_method: String,
    pub uplink_http_method: String,
    pub session_placement: String,
    pub session_key: String,
    pub session_table: String,
    pub session_length: String,
    pub seq_placement: String,
    pub seq_key: String,
    pub uplink_data_placement: String,
    pub uplink_data_key: String,
    pub uplink_chunk_size: String,
    pub sc_max_each_post_bytes: String,
    pub sc_min_posts_interval_ms: String,
    pub reuse: Option<XhttpReuse>,
    pub download: Option<Box<XhttpDownload>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    #[default]
    Tcp,
    Ws(WsOpts),
    Grpc(GrpcOpts),
    H2(H2Opts),
    Http(HttpOpts),
    Xhttp(Box<XhttpOpts>),
}

impl Transport {
    pub fn name(&self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Ws(_) => "ws",
            Transport::Grpc(_) => "grpc",
            Transport::H2(_) => "h2",
            Transport::Http(_) => "http",
            Transport::Xhttp(_) => "xhttp",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GostRelayOpts {
    pub server: String,
    pub port: u16,
    pub forward: bool,
    pub mux: bool,
    pub username: String,
    pub password: String,
    pub tls: TlsOpts,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectOpts;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RejectOpts;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsOpts;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SsPlugin {
    Obfs { mode: String, host: String },
    V2ray(Box<V2rayPlugin>),
    Gost(Box<V2rayPlugin>),
    ShadowTls(ShadowTlsOpts),
    Jls(JlsPlugin),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShadowTlsOpts {
    pub host: String,
    pub password: String,
    pub version: u8,
    pub fingerprint: String,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub certificate: String,
    pub private_key: String,
    pub name_cert_verify: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V2rayPlugin {
    pub mode: String,
    pub host: String,
    pub path: String,
    pub tls: bool,
    pub ech: Option<EchOpts>,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub headers: IndexMap<String, String>,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub mux: bool,
    pub v2ray_http_upgrade: bool,
    pub v2ray_http_upgrade_fast_open: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SsOpts {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub plugin: Option<SsPlugin>,
    pub udp_over_tcp: bool,
    pub udp_over_tcp_version: u8,
    pub client_fingerprint: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmessOpts {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub alter_id: u32,
    pub cipher: String,
    pub tls: TlsOpts,
    pub transport: Transport,
    pub packet_addr: bool,
    pub xudp: bool,
    pub packet_encoding: String,
    pub global_padding: bool,
    pub authenticated_length: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VlessOpts {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub flow: String,
    pub encryption: String,
    pub tls: TlsOpts,
    pub transport: Transport,
    pub packet_addr: bool,
    pub xudp: bool,
    pub packet_encoding: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrojanSsOpts {
    pub enabled: bool,
    pub method: String,
    pub password: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrojanOpts {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub tls: TlsOpts,
    pub transport: Transport,
    pub ss: Option<TrojanSsOpts>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hysteria2Realm {
    pub enable: bool,
    pub server_url: String,
    pub token: String,
    pub realm_id: String,
    pub stun_servers: Vec<String>,
    pub sni: String,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hysteria2Opts {
    pub server: String,
    pub port: u16,
    pub ports: String,
    pub hop_interval: String,
    pub up: String,
    pub down: String,
    pub password: String,
    pub obfs: String,
    pub obfs_password: String,
    pub obfs_min_packet_size: u32,
    pub obfs_max_packet_size: u32,
    pub tls: TlsOpts,
    pub cwnd: u32,
    pub bbr_profile: String,
    pub udp_mtu: u32,
    pub handshake_timeout: u32,
    pub realm: Option<Hysteria2Realm>,
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TuicOpts {
    pub server: String,
    pub port: u16,
    pub token: String,
    pub uuid: String,
    pub password: String,
    pub ip: String,
    pub heartbeat_interval: u32,
    pub tls: TlsOpts,
    pub reduce_rtt: bool,
    pub request_timeout: u32,
    pub udp_relay_mode: String,
    pub congestion_controller: String,
    pub disable_sni: bool,
    pub max_udp_relay_packet_size: u32,
    pub fast_open: bool,
    pub max_open_streams: u32,
    pub cwnd: u32,
    pub bbr_profile: String,
    pub recv_window_conn: u32,
    pub recv_window: u32,
    pub disable_mtu_discovery: bool,
    pub max_datagram_frame_size: u32,
    pub udp_over_stream: bool,
    pub udp_over_stream_version: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MiuOpts {
    pub server: String,
    pub port: u16,
    pub psk: String,
    pub tls: TlsOpts,
    pub idle_session_timeout: u64,
    pub min_idle_session: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnyTlsOpts {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub tls: TlsOpts,
    pub client_metadata: String,
    pub idle_session_check_interval: u32,
    pub idle_session_timeout: u32,
    pub min_idle_session: u32,
    pub disable_reuse: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Socks5Opts {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tls: TlsOpts,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpProxyOpts {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tls: TlsOpts,
    pub headers: IndexMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WgPeer {
    pub server: String,
    pub port: u16,
    pub public_key: String,
    pub pre_shared_key: String,
    pub reserved: Vec<u8>,
    pub allowed_ips: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AmneziaWgOpts {
    pub version: u32,
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
    pub s1: u32,
    pub s2: u32,
    pub s3: u32,
    pub s4: u32,
    pub h: [String; 4],
    pub i: [String; 5],
    pub j: [String; 3],
    pub itime: i64,
    pub header_protection_key: String,
    pub content_padding_addition: String,
    pub rekey_after_time: String,
    pub rekey_timeout: String,
    pub reject_after_time: String,
    pub keepalive_timeout: String,
    pub max_handshake_attempts: String,
    pub random_trailers: bool,
    pub disable_cookies: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MasqueOpts {
    pub server: String,
    pub port: u16,
    pub private_key: String,
    pub public_key: String,
    pub ip: String,
    pub ipv6: String,
    pub uri: String,
    pub sni: String,
    pub mtu: u32,
    pub handshake_timeout: u64,
    pub skip_cert_verify: bool,
    pub network: String,
    pub congestion_controller: String,
    pub cwnd: u32,
    pub bbr_profile: String,
    pub ip_stack_mode: String,
    pub ip_stack_congestion_controller: String,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireGuardOpts {
    pub ip: String,
    pub ipv6: String,
    pub private_key: String,
    pub workers: u32,
    pub mtu: u32,
    pub persistent_keepalive: u32,
    pub ip_stack_mode: String,
    pub ip_stack_congestion_controller: String,
    pub amnezia: Option<AmneziaWgOpts>,
    pub peers: Vec<WgPeer>,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
    pub refresh_server_ip_interval: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HysteriaOpts {
    pub server: String,
    pub port: u16,
    pub ports: String,
    pub protocol: String,
    pub obfs_protocol: String,
    pub up: String,
    pub up_speed: u32,
    pub down: String,
    pub down_speed: u32,
    pub auth: String,
    pub auth_str: String,
    pub obfs: String,
    pub tls: TlsOpts,
    pub recv_window_conn: u32,
    pub recv_window: u32,
    pub disable_mtu_discovery: bool,
    pub fast_open: bool,
    pub hop_interval: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SsrOpts {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub obfs: String,
    pub obfs_param: String,
    pub protocol: String,
    pub protocol_param: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnellOpts {
    pub mode: String,
    pub userkey: String,
    pub server: String,
    pub port: u16,
    pub psk: String,
    pub version: u32,
    pub reuse: bool,
    pub obfs_mode: String,
    pub obfs_host: String,
    pub shadow_tls: Option<ShadowTlsOpts>,
    pub jls: Option<JlsPlugin>,
    pub client_fingerprint: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MieruOpts {
    pub server: String,
    pub port: u16,
    pub port_range: String,
    pub transport: String,
    pub username: String,
    pub password: String,
    pub multiplexing: String,
    pub handshake_mode: String,
    pub traffic_pattern: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshOpts {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub private_key: String,
    pub private_key_passphrase: String,
    pub host_key: Vec<String>,
    pub host_key_algorithms: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShadowQuicOpts {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub quic_versions: Vec<String>,
    pub udp_over_stream: bool,
    pub zero_rtt: bool,
    pub keep_alive_interval: u32,
    pub congestion_controller: String,
    pub up: String,
    pub down: String,
    pub cwnd: u32,
    pub bbr_profile: String,
    pub recv_window_conn: u32,
    pub recv_window: u32,
    pub disable_mtu_discovery: bool,
    pub max_datagram_frame_size: u32,
    pub max_open_streams: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RematchOpts {
    pub target_rematch_name: Option<String>,
    pub target_sub_rule: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    Direct(DirectOpts),
    Reject(RejectOpts),
    Dns(DnsOpts),
    Rematch(RematchOpts),
    Ss(SsOpts),
    Vmess(Box<VmessOpts>),
    Vless(Box<VlessOpts>),
    Trojan(Box<TrojanOpts>),
    Hysteria2(Box<Hysteria2Opts>),
    Tuic(Box<TuicOpts>),
    AnyTls(Box<AnyTlsOpts>),
    Miu(Box<MiuOpts>),
    Socks5(Socks5Opts),
    GostRelay(Box<GostRelayOpts>),
    Http(HttpProxyOpts),
    WireGuard(Box<WireGuardOpts>),
    Masque(Box<MasqueOpts>),
    Hysteria(Box<HysteriaOpts>),
    Ssr(SsrOpts),
    Snell(SnellOpts),
    Mieru(MieruOpts),
    Ssh(SshOpts),
    ShadowQuic(Box<ShadowQuicOpts>),
}

impl ProxyKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            ProxyKind::Direct(_) => "direct",
            ProxyKind::Reject(_) => "reject",
            ProxyKind::Dns(_) => "dns",
            ProxyKind::Rematch(_) => "rematch",
            ProxyKind::Ss(_) => "ss",
            ProxyKind::Vmess(_) => "vmess",
            ProxyKind::Vless(_) => "vless",
            ProxyKind::Trojan(_) => "trojan",
            ProxyKind::Hysteria2(_) => "hysteria2",
            ProxyKind::Tuic(_) => "tuic",
            ProxyKind::AnyTls(_) => "anytls",
            ProxyKind::Miu(_) => "miu",
            ProxyKind::Socks5(_) => "socks5",
            ProxyKind::GostRelay(_) => "gost-relay",
            ProxyKind::Http(_) => "http",
            ProxyKind::WireGuard(_) => "wireguard",
            ProxyKind::Masque(_) => "masque",
            ProxyKind::Hysteria(_) => "hysteria",
            ProxyKind::Ssr(_) => "ssr",
            ProxyKind::Snell(_) => "snell",
            ProxyKind::Mieru(_) => "mieru",
            ProxyKind::Ssh(_) => "ssh",
            ProxyKind::ShadowQuic(_) => "shadowquic",
        }
    }

    pub fn server(&self) -> Option<(&str, u16)> {
        match self {
            ProxyKind::Direct(_)
            | ProxyKind::Reject(_)
            | ProxyKind::Dns(_)
            | ProxyKind::Rematch(_)
            | ProxyKind::WireGuard(_) => None,
            ProxyKind::Masque(o) => Some((&o.server, o.port)),

            ProxyKind::Ss(o) => Some((&o.server, o.port)),
            ProxyKind::Vmess(o) => Some((&o.server, o.port)),
            ProxyKind::Vless(o) => Some((&o.server, o.port)),
            ProxyKind::Trojan(o) => Some((&o.server, o.port)),
            ProxyKind::Hysteria2(o) => Some((&o.server, o.port)),
            ProxyKind::Tuic(o) => Some((&o.server, o.port)),
            ProxyKind::AnyTls(o) => Some((&o.server, o.port)),
            ProxyKind::Miu(o) => Some((&o.server, o.port)),
            ProxyKind::Socks5(o) => Some((&o.server, o.port)),
            ProxyKind::GostRelay(o) => Some((&o.server, o.port)),
            ProxyKind::Http(o) => Some((&o.server, o.port)),
            ProxyKind::Hysteria(o) => Some((&o.server, o.port)),
            ProxyKind::Ssr(o) => Some((&o.server, o.port)),
            ProxyKind::Snell(o) => Some((&o.server, o.port)),
            ProxyKind::Mieru(o) => Some((&o.server, o.port)),
            ProxyKind::Ssh(o) => Some((&o.server, o.port)),
            ProxyKind::ShadowQuic(o) => Some((&o.server, o.port)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyDef {
    pub name: String,
    pub common: CommonOpts,
    pub kind: ProxyKind,
    pub smux: Option<SmuxOpts>,
    /// Keys read past with a reason, reported as warnings.
    pub ignored: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyParse {
    Ok(Box<ProxyDef>),
    Quarantined {
        name: String,
        kind: String,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quarantined {
    pub index: Option<usize>,
    pub provider: Option<String>,
    pub name: String,
    pub kind: String,
    pub reason: String,
}
