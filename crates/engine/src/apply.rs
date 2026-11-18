use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, ClockOffset, CoreOptions, DialEnv, EventSink, HostResolver, NodeDialer,
    PacketSession, SockOpts,
};
use concord_config::general::General;
use concord_config::ntp::NtpConfig;
use concord_config::sniffer::{SniffProtocol, SnifferConfig};
use concord_config::tun::TunConfig;
use concord_config::{Capabilities, ConfigError, LoadOptions, Profile, RawConfig};
use concord_dns::{
    DnsError, DomainMatch, GeoIpLookup, RESPECT_RULES, Resolver, ResolverDeps, RuleEnv, RuleError,
    UpstreamDialer, domain_matchers, ip_matchers,
};
use concord_group::{
    EnvFactory, GroupDeps, GroupError, Outbounds, ProxyFactory, RouteMoved, SelectionStore,
    TestDefaults,
};
use concord_inbound::ListenSpec;
use concord_net::{LoopbackGuard, Sockets};
use concord_platform::{HomeDir, Platform};
use concord_proxy::BuildCtx;
use concord_rules::geo::{GeoError, GeoFile, GeoStore};
use concord_rules::{CompileEnv, CompileError, RouteProgram, RuleSetStore};
use concord_tls::{SystemRoots, TrustStore, parse_certificates};
use concord_tun::{Congestion, Prefix, TunDevice};
use concord_tunnel::sniff::{Dispatcher, DispatcherConfig, SnifferEntry, SnifferKind};
use concord_tunnel::{Runtime, Tunnel};
use rustls_pki_types::CertificateDer;
use tokio_util::sync::CancellationToken;

use crate::error::{Failure, GeoUpdateError, RuleLoadError};
use crate::fake_ip_store::FakeIpStore;
use crate::lan;
use crate::ops::on_parse_stack;
use crate::resources::{GeoUpdater, GeoUrls, RuleProviders, TunnelFetcher};
use crate::route::RouteCounters;
use crate::views::WarningView;

pub(crate) struct Options {
    pub current: Arc<ArcSwap<CoreOptions>>,
    pub unified_delay: AtomicBool,
}

impl TestDefaults for Options {
    fn test_url(&self) -> Option<String> {
        let options = self.current.load();
        (!options.test_url.is_empty()).then(|| options.test_url.clone())
    }

    fn delay_timeout(&self) -> Option<std::time::Duration> {
        let millis = self.current.load().delay_test_timeout;
        u64::try_from(millis)
            .ok()
            .filter(|millis| *millis > 0)
            .map(std::time::Duration::from_millis)
    }

    fn unified_delay(&self) -> bool {
        self.unified_delay.load(Ordering::Relaxed)
    }
}

struct Moved(Arc<RouteCounters>);

impl RouteMoved for Moved {
    fn moved(&self) {
        self.0.moved();
    }
}

/// DNS over a proxy reaches its upstream through the tunnel, by name or by rules.
pub(crate) struct TunnelUpstream {
    pub tunnel: Tunnel,
}

fn via_proxy(via: &str) -> Option<&str> {
    (via != RESPECT_RULES).then_some(via)
}

#[async_trait]
impl UpstreamDialer for TunnelUpstream {
    fn knows(&self, via: &str) -> bool {
        self.tunnel
            .runtime()
            .is_some_and(|runtime| runtime.outbounds.node(via).is_some())
    }

    async fn connect(&self, via: &str, target: &Address) -> std::io::Result<BoxStream> {
        self.tunnel.dial_inner(target, via_proxy(via)).await
    }

    async fn bind_udp(
        &self,
        via: &str,
        target: &Address,
    ) -> std::io::Result<Arc<dyn PacketSession>> {
        self.tunnel.associate_inner(target, via_proxy(via)).await
    }
}

/// What DNS matchers ask of geo data and rule sets. A geo error goes back as the
/// `DnsError` source, so the apply can fetch a missing file and build again.
struct DnsRules {
    geo: Arc<GeoStore>,
    rule_sets: Arc<RuleSetStore>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum GeoProblem {
    Missing(GeoFile),
    Invalid(GeoFile),
}

impl GeoProblem {
    fn of(err: &GeoError) -> Option<GeoProblem> {
        match err {
            GeoError::Missing { file, .. } => Some(GeoProblem::Missing(*file)),
            GeoError::Invalid { file, .. } => Some(GeoProblem::Invalid(*file)),
            GeoError::Load(_) => None,
        }
    }

    fn in_dns(err: &DnsError) -> Option<GeoProblem> {
        let mut source = std::error::Error::source(err);
        while let Some(err) = source {
            if let Some(geo) = err.downcast_ref::<GeoError>() {
                return GeoProblem::of(geo);
            }
            source = err.source();
        }
        None
    }
}

struct SiteMatch(Arc<concord_rules::geo::SiteSlot>);

impl DomainMatch for SiteMatch {
    fn matches(&self, domain: &str) -> bool {
        self.0.matches(domain)
    }
}

struct RuleSetMatch(Arc<concord_rules::RuleSetHandle>, Arc<GeoStore>);

impl DomainMatch for RuleSetMatch {
    fn matches(&self, domain: &str) -> bool {
        self.0.match_domain(domain, &self.1)
    }
}

struct RuleSetIp(Arc<concord_rules::RuleSetHandle>, Arc<GeoStore>);

impl concord_dns::IpMatch for RuleSetIp {
    fn matches(&self, ip: IpAddr) -> bool {
        self.0.match_ip(ip, &self.1)
    }
}

struct GeoMatch(Arc<GeoStore>);

impl GeoIpLookup for GeoMatch {
    fn country_codes(&self, ip: IpAddr) -> Vec<String> {
        self.0.country_codes(ip)
    }
}

impl RuleEnv for DnsRules {
    fn geosite(&self, name: &str) -> Result<Arc<dyn DomainMatch>, RuleError> {
        match self.geo.site_slot(name) {
            Ok(slot) => Ok(Arc::new(SiteMatch(slot))),
            Err(err) => Err(err.into()),
        }
    }

    fn domain_rule_set(&self, name: &str) -> Result<Arc<dyn DomainMatch>, RuleError> {
        let handle = self
            .rule_sets
            .get(name)
            .ok_or_else(|| format!("rule-set {name} not found"))?;
        Ok(Arc::new(RuleSetMatch(handle, self.geo.clone())))
    }

    fn geoip(&self) -> Result<Arc<dyn GeoIpLookup>, RuleError> {
        match self.geo.ensure(GeoFile::Mmdb) {
            Ok(()) => Ok(Arc::new(GeoMatch(self.geo.clone()))),
            Err(err) => Err(err.into()),
        }
    }

    fn ip_rule_set(&self, name: &str) -> Result<Arc<dyn concord_dns::IpMatch>, RuleError> {
        let handle = self
            .rule_sets
            .get(name)
            .ok_or_else(|| format!("not found rule-set: {name}"))?;
        if handle.behavior() == concord_rules::Behavior::Domain {
            return Err(format!(
                "rule provider type error, expect ipcidr,actual {}",
                handle.behavior().name()
            )
            .into());
        }
        Ok(Arc::new(RuleSetIp(handle, self.geo.clone())))
    }
}

struct SniffDomain(Arc<dyn DomainMatch>);

impl concord_tunnel::sniff::DomainMatch for SniffDomain {
    fn matches(&self, domain: &str) -> bool {
        self.0.matches(domain)
    }
}

struct SniffIp(Arc<dyn concord_dns::IpMatch>);

impl concord_tunnel::sniff::IpMatch for SniffIp {
    fn matches(&self, ip: IpAddr) -> bool {
        self.0.matches(ip)
    }
}

fn sniffer_of(config: &SnifferConfig, rules: &dyn RuleEnv) -> Result<Dispatcher, ApplyError> {
    let domains = |entries: &[String], what: &str| {
        domain_matchers(entries, what, rules)
            .map(|matchers| {
                matchers
                    .into_iter()
                    .map(|matcher| {
                        Arc::new(SniffDomain(matcher))
                            as Arc<dyn concord_tunnel::sniff::DomainMatch>
                    })
                    .collect::<Vec<_>>()
            })
            .map_err(ApplyError::Dns)
    };
    let ips = |items: &concord_config::sniffer::SniffIps, what: &'static str| {
        ip_matchers(items.cidrs.clone(), &items.geoip, &items.rule_sets, rules)
            .map(|matchers| {
                matchers
                    .into_iter()
                    .map(|matcher| {
                        Arc::new(SniffIp(matcher)) as Arc<dyn concord_tunnel::sniff::IpMatch>
                    })
                    .collect::<Vec<_>>()
            })
            .map_err(|source| ApplyError::SnifferIps { what, source })
    };
    Ok(Dispatcher::new(DispatcherConfig {
        enable: config.enable,
        sniffers: config
            .sniff
            .iter()
            .map(|entry| SnifferEntry {
                kind: match entry.protocol {
                    SniffProtocol::Tls => SnifferKind::Tls,
                    SniffProtocol::Http => SnifferKind::Http,
                    SniffProtocol::Quic => SnifferKind::Quic,
                },
                ports: entry
                    .ports
                    .iter()
                    .map(|range| (range.start, range.end))
                    .collect(),
                override_dest: entry.override_destination,
            })
            .collect(),
        force_domain: domains(&config.force_domain, "sniffer.force-domain")?,
        skip_domain: domains(&config.skip_domain, "sniffer.skip-domain")?,
        skip_src: ips(&config.skip_src_address, "sniffer.skip-src-address")?,
        skip_dst: ips(&config.skip_dst_address, "sniffer.skip-dst-address")?,
        force_dns_mapping: config.force_dns_mapping,
        parse_pure_ip: config.parse_pure_ip,
    }))
}

/// mihomo turns keep-alive off on Android for dialed and accepted sockets alike.
fn keep_alive_disabled(general: &General) -> bool {
    !concord_platform::KEEP_ALIVE || general.disable_keep_alive
}

pub(crate) fn sock_opts(general: &General) -> SockOpts {
    SockOpts {
        interface: (!general.interface_name.is_empty())
            .then(|| Arc::from(general.interface_name.as_str())),
        routing_mark: (general.routing_mark != 0).then_some(general.routing_mark),
        tfo: false,
        mptcp: false,
        keep_alive_idle_secs: general.keep_alive_idle,
        keep_alive_interval_secs: general.keep_alive_interval,
        disable_keep_alive: keep_alive_disabled(general),
        tunnel_udp_buffers: false,
    }
}

pub(crate) fn listen_spec(general: &General) -> ListenSpec {
    let port = |port: u16| (port != 0).then_some(port);
    ListenSpec {
        mixed_port: port(general.mixed_port),
        http_port: port(general.port),
        socks_port: port(general.socks_port),
        redir_port: port(general.redir_port),
        tproxy_port: port(general.tproxy_port),
        allow_lan: general.allow_lan,
        bind_address: general.bind_address.clone(),
        lan_allowed_ips: lan::cidrs(&general.lan_allowed_ips),
        lan_disallowed_ips: lan::cidrs(&general.lan_disallowed_ips),
        authentication: general
            .authentication
            .iter()
            .map(|credential| (credential.user.clone(), credential.pass.clone()))
            .collect(),
        skip_auth: lan::cidrs(&general.skip_auth_prefixes),
        tcp_keepalive: !keep_alive_disabled(general),
        keepalive_idle_secs: general.keep_alive_idle,
        keepalive_interval_secs: general.keep_alive_interval,
        ..ListenSpec::default()
    }
}

/// What one config needs for as long as it is in force.
pub(crate) struct Applied {
    pub general: General,
    pub ntp: NtpConfig,
    pub tun: TunConfig,
    pub tun_inet4: Option<Prefix>,
    pub dns_listen: String,
    pub dns_listen_mark: u32,
    pub store_fake_ip: bool,
    pub sniffing: bool,
    pub stop: CancellationToken,
}

/// A built config, not yet in force.
pub(crate) struct Built {
    pub runtime: Arc<Runtime>,
    pub applied: Applied,
    pub outbounds: Arc<Outbounds>,
    pub rule_providers: Arc<RuleProviders>,
    pub deferred_geo: Vec<GeoFile>,
    pub warnings: Vec<WarningView>,
    pub mitm: concord_config::MitmDef,
    pub trust: Arc<TrustStore>,
}

const CA_BUNDLE: &[u8] = include_bytes!("../../../assets/ca-certificates.crt");

pub(crate) struct TrustCache {
    system: Arc<SystemRoots>,
    current: Mutex<Option<(Vec<String>, Arc<TrustStore>)>>,
    clock: Arc<ClockOffset>,
}

impl TrustCache {
    pub fn new(clock: Arc<ClockOffset>) -> Self {
        TrustCache {
            system: Arc::default(),
            current: Mutex::new(None),
            clock,
        }
    }

    pub fn for_custom(&self, custom: Vec<String>) -> Arc<TrustStore> {
        let mut current = lock(&self.current);
        if let Some((held, store)) = current.as_ref()
            && *held == custom
        {
            return store.clone();
        }
        let mut certs = Vec::new();
        for text in &custom {
            let parsed = parse_certificates(text);
            if parsed.is_empty() {
                tracing::warn!("{text}\nadd error: add certificate failed");
            }
            certs.extend(parsed);
        }
        let store = self.store(certs);
        *current = Some((custom, store.clone()));
        store
    }

    fn store(&self, custom: Vec<CertificateDer<'static>>) -> Arc<TrustStore> {
        TrustStore::with_system_roots(self.clock.clone(), self.system.clone(), CA_BUNDLE, custom)
    }
}

pub(crate) struct Shared {
    pub platform: Arc<dyn Platform>,
    pub sockets: Arc<Sockets>,
    pub loopback: Option<Arc<LoopbackGuard>>,
    pub tunnel: Tunnel,
    pub route: Arc<RouteCounters>,
    pub options: Arc<Options>,
    pub trust: TrustCache,
    pub clock: Arc<ClockOffset>,
    pub events: Arc<dyn EventSink>,
    pub geo: Arc<GeoUpdater>,
    pub fetcher: Arc<TunnelFetcher>,
    pub upstream: Arc<TunnelUpstream>,
    /// Those of the config in force; the next config starts its rule sets from them.
    pub rule_providers: ArcSwapOption<RuleProviders>,
    pub fake_ip_store: Arc<FakeIpStore>,
    pub android: bool,
    pub proxy_tasks: crate::proxy_tasks::ProxyTasks,
}

/// Why a config could not be applied. Only the text reaches the host, as the failure message.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApplyError {
    #[error("open {path}: {source}")]
    Open { path: String, source: io::Error },
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Save(io::Error),
    #[error("{}", .0.message)]
    Parse(Failure),
    #[error(transparent)]
    Providers(#[from] RuleLoadError),
    #[error(transparent)]
    Rules(#[from] CompileError),
    #[error(transparent)]
    GeoFetch(#[from] GeoUpdateError),
    #[error(transparent)]
    Dns(#[from] DnsError),
    #[error("{what}: {source}")]
    SnifferIps {
        what: &'static str,
        source: DnsError,
    },
    #[error(transparent)]
    Outbounds(#[from] GroupError),
    #[error(transparent)]
    OutboundsTask(tokio::task::JoinError),
}

pub(crate) async fn load_profile(
    shared: &Shared,
    home: &Arc<HomeDir>,
    base: Option<(String, String)>,
) -> Result<Profile, ApplyError> {
    let android = shared.android;
    let home = home.clone();
    on_parse_stack(move || {
        let path = home.join("config.yaml");
        let raw = match base {
            Some((source, overlay)) => {
                let source = std::fs::read(&source).map_err(|err| ApplyError::Open {
                    path: source,
                    source: err,
                })?;
                let merged = concord_config::merge_document(&source, &overlay, None)?;
                drop(source);
                let raw = RawConfig::from_document(merged)?;
                let text = concord_config::raw_to_yaml(&raw);
                home.write_atomic(&path, text.as_bytes())
                    .map_err(ApplyError::Save)?;
                drop(text);
                raw
            }
            None => {
                let bytes = std::fs::read(&path).map_err(|err| ApplyError::Open {
                    path: path.display().to_string(),
                    source: err,
                })?;
                concord_config::parse_raw(&bytes)?
            }
        };
        let options = LoadOptions {
            capabilities: capabilities(),
            android,
            age_secret_key: None,
        };
        Ok(concord_config::load_raw(raw, &options)?)
    })
    .await
    .map_err(ApplyError::Parse)?
}

async fn compile_program(
    shared: &Shared,
    profile: &mut Profile,
    env: &Arc<CompileEnv>,
) -> Result<RouteProgram, ApplyError> {
    let rules = Arc::new(std::mem::take(&mut profile.rules));
    let sub_rules = Arc::new(std::mem::take(&mut profile.sub_rules));
    // As mihomo, each geo file is downloaded at most once while missing and once while invalid.
    let mut fetched = HashSet::new();
    loop {
        let rules = rules.clone();
        let sub_rules = sub_rules.clone();
        let env_for_parse = env.clone();
        let compiled =
            on_parse_stack(move || RouteProgram::compile_lines(&rules, &sub_rules, &env_for_parse))
                .await
                .map_err(ApplyError::Parse)?;
        match compiled {
            Ok(program) => return Ok(program),
            Err(err) => match geo_problem(&err) {
                Some(problem) if fetched.insert(problem) => fetch_geo(shared, problem).await?,
                _ => return Err(err.into()),
            },
        }
    }
}

fn geo_problem(err: &CompileError) -> Option<GeoProblem> {
    err.missing_geo_file()
        .map(GeoProblem::Missing)
        .or_else(|| err.invalid_geo_file().map(GeoProblem::Invalid))
}

async fn fetch_geo(shared: &Shared, problem: GeoProblem) -> Result<(), ApplyError> {
    match problem {
        GeoProblem::Missing(file) => shared.geo.fetch_missing(file, &*shared.fetcher).await,
        GeoProblem::Invalid(file) => shared.geo.replace_invalid(file, &*shared.fetcher).await,
    }
    .map_err(ApplyError::from)
}

/// What this build can run: nodes outside it are quarantined, and a rule outside it
/// refuses the config. mihomo reads a UID only on Linux and Android.
pub(crate) fn capabilities() -> Capabilities {
    let mut capabilities = concord_proxy::capabilities();
    if !concord_platform::owner::READS_UID {
        capabilities.rule_types.retain(|name| *name != "UID");
    }
    capabilities
}

/// Builds without touching anything in force, so a failure leaves the running
/// config as it is until the caller decides what replaces it.
pub(crate) async fn build(
    shared: &Shared,
    home: &Arc<HomeDir>,
    mut profile: Profile,
    selections: Arc<SelectionStore>,
) -> Result<Built, ApplyError> {
    shared
        .geo
        .urls
        .store(Arc::new(GeoUrls::from_config(&profile.geo)));
    shared
        .fetcher
        .user_agent
        .store(Arc::new(user_agent(&profile.general)));
    let trust = shared
        .trust
        .for_custom(profile.tls.custom_certificates.clone());
    shared.fetcher.trust.store(trust.clone());

    let store = Arc::new(RuleSetStore::new());
    let rule_providers = Arc::new(RuleProviders::new(
        &profile.rule_providers,
        &store,
        &shared.geo,
        home.clone(),
        shared.fetcher.clone(),
        shared.events.clone(),
        shared.route.clone(),
    )?);
    if let Some(previous) = shared.rule_providers.load().as_deref() {
        carry_rule_sets(&rule_providers, previous);
    }
    let env = Arc::new(CompileEnv::new(shared.geo.store.clone(), store.clone()));
    let program = compile_program(shared, &mut profile, &env).await?;

    let rules = Arc::new(DnsRules {
        geo: shared.geo.store.clone(),
        rule_sets: store,
    });
    let opts = sock_opts(&profile.general);
    let dns = build_dns(shared, home, &profile, &rules, &trust, &opts).await?;

    let sniffer = Arc::new(sniffer_of(&profile.sniffer, rules.as_ref())?);
    let (profile, outbounds) =
        build_outbounds(shared, home, profile, selections, &dns, &trust, &opts).await?;

    shared.sockets.set_ip4p(profile.dialer_ip4p_convert);
    shared
        .options
        .unified_delay
        .store(profile.general.unified_delay, Ordering::Relaxed);

    let warnings = warning_views(&profile, shared.android);
    log_warnings(&warnings);
    let deferred_geo = program.deferred_geo().to_vec();

    let runtime = Arc::new(Runtime::new(
        program,
        outbounds.clone(),
        dns,
        sniffer,
        shared.geo.store.clone(),
        shared.platform.clone(),
    ));
    let applied = Applied {
        tun_inet4: crate::tun::inet4_of(profile.dns.fake_ip_range),
        dns_listen: if profile.dns.enable {
            profile.dns.listen.clone()
        } else {
            String::new()
        },
        dns_listen_mark: profile.dns.listen_routing_mark,
        store_fake_ip: profile.store_fake_ip,
        sniffing: profile.sniffer.enable,
        tun: profile.tun,
        ntp: profile.ntp,
        general: profile.general,
        stop: CancellationToken::new(),
    };
    Ok(Built {
        runtime,
        applied,
        outbounds,
        rule_providers,
        deferred_geo,
        warnings,
        mitm: profile.mitm,
        trust,
    })
}

async fn build_dns(
    shared: &Shared,
    home: &Arc<HomeDir>,
    profile: &Profile,
    rules: &Arc<DnsRules>,
    trust: &Arc<TrustStore>,
    opts: &SockOpts,
) -> Result<Arc<Resolver>, ApplyError> {
    let upstream: Arc<dyn UpstreamDialer> = shared.upstream.clone();
    let weak: Weak<dyn UpstreamDialer> = Arc::downgrade(&upstream);
    let mut fetched = HashSet::new();
    let dns = loop {
        let deps = ResolverDeps {
            sockets: shared.sockets.clone(),
            trust: trust.clone(),
            events: shared.events.clone(),
            platform: shared.platform.clone(),
            rules: rules.clone(),
            dialer: weak.clone(),
            sock_opts: opts.clone(),
            ipv6: profile.general.ipv6,
            store_fake_ip: profile.store_fake_ip,
        };
        match Resolver::new(&profile.dns, &profile.hosts, deps) {
            Ok(resolver) => break resolver,
            Err(err) => match GeoProblem::in_dns(&err) {
                Some(problem) if fetched.insert(problem) => fetch_geo(shared, problem).await?,
                _ => return Err(err.into()),
            },
        }
    };
    let carried = shared.tunnel.runtime().is_some_and(|previous| {
        dns.patch_from(&previous.dns);
        previous.dns.has_fake_ip_mappings()
    });
    if profile.store_fake_ip && !carried {
        shared.fake_ip_store.restore(home, &dns);
    }
    Ok(dns)
}

/// Starts each rule set with what the previous config's provider of the same name, source,
/// behavior and format holds, so its rules keep matching until this config's first load.
fn carry_rule_sets(providers: &RuleProviders, previous: &RuleProviders) {
    for provider in &providers.list {
        let def = &provider.def;
        if let Some(old) = previous.get(&def.name).filter(|old| {
            (&old.def.source, old.def.behavior, old.def.format)
                == (&def.source, def.behavior, def.format)
        }) {
            provider.handle.take_from(&old.handle);
        }
    }
}

async fn build_outbounds(
    shared: &Shared,
    home: &Arc<HomeDir>,
    mut profile: Profile,
    selections: Arc<SelectionStore>,
    dns: &Arc<Resolver>,
    trust: &Arc<TrustStore>,
    opts: &SockOpts,
) -> Result<(Profile, Arc<Outbounds>), ApplyError> {
    let env_factory: EnvFactory = {
        let sockets = shared.sockets.clone();
        let resolver: Arc<dyn HostResolver> = dns.clone();
        let events = shared.events.clone();
        let opts = opts.clone();
        let (tcp_concurrent, ipv6) = (profile.general.tcp_concurrent, profile.general.ipv6);
        Arc::new(move |nodes: Arc<dyn NodeDialer>| DialEnv {
            sockets: sockets.clone(),
            resolver: resolver.clone(),
            nodes,
            events: events.clone(),
            sock_opts: opts.clone(),
            tcp_concurrent,
            ipv6,
        })
    };
    let clock = shared.clock.clone();
    let mut ctx = BuildCtx::new(trust.clone())
        .with_home(home.clone())
        .with_clock(Arc::new(move || clock.now()));
    (ctx.loopback, ctx.tasks) = (shared.loopback.clone(), shared.proxy_tasks.tasks());
    let deps = GroupDeps {
        selections,
        env: env_factory,
        fetcher: shared.fetcher.clone(),
        events: shared.events.clone(),
        route: Arc::new(Moved(shared.route.clone())),
        options: shared.options.clone(),
        home: home.clone(),
        trust: trust.clone(),
        factory: Arc::new(ProxyFactory::new(ctx, capabilities())),
    };
    tokio::task::spawn_blocking(move || {
        let outbounds = Outbounds::build(&mut profile, deps)?;
        Ok((profile, outbounds))
    })
    .await
    .map_err(ApplyError::OutboundsTask)?
}

/// Everything an apply of `profile` warns about; `concord -t` reports the same list.
pub(crate) fn warning_views(profile: &Profile, android: bool) -> Vec<WarningView> {
    let mut warnings = profile
        .report
        .warnings
        .iter()
        .map(|warning| WarningView {
            level: match warning.level {
                concord_config::Level::Info => "info",
                concord_config::Level::Warning => "warning",
            },
            code: warning.code,
            path: warning.path.clone(),
            message: warning.message.clone(),
        })
        .collect::<Vec<_>>();
    warnings.extend(tun_congestion_warning(&profile.tun, android));
    warnings.extend(tun_offload_warning(&profile.tun, TunDevice::OFFLOADS));
    warnings
}

fn log_warnings(warnings: &[WarningView]) {
    for warning in warnings {
        if warning.level == "info" {
            tracing::info!("[Config] {}: {}", warning.path, warning.message);
        } else {
            tracing::warn!("[Config] {}: {}", warning.path, warning.message);
        }
    }
}

/// Android takes the congestion control from the host's VPN options, not the profile.
fn tun_congestion_warning(tun: &TunConfig, android: bool) -> Option<WarningView> {
    let name = &tun.congestion_controller;
    if !tun.enable || android || Congestion::parse(name).1 {
        return None;
    }
    Some(WarningView {
        level: "warning",
        code: "not_applied",
        path: "tun.congestion-controller".to_string(),
        message: format!("{name} is not available, so cubic runs instead"),
    })
}

/// The Linux device asks for offload whatever `gso` says, where sing-tun enables it only when
/// asked (`tun_linux.go`); no other platform has it, in either core.
fn tun_offload_warning(tun: &TunConfig, offloads: bool) -> Option<WarningView> {
    (tun.enable && offloads && tun.gso == Some(false)).then(|| WarningView {
        level: "warning",
        code: "not_applied",
        path: "tun.gso".to_string(),
        message: "offload is used whenever the device supports it".to_string(),
    })
}

fn user_agent(general: &General) -> String {
    if general.global_ua.is_empty() {
        "clash.meta".to_string()
    } else {
        general.global_ua.clone()
    }
}

#[cfg(test)]
mod tests {
    use concord_config::net::IpCidr;

    use super::*;

    #[test]
    fn keep_alive_settings_reach_dialed_and_accepted_sockets() {
        let mut general = General {
            keep_alive_idle: 120,
            keep_alive_interval: 30,
            ..General::default()
        };
        let enabled = !cfg!(target_os = "android");
        let spec = listen_spec(&general);
        assert_eq!(spec.tcp_keepalive, enabled);
        assert_eq!(
            (spec.keepalive_idle_secs, spec.keepalive_interval_secs),
            (120, 30)
        );
        assert_eq!(sock_opts(&general).disable_keep_alive, !enabled);

        general.disable_keep_alive = true;
        assert!(!listen_spec(&general).tcp_keepalive);
        assert!(sock_opts(&general).disable_keep_alive);
    }

    #[test]
    fn an_unavailable_tun_congestion_control_is_reported() {
        let mut tun = TunConfig {
            enable: true,
            congestion_controller: "bbr".into(),
            ..TunConfig::default()
        };
        let warning = tun_congestion_warning(&tun, false).unwrap();
        assert_eq!(
            (warning.code, warning.path.as_str()),
            ("not_applied", "tun.congestion-controller")
        );
        assert!(tun_congestion_warning(&tun, true).is_none());
        for name in ["", "cubic", "Reno"] {
            tun.congestion_controller = name.into();
            assert!(tun_congestion_warning(&tun, false).is_none(), "{name}");
        }
        tun.congestion_controller = "bbr3".into();
        tun.enable = false;
        assert!(tun_congestion_warning(&tun, false).is_none());
    }

    #[test]
    fn the_lan_keys_reach_the_listen_spec() {
        let mut general = General {
            allow_lan: true,
            bind_address: "192.168.1.2".into(),
            lan_disallowed_ips: vec![IpCidr::parse("192.168.1.1/32").unwrap()],
            ..General::default()
        };
        let spec = listen_spec(&general);
        assert!(spec.allow_lan);
        assert_eq!(spec.bind_address, "192.168.1.2");
        assert_eq!(spec.lan_allowed_ips.len(), 2);
        assert_eq!(spec.lan_disallowed_ips.len(), 1);
        general.lan_allowed_ips.clear();
        assert!(listen_spec(&general).lan_allowed_ips.is_empty());
    }

    #[test]
    fn only_turning_linux_offload_off_is_reported() {
        let mut tun = TunConfig {
            enable: true,
            gso: Some(false),
            ..TunConfig::default()
        };
        let warning = tun_offload_warning(&tun, true).unwrap();
        assert_eq!(
            (warning.code, warning.path.as_str()),
            ("not_applied", "tun.gso")
        );
        assert!(tun_offload_warning(&tun, false).is_none());
        for gso in [None, Some(true)] {
            tun.gso = gso;
            assert!(tun_offload_warning(&tun, true).is_none(), "{gso:?}");
        }
    }
}
