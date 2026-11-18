use std::collections::BTreeMap;
use std::mem::take;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use concord_common::sync::lock;
use concord_common::{
    Change, ClockOffset, CoreEvent, CoreOptions, EventSink, Origin, RouteStamp, RouteView,
    StateChange,
};
use concord_config::Profile;
use concord_config::general::ControllerCors;
use concord_config::tun::TunConfig;
use concord_dns::{QueryError, QueryView};
use concord_group::{Outbounds, SelectionStore};
use concord_inbound::Listeners;
use concord_net::{LoopbackGuard, Sockets};
use concord_platform::{HomeDir, Platform, mmap};
use concord_rules::geo::GeoStore;
use concord_tls::TrustStore;
use concord_tun::{Prefix, TunRunner};
use concord_tunnel::{ConnTable, LiveOptions, Tunnel, TunnelStatus};
use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;

use crate::apply::{self, Applied, Options, Shared, TrustCache, TunnelUpstream};
use crate::dns_server::DnsServer;
use crate::error::Failure;
use crate::fake_ip_store;
use crate::faults::Faults;
use crate::ntp::{self, NtpSettings};
use crate::ops::{self, RuleSetSource};
use crate::probe::{Prober, RouteHit};
use crate::probe_env::TunnelProbes;
use crate::proxy_tasks::ProxyTasks;
use crate::resources::{self, GeoUpdater, TunnelFetcher};
use crate::route::RouteCounters;
use crate::views::*;

mod connections;
#[cfg_attr(not(feature = "mitm"), path = "engine/mitm_disabled.rs")]
mod mitm;
mod providers;
mod proxies;
mod reconcile;
#[cfg(test)]
mod tests;
mod tun;
mod update;
mod views;

pub use mitm::MitmService;
pub use providers::Providers;
use providers::request_failure;

pub struct EngineConfig {
    pub sink: Arc<dyn EventSink>,
    pub android: bool,
    pub platform: Arc<dyn Platform>,
}

pub struct SetupRequest {
    pub base: Option<(String, String)>,
    pub selected: BTreeMap<String, String>,
    pub options: CoreOptions,
}

pub struct TunPatch {
    pub enable: bool,
    pub device: Option<String>,
    pub stack: Option<String>,
    pub auto_route: Option<bool>,
}

#[derive(Default)]
pub struct UpdateRequest {
    pub tun: Option<TunPatch>,
    pub allow_lan: Option<bool>,
    pub bind_address: Option<String>,
    pub lan_allowed_ips: Option<Vec<String>>,
    pub lan_disallowed_ips: Option<Vec<String>>,
    pub mixed_port: Option<u16>,
    pub find_process_mode: Option<String>,
    pub mode: Option<String>,
    pub log_level: Option<String>,
    pub ipv6: Option<bool>,
    pub tcp_concurrent: Option<bool>,
    pub unified_delay: Option<bool>,
    pub authentication: Option<Vec<String>>,
    pub geo_auto_update: Option<bool>,
    pub geo_update_interval: Option<i64>,
    pub geox_url: BTreeMap<String, String>,
    pub options: Option<CoreOptions>,
}

pub struct Engine {
    home: ArcSwapOption<HomeDir>,
    initialized: AtomicBool,
    running: AtomicBool,
    sdk_version: AtomicI32,
    route: Arc<RouteCounters>,
    android: bool,
    shared: Shared,
    table: Arc<ConnTable>,
    listeners: Listeners,
    /// `configMu`: one apply or update at a time, with what is in force.
    state: AsyncMutex<Option<Applied>>,
    /// Taken after `state`, never the other way round.
    tun: AsyncMutex<Option<TunRunner>>,
    tun_config: StdMutex<Option<(TunConfig, Option<Prefix>, bool)>>,
    dns_server: AsyncMutex<Option<DnsServer>>,
    faults: Faults,
    warnings: ArcSwap<Vec<WarningView>>,
    system_dns: StdMutex<Option<Vec<SocketAddr>>>,
    dns_update_seq: AtomicU64,
    mitm: MitmService,
    handle: Handle,
    prober: Prober,
    /// Every background task the engine starts; shutdown ends them and waits, so nothing
    /// outlives the engine.
    tasks: TaskTracker,
    /// The last change of state a host keeps. Taken after `state`; held only to
    /// set a value and publish its change, never across a probe or a load.
    intent: Arc<AsyncMutex<u64>>,
    /// Whether the profile's `external-controller` and `secret` count, as they do
    /// when the core runs on its own; a host sets them through `config.patch`.
    profile_controller: AtomicBool,
    /// Released once the apply in progress has answered; until then each
    /// provider's first load keeps its outcome to itself. Released when no
    /// apply holds it.
    answered: StdMutex<CancellationToken>,
}

const NOT_INITIALIZED: &str = "not initialized";

/// Past this, shutdown reports the tasks still running and returns rather than hang on one.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

impl Engine {
    /// Call inside the runtime that should carry the flows.
    pub fn new(config: EngineConfig) -> Arc<Self> {
        let events = config.sink;
        let route = Arc::new(RouteCounters::new(events.clone()));
        let loopback_guard = LoopbackGuard::new(!config.android);
        let loopback = (!config.android).then(|| loopback_guard.clone());
        let sockets = Arc::new(Sockets::new(config.platform.clone()));
        let table = ConnTable::new(events.clone());
        let tunnel = Tunnel::new(table.clone(), loopback_guard);
        let options = Arc::new(ArcSwap::from_pointee(CoreOptions::default()));
        let fetcher = Arc::new(TunnelFetcher {
            tunnel: tunnel.clone(),
            trust: ArcSwap::new(TrustStore::from_parts(Vec::new(), &[], Vec::new())),
            options: options.clone(),
            user_agent: ArcSwap::from_pointee("clash.meta".to_string()),
        });
        let geo_store = Arc::new(GeoStore::new(".").with_opener(mmap::open_read_only));
        let prober = Prober::new(Arc::new(TunnelProbes {
            tunnel: tunnel.clone(),
            route: route.clone(),
            fetcher: fetcher.clone(),
        }));
        let clock = Arc::new(ClockOffset::default());
        let tasks = TaskTracker::new();
        let handle = Handle::current();
        let shared = Shared {
            platform: config.platform,
            sockets,
            loopback,
            upstream: Arc::new(TunnelUpstream {
                tunnel: tunnel.clone(),
            }),
            tunnel,
            route: route.clone(),
            options: Arc::new(Options {
                current: options,
                unified_delay: AtomicBool::new(false),
            }),
            trust: TrustCache::new(clock.clone()),
            clock,
            geo: GeoUpdater::new(geo_store, events.clone(), route.clone()),
            events,
            fetcher,
            rule_providers: ArcSwapOption::empty(),
            fake_ip_store: Arc::default(),
            android: config.android,
            proxy_tasks: ProxyTasks::new(tasks.clone(), handle.clone()),
        };
        Arc::new(Engine {
            home: ArcSwapOption::empty(),
            initialized: AtomicBool::new(false),
            running: AtomicBool::new(false),
            sdk_version: AtomicI32::new(0),
            route,
            android: config.android,
            shared,
            table: table.clone(),
            listeners: Listeners::native(),
            state: AsyncMutex::new(None),
            tun: AsyncMutex::new(None),
            tun_config: StdMutex::new(None),
            dns_server: AsyncMutex::new(None),
            faults: Faults::default(),
            warnings: ArcSwap::from_pointee(Vec::new()),
            system_dns: StdMutex::new(None),
            dns_update_seq: AtomicU64::new(0),
            mitm: MitmService::new(table.clone()),
            handle,
            prober,
            tasks,
            intent: Arc::new(AsyncMutex::new(0)),
            profile_controller: AtomicBool::new(false),
            answered: StdMutex::new(released()),
        })
    }

    pub fn home(&self) -> Option<Arc<HomeDir>> {
        self.home.load_full()
    }

    pub fn is_android(&self) -> bool {
        self.android
    }

    fn runtime(&self) -> Option<Arc<concord_tunnel::Runtime>> {
        self.shared.tunnel.runtime()
    }

    fn outbounds(&self) -> Option<Arc<Outbounds>> {
        self.runtime().map(|runtime| runtime.outbounds.clone())
    }

    pub fn init(&self, home_dir: &str, sdk_version: i32) -> Result<(), Failure> {
        self.sdk_version.store(sdk_version, Ordering::SeqCst);
        let home = Arc::new(HomeDir::new(home_dir));
        self.shared.geo.set_home(home.clone());
        self.shared.geo.reopen();
        self.shared.geo.store.set_dir(home.root());
        home.reclaim();
        self.start_mitm(&home);
        self.home.store(Some(home));
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// The CA and the script store live under the home directory, so this waits for
    /// `core.init`; a repeat with the same directory keeps the engine and its captures.
    fn start_mitm(&self, home: &Arc<HomeDir>) {
        let same_home = self
            .home
            .load()
            .as_ref()
            .is_some_and(|current| current.root() == home.root());
        if same_home && self.mitm.is_started() {
            return;
        }
        self.mitm
            .start(home, &self.shared.tunnel, self.is_running());
    }

    pub fn mitm(&self) -> &MitmService {
        &self.mitm
    }

    fn set_running(&self, running: bool) {
        self.running.store(running, Ordering::SeqCst);
        self.mitm.set_running(running);
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn sdk_version(&self) -> i32 {
        self.sdk_version.load(Ordering::SeqCst)
    }

    pub fn release_memory(&self) {
        if let Some(outbounds) = self.outbounds() {
            outbounds.reset_sessions();
        }
        concord_platform::release_free_memory();
    }

    fn apply_options(&self, options: &CoreOptions) {
        let mut current = (**self.shared.options.current.load()).clone();
        if !options.test_url.is_empty() {
            current.test_url.clone_from(&options.test_url);
        }
        if options.delay_test_timeout != 0 {
            current.delay_test_timeout = options.delay_test_timeout;
        }
        current.skip_cert_verify = options.skip_cert_verify;
        current.mitm_capture = options.mitm_capture;
        self.mitm.set_capture(options.mitm_capture);
        self.shared.options.current.store(Arc::new(current));
    }

    /// The first download a config needs goes through the tunnel, so there must be
    /// a route before the first config is in force.
    async fn ensure_bootstrap(&self, home: &Arc<HomeDir>) -> Result<(), Failure> {
        if self.runtime().is_some() {
            return Ok(());
        }
        let built = apply::build(
            &self.shared,
            home,
            Profile::rejected_empty(),
            Arc::new(SelectionStore::new()),
        )
        .await
        .map_err(|err| Failure::core(err.to_string()))?;
        self.shared.tunnel.install(built.runtime);
        self.shared.tunnel.set_status(TunnelStatus::Inner);
        Ok(())
    }

    pub async fn setup(self: &Arc<Self>, request: SetupRequest) -> Result<(), Failure> {
        self.setup_as(Origin::Host, request).await
    }

    pub async fn setup_as(
        self: &Arc<Self>,
        origin: Origin,
        request: SetupRequest,
    ) -> Result<(), Failure> {
        if !self.is_initialized() {
            return Err(Failure::core(NOT_INITIALIZED));
        }
        let mut state = self.state.lock().await;
        let home = self.home().ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        self.apply_options(&request.options);
        self.ensure_bootstrap(&home).await?;

        let selections = Arc::new(SelectionStore::new());
        selections.replace_all(request.selected);
        let built = match apply::load_profile(&self.shared, &home, request.base).await {
            Ok(profile) => apply::build(&self.shared, &home, profile, selections.clone()).await,
            Err(err) => Err(err),
        };
        let (built, rejected) = self.built_or_default(&home, built, &selections).await?;
        let apply::Built {
            runtime,
            mut applied,
            outbounds,
            rule_providers,
            deferred_geo,
            mut warnings,
            mitm,
            trust,
        } = built;
        if !self.profile_controller.load(Ordering::Relaxed) {
            host_owns_controller(&mut applied.general, &mut warnings);
        }

        if let Some(old) = state.take() {
            old.stop.cancel();
        }
        self.warnings.store(Arc::new(warnings));
        self.shared.tunnel.set_live(LiveOptions {
            mode: applied.general.mode,
            find_process_mode: applied.general.find_process_mode,
            ..LiveOptions::default()
        });
        let resolver = runtime.dns.clone();
        let system_dns = lock(&self.system_dns).clone();
        if let Some(servers) = system_dns {
            resolver.set_system_servers(servers);
        }
        {
            let mut seq = self.intent.lock().await;
            self.shared.tunnel.install(runtime);
            self.publish_change(&mut seq, origin, Change::Applied);
        }
        self.shared.tunnel.set_status(TunnelStatus::Running);
        self.mitm.apply(&mitm, trust);
        if applied.store_fake_ip {
            fake_ip_store::start(
                self.shared.fake_ip_store.clone(),
                &self.tasks,
                &self.handle,
                home.clone(),
                resolver.clone(),
                applied.stop.clone(),
            );
        }
        self.sync_dns_server(&applied.dns_listen, applied.dns_listen_mark, resolver)
            .await;
        self.start_ntp(&applied, &outbounds);
        let answered = lock(&self.answered).clone();
        outbounds.start_background(applied.stop.clone(), answered.clone());
        self.tasks.spawn_on(
            report_revoked(
                selections,
                self.intent.clone(),
                self.shared.events.clone(),
                applied.stop.clone(),
            ),
            &self.handle,
        );
        self.shared.geo.fetch_deferred(
            &deferred_geo,
            self.shared.fetcher.clone(),
            &applied.stop,
            &answered,
            &self.tasks,
        );
        rule_providers.start(applied.stop.clone(), answered, &self.tasks);
        self.shared.rule_providers.store(Some(rule_providers));
        self.reconcile_listeners(&applied).await;
        self.route.reset(self.is_running());
        self.shared.geo.sync_auto(
            applied.general.geo_auto_update,
            applied.general.geo_update_interval,
            self.shared.fetcher.clone(),
            &self.tasks,
        );
        *state = Some(applied);
        drop(state);
        self.handle
            .spawn_blocking(concord_platform::release_free_memory);
        match rejected {
            Some(message) => Err(Failure::new("config_rejected", message)),
            None => Ok(()),
        }
    }

    async fn built_or_default(
        &self,
        home: &Arc<HomeDir>,
        built: Result<apply::Built, apply::ApplyError>,
        selections: &Arc<SelectionStore>,
    ) -> Result<(apply::Built, Option<String>), Failure> {
        match built {
            Ok(built) => Ok((built, None)),
            Err(err) => {
                tracing::error!(
                    "config apply failed, falling back to the built-in default - no proxies will be available: {err}"
                );
                match apply::build(
                    &self.shared,
                    home,
                    Profile::rejected_empty(),
                    selections.clone(),
                )
                .await
                {
                    Ok(built) => Ok((built, Some(err.to_string()))),
                    Err(_) => Err(Failure::core(err.to_string())),
                }
            }
        }
    }

    fn start_ntp(&self, applied: &Applied, outbounds: &Outbounds) {
        let ntp = &applied.ntp;
        if !ntp.enable || ntp.server.is_empty() || ntp.interval == 0 {
            return;
        }
        let mut write_to_system = ntp.write_to_system;
        if write_to_system && self.android {
            tracing::warn!(
                "ntp write-to-system ignored: Android does not let apps set the system time"
            );
            write_to_system = false;
        }
        ntp::start(
            &self.tasks,
            &self.handle,
            NtpSettings {
                server: ntp.server.clone(),
                port: ntp.port,
                interval: Duration::from_secs(u64::from(ntp.interval) * 60),
                dialer_proxy: ntp.dialer_proxy.clone(),
                write_to_system,
            },
            outbounds.env(),
            self.shared.clock.clone(),
            applied.stop.clone(),
        );
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// `handleUpdateDns`: the newest value wins however the tasks interleave.
    pub fn update_system_dns(self: &Arc<Self>, value: String) {
        let seq = self.dns_update_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let engine = self.clone();
        let update = async move {
            if engine.dns_update_seq.load(Ordering::SeqCst) != seq {
                return;
            }
            tracing::info!("[DNS] updateDns {value}");
            let servers: Vec<SocketAddr> = value
                .split(',')
                .filter(|server| !server.is_empty())
                .filter_map(|server| {
                    let parsed = server.parse().ok();
                    if parsed.is_none() {
                        tracing::warn!("[DNS] updateDns: invalid address {server}");
                    }
                    parsed
                })
                .collect();
            {
                let mut held = lock(&engine.system_dns);
                *held = Some(servers.clone());
            }
            if let Some(runtime) = engine.runtime() {
                runtime.dns.set_system_servers(servers);
            }
        };
        self.tasks.spawn_on(update, &self.handle);
    }

    fn publish_change(&self, seq: &mut u64, origin: Origin, change: Change) {
        publish_change(&*self.shared.events, seq, origin, change);
    }

    /// Holds back the outcome of the first load of every provider the next
    /// apply makes until the guard drops, so a host that answers its own caller
    /// after the apply hears of a provider only once it knows of it.
    pub fn hold_first_loads(&self) -> DropGuard {
        let token = CancellationToken::new();
        {
            let mut answered = lock(&self.answered);
            answered.cancel();
            *answered = token.clone();
        }
        token.drop_guard()
    }

    pub fn set_profile_controller(&self, owned: bool) {
        self.profile_controller.store(owned, Ordering::Relaxed);
    }

    pub async fn dns_query(&self, name: &str, qtype: &str) -> Result<QueryView, Failure> {
        let runtime = self
            .runtime()
            .ok_or_else(|| Failure::core("config is not applied"))?;
        runtime
            .dns
            .query(name, qtype)
            .await
            .map_err(|err| match err {
                QueryError::Exchange(err) => Failure::core(err.to_string()),
                other => Failure::new("invalid_query", other.to_string()),
            })
    }

    pub fn flush_fake_ip(&self) {
        if let Some(runtime) = self.runtime() {
            runtime.dns.flush_fake_ip();
        }
    }

    pub fn clear_effect(&self, profile_id: i64) -> Result<(), Failure> {
        let home = self.home().ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        ops::clear_effect(&home, profile_id)
    }

    pub fn providers(&self) -> Providers<'_> {
        Providers { engine: self }
    }

    pub async fn compile_rule_set(&self, name: &str, url: &str) -> Result<RuleSetInfo, Failure> {
        let home = self.home().ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        let valid = !name.is_empty()
            && !name.starts_with('.')
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !valid {
            return Err(Failure::new("invalid_arguments", "invalid rule set name"));
        }
        let source = home.join("providers").join("rules").join(name);
        let downloaded = !url.is_empty();
        let from = if downloaded {
            RuleSetSource::Downloaded(
                resources::download(&*self.shared.fetcher, resources::rule_set_request(url))
                    .await
                    .map_err(|err| request_failure(&err, json!({})))?,
            )
        } else {
            RuleSetSource::Local(source.clone())
        };
        let (bytes, compiled) = ops::compile_rule_set(from).await?;
        if downloaded {
            home.write_atomic(&source, &bytes)?;
        }
        if let Some(mrs) = &compiled.mrs {
            let mut target = source.clone().into_os_string();
            target.push(".mrs");
            home.write_atomic(std::path::PathBuf::from(target), mrs)?;
        }
        Ok(RuleSetInfo {
            behavior: compiled.info.behavior.name(),
            format: compiled.info.format.name(),
        })
    }

    pub fn geo_update(self: &Arc<Self>, kind: &str) -> Result<(), Failure> {
        let file = resources::geo_file_of(kind)
            .ok_or_else(|| Failure::core(format!("unknown geo resource: {kind}")))?;
        let claim = self
            .shared
            .geo
            .claim(file)
            .ok_or_else(|| Failure::core(format!("geo update already in progress: {kind}")))?;
        self.shared
            .geo
            .spawn_update(claim, self.shared.fetcher.clone(), &self.tasks);
        Ok(())
    }

    pub fn reset_resolver_connections(&self) {
        if let Some(runtime) = self.runtime() {
            runtime.dns.reset_connections();
        }
    }

    pub fn clear_dns_cache(&self) {
        if let Some(runtime) = self.runtime() {
            runtime.dns.clear_cache();
        }
    }

    pub fn network_changed(&self) {
        self.shared.platform.network_changed();
        self.clear_dns_cache();
        self.mitm.network_changed();
    }

    /// `handleResetNetwork`: connections over a network the device has left would
    /// hang until TCP gives up on them, the probes among them, so the epoch moves.
    pub fn reset_network(&self) {
        self.close_all_connections();
        self.network_changed();
        if let Some(outbounds) = self.outbounds() {
            outbounds.reset_sessions();
        }
        self.route.reset(self.is_running());
    }

    pub fn watch_route(&self, watched: bool) -> RouteView {
        self.route.watch(watched)
    }

    pub async fn check_routes(&self, routes: Vec<Vec<RouteHit>>) -> (RouteStamp, Vec<bool>) {
        self.prober.check_routes(&routes).await
    }

    pub async fn probe_outbound_ip(&self, proxy: String, urls: Vec<String>, timeout: i64) -> Value {
        self.prober.outbound_ip(&proxy, &urls, timeout).await
    }

    pub async fn probe_services(&self, proxy: String, names: Vec<String>, timeout: i64) -> Value {
        self.prober.services(&proxy, &names, timeout).await
    }

    pub async fn shutdown(&self) {
        let mut state = self.state.lock().await;
        self.set_running(false);
        self.mitm.shutdown();
        self.route.watch(false);
        self.listeners.stop_all().await;
        {
            let mut slot = self.tun.lock().await;
            self.close_tun(&mut slot).await;
        }
        *self.dns_server.lock().await = None;
        self.shared.geo.close();
        self.shared.rule_providers.store(None);
        if let Some(applied) = state.take() {
            applied.stop.cancel();
        }
        self.shared.proxy_tasks.stop();
        self.table.close_all();
        self.shared.tunnel.set_status(TunnelStatus::Suspended);
        self.shared.tunnel.clear();
        self.tasks.close();
        if tokio::time::timeout(SHUTDOWN_GRACE, self.tasks.wait())
            .await
            .is_err()
        {
            tracing::warn!(
                "[Engine] {} background tasks still running {SHUTDOWN_GRACE:?} into shutdown",
                self.tasks.len()
            );
        }
        self.tasks.reopen();
        self.initialized.store(false, Ordering::SeqCst);
    }
}

fn host_owns_controller(
    general: &mut concord_config::general::General,
    warnings: &mut Vec<WarningView>,
) {
    const MESSAGE: &str = "the host sets this; the profile's value is ignored";
    let written = [
        (
            "external-controller",
            !take(&mut general.external_controller).is_empty(),
        ),
        ("secret", !take(&mut general.secret).is_empty()),
        (
            "external-controller-cors",
            take(&mut general.external_controller_cors) != ControllerCors::default(),
        ),
    ];
    for (key, _) in written.into_iter().filter(|(_, written)| *written) {
        tracing::warn!("[Config] {key}: {MESSAGE}");
        warnings.push(WarningView {
            level: "warning",
            code: "host_owned_key",
            path: key.to_string(),
            message: MESSAGE.to_string(),
        });
    }
}

fn publish_change(events: &dyn EventSink, seq: &mut u64, origin: Origin, change: Change) {
    *seq += 1;
    if events.enabled() {
        events.publish(CoreEvent::State(StateChange {
            seq: *seq,
            origin,
            change,
        }));
    }
}

/// Reports each pick a fallback group dropped because its node died. A pick
/// set again before the report is taken was already reported by its caller.
async fn report_revoked(
    selections: Arc<SelectionStore>,
    intent: Arc<AsyncMutex<u64>>,
    events: Arc<dyn EventSink>,
    stop: CancellationToken,
) {
    loop {
        let groups = tokio::select! {
            () = stop.cancelled() => return,
            groups = selections.take_revoked() => groups,
        };
        let mut seq = intent.lock().await;
        for group in groups {
            if selections.get(&group).is_none() {
                let change = Change::Selected {
                    group: group.to_string(),
                    proxy: String::new(),
                };
                publish_change(&*events, &mut seq, Origin::Core, change);
            }
        }
    }
}

fn released() -> CancellationToken {
    let token = CancellationToken::new();
    token.cancel();
    token
}
