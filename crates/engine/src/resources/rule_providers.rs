use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use concord_common::backoff::{Attempt, retry_until_loaded};
use concord_common::sync::lock;
use concord_common::{
    CoreEvent, EventSink, Fetch, Refresh, ResourceKind, ResourcePhase, ResourceUpdate,
};
use concord_config::provider::{RuleBehavior, RuleProviderDef, RuleSource};
use concord_group::{FetchRequest, Fetcher};
use concord_platform::HomeDir;
use concord_rules::{
    Behavior, CompileEnv, Format, GeoFault, ParsedRuleSet, RuleSet, RuleSetHandle, RuleSetStore,
};
use md5::{Digest, Md5};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::fetch::{download, touch};
use super::geo::{GEO_REPARSES, GeoUpdater};
use crate::error::{ResourceError, RuleLoadError};
use crate::route::RouteCounters;

const PROVIDER_TIMEOUT: Duration = Duration::from_secs(20);

type Hash = [u8; 16];

pub(crate) fn rule_set_request(url: &str) -> FetchRequest {
    FetchRequest {
        url: url.to_string(),
        headers: Vec::new(),
        via_proxy: None,
        size_limit: None,
        timeout: PROVIDER_TIMEOUT,
    }
}

fn md5_of(bytes: &[u8]) -> Hash {
    Md5::digest(bytes).into()
}

pub(crate) struct RuleProvider {
    pub def: RuleProviderDef,
    pub handle: Arc<RuleSetHandle>,
    path: Option<PathBuf>,
    updated_at: Mutex<Option<SystemTime>>,
    hash: Mutex<Option<Hash>>,
    updating: AtomicBool,
    gate: tokio::sync::Mutex<()>,
}

pub(crate) fn behavior_of(behavior: RuleBehavior) -> Behavior {
    match behavior {
        RuleBehavior::Domain => Behavior::Domain,
        RuleBehavior::IpCidr => Behavior::IpCidr,
        RuleBehavior::Classical => Behavior::Classical,
    }
}

impl RuleProvider {
    pub fn vehicle(&self) -> &'static str {
        match self.def.source {
            RuleSource::File { .. } => "File",
            RuleSource::Http(_) => "HTTP",
            RuleSource::Inline { .. } => "Inline",
        }
    }

    pub fn path_text(&self) -> String {
        self.path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    pub fn updated_at(&self) -> Option<SystemTime> {
        *lock(&self.updated_at)
    }

    /// An inline provider is reachable by name but not listed, as in `toExternalProvider`.
    pub fn is_listed(&self) -> bool {
        !matches!(self.def.source, RuleSource::Inline { .. })
    }

    fn remember(&self, hash: Option<Hash>, at: SystemTime) {
        if let Some(hash) = hash {
            *lock(&self.hash) = Some(hash);
        }
        {
            let mut updated = lock(&self.updated_at);
            *updated = Some(at);
        }
    }

    fn holds(&self, hash: Hash) -> bool {
        *lock(&self.hash) == Some(hash)
    }

    fn since_update(&self) -> Duration {
        self.updated_at()
            .and_then(|at| at.elapsed().ok())
            .unwrap_or(Duration::ZERO)
    }
}

/// The rule providers of one config. Their sets live in `RuleSetHandle`s the
/// route program already holds, so an update needs no recompile.
pub(crate) struct RuleProviders {
    pub list: Vec<Arc<RuleProvider>>,
    env: Arc<CompileEnv>,
    geo: Arc<GeoUpdater>,
    home: Arc<HomeDir>,
    fetcher: Arc<dyn Fetcher>,
    events: Arc<dyn EventSink>,
    route: Arc<RouteCounters>,
}

impl RuleProviders {
    pub fn new(
        defs: &[RuleProviderDef],
        store: &Arc<RuleSetStore>,
        geo: &Arc<GeoUpdater>,
        home: Arc<HomeDir>,
        fetcher: Arc<dyn Fetcher>,
        events: Arc<dyn EventSink>,
        route: Arc<RouteCounters>,
    ) -> Result<Self, RuleLoadError> {
        let mut list = Vec::with_capacity(defs.len());
        for def in defs {
            let handle = store.declare(&def.name, behavior_of(def.behavior));
            let confine = |path: &str| home.confine(path).map_err(RuleLoadError::path(def, path));
            let path = match &def.source {
                RuleSource::File { path } => Some(confine(path)?),
                RuleSource::Http(http) => {
                    let relative = if http.path.is_empty() {
                        format!("rules/{:x}", Md5::digest(http.url.as_bytes()))
                    } else {
                        http.path.clone()
                    };
                    Some(confine(&relative)?)
                }
                RuleSource::Inline { .. } => None,
            };
            list.push(Arc::new(RuleProvider {
                def: def.clone(),
                handle,
                path,
                updated_at: Mutex::new(None),
                hash: Mutex::new(None),
                updating: AtomicBool::new(false),
                gate: tokio::sync::Mutex::new(()),
            }));
        }
        Ok(RuleProviders {
            list,
            env: Arc::new(CompileEnv::new(geo.store.clone(), store.clone())),
            geo: geo.clone(),
            home,
            fetcher,
            events,
            route,
        })
    }

    pub fn get(&self, name: &str) -> Option<&Arc<RuleProvider>> {
        self.list.iter().find(|provider| provider.def.name == name)
    }

    /// Downloads the geo files that classical entries needed and did not find, as mihomo does while
    /// parsing them. True when every file arrived, so parsing again can keep those entries.
    async fn fetch_geo_faults(&self, faults: &[GeoFault]) -> bool {
        if faults.is_empty() {
            return false;
        }
        for fault in faults {
            let fetched = match *fault {
                GeoFault::Missing(file) => self.geo.fetch_missing(file, &*self.fetcher).await,
                GeoFault::Invalid(file) => self.geo.replace_invalid(file, &*self.fetcher).await,
            };
            if let Err(err) = fetched {
                tracing::warn!("[Provider] {err}");
                return false;
            }
        }
        true
    }

    async fn parse_entries(&self, provider: &RuleProvider, entries: &[String]) -> ParsedRuleSet {
        let behavior = behavior_of(provider.def.behavior);
        let mut rounds = 0;
        loop {
            let parsed = RuleSet::from_entries(behavior, entries, &self.env);
            if rounds < GEO_REPARSES && self.fetch_geo_faults(&parsed.geo_faults).await {
                rounds += 1;
                continue;
            }
            return parsed;
        }
    }

    /// Hands the bytes back so the caller can write what it just parsed.
    async fn parse(
        &self,
        provider: &RuleProvider,
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>, RuleLoadError> {
        let behavior = behavior_of(provider.def.behavior);
        let format = Format::from(provider.def.format);
        let mut bytes = bytes;
        let mut rounds = 0;
        let parsed = loop {
            let env = self.env.clone();
            let (back, parsed) = tokio::task::spawn_blocking(move || {
                let parsed = RuleSet::parse(behavior, format, &bytes, &env);
                (bytes, parsed)
            })
            .await?;
            bytes = back;
            let parsed = parsed?;
            if rounds < GEO_REPARSES && self.fetch_geo_faults(&parsed.geo_faults).await {
                rounds += 1;
                continue;
            }
            break parsed;
        };
        for warning in &parsed.warnings {
            tracing::warn!("[Provider] {}: {warning}", provider.def.name);
        }
        provider.handle.store(parsed.set);
        Ok(bytes)
    }

    /// mihomo's `Fetcher.loadBuf`.
    async fn load_buf(
        &self,
        provider: &RuleProvider,
        bytes: Vec<u8>,
        update_file: bool,
    ) -> Result<Refresh, RuleLoadError> {
        let _gate = provider.gate.lock().await;
        let hash = md5_of(&bytes);
        if provider.holds(hash) {
            if let (true, Some(path)) = (update_file, provider.path.clone()) {
                let _ = tokio::task::spawn_blocking(move || touch(&path)).await;
            }
            provider.remember(None, SystemTime::now());
            return Ok(Refresh::Unchanged);
        }
        if bytes.is_empty() {
            return Ok(Refresh::Updated);
        }
        let bytes = self.parse(provider, bytes).await?;
        if let (true, Some(path)) = (update_file, provider.path.clone()) {
            let home = self.home.clone();
            tokio::task::spawn_blocking(move || home.write_atomic(&path, &bytes))
                .await?
                .map_err(RuleLoadError::Write)?;
        }
        provider.remember(Some(hash), SystemTime::now());
        self.route.moved();
        Ok(Refresh::Updated)
    }

    /// True means what is on disk is older than the update interval.
    async fn initial(&self, provider: &RuleProvider) -> Result<bool, RuleLoadError> {
        if let RuleSource::Inline { payload } = &provider.def.source {
            let parsed = self.parse_entries(provider, payload).await;
            for warning in &parsed.warnings {
                tracing::warn!("[Provider] {}: {warning}", provider.def.name);
            }
            provider.handle.store(parsed.set);
            provider.remember(None, SystemTime::now());
            return Ok(false);
        }
        if !provider.def.fallback.is_empty() {
            let parsed = self.parse_entries(provider, &provider.def.fallback).await;
            for warning in &parsed.warnings {
                tracing::warn!("[Provider] {}: {warning}", provider.def.name);
            }
            provider.handle.store(parsed.set);
        }
        if let Some(path) = &provider.path
            && let Ok(bytes) = tokio::fs::read(path).await
        {
            let modified = tokio::fs::metadata(path)
                .await
                .and_then(|meta| meta.modified())
                .ok();
            let loaded = self.load_buf(provider, bytes, false).await;
            if let Some(at) = modified {
                provider.remember(None, at);
            }
            match loaded {
                Ok(_) => {
                    let interval = Duration::from_secs(u64::from(provider.def.interval));
                    return Ok(provider.since_update() > interval);
                }
                Err(err) => {
                    tracing::warn!("[Provider] {} read local file: {err}", provider.def.name);
                }
            }
        }
        Ok(self.pull(provider).await.map(|_| false)?)
    }

    /// mihomo's `Fetcher.Update`.
    pub async fn pull(&self, provider: &RuleProvider) -> Result<Refresh, ResourceError> {
        let (bytes, update_file) = match &provider.def.source {
            RuleSource::Inline { .. } => {
                provider.remember(None, SystemTime::now());
                return Ok(Refresh::Unchanged);
            }
            RuleSource::File { .. } => {
                let path = provider
                    .path
                    .as_ref()
                    .ok_or_else(|| ResourceError::Other("no path".to_string()))?;
                let bytes = tokio::fs::read(path)
                    .await
                    .map_err(|err| ResourceError::Other(err.to_string()))?;
                (bytes, false)
            }
            RuleSource::Http(http) => {
                let headers = http
                    .header
                    .iter()
                    .flat_map(|(name, values)| {
                        values
                            .iter()
                            .map(move |value| (name.clone(), value.clone()))
                    })
                    .collect();
                let bytes = download(
                    &*self.fetcher,
                    FetchRequest {
                        url: http.url.clone(),
                        headers,
                        via_proxy: Some(http.proxy.clone()).filter(|proxy| !proxy.is_empty()),
                        size_limit: u64::try_from(http.size_limit)
                            .ok()
                            .filter(|limit| *limit > 0),
                        timeout: PROVIDER_TIMEOUT,
                    },
                )
                .await?;
                (bytes, true)
            }
        };
        self.load_buf(provider, bytes, update_file)
            .await
            .map_err(|err| ResourceError::Load(Box::new(err)))
    }

    pub async fn side_load(
        &self,
        provider: &RuleProvider,
        bytes: Vec<u8>,
    ) -> Result<(), RuleLoadError> {
        self.reported(provider, self.load_buf(provider, bytes, true))
            .await
            .map(|_| ())
    }

    fn report(&self, provider: &RuleProvider, phase: ResourcePhase) {
        if self.events.enabled() {
            self.events.publish(CoreEvent::Resource(ResourceUpdate {
                kind: ResourceKind::RuleProvider,
                name: Arc::from(provider.def.name.as_str()),
                phase,
            }));
        }
    }

    pub async fn reported<E: std::fmt::Display>(
        &self,
        provider: &RuleProvider,
        work: impl Future<Output = Result<Refresh, E>>,
    ) -> Result<Refresh, E> {
        let fetch = Fetch::start(|phase| self.report(provider, phase));
        let outcome = work.await;
        fetch.finish(ResourcePhase::of(&outcome));
        outcome
    }

    pub fn claim(&self, provider: &RuleProvider) -> bool {
        !provider.updating.swap(true, Ordering::AcqRel)
    }

    pub fn release(&self, provider: &RuleProvider) {
        provider.updating.store(false, Ordering::Release);
    }

    /// `answered` holds back every step of each first load, as
    /// `Outbounds::start_background` does for proxy providers.
    pub fn start(
        self: &Arc<Self>,
        stop: CancellationToken,
        answered: CancellationToken,
        tasks: &TaskTracker,
    ) {
        let loading = Arc::new(AtomicUsize::new(self.list.len()));
        for provider in self.list.clone() {
            let providers = self.clone();
            let stop = stop.clone();
            let answered = answered.clone();
            let loading = loading.clone();
            tasks.spawn(async move {
                tokio::select! {
                    () = stop.cancelled() => {}
                    () = providers.run(&provider, &answered, &loading, &stop) => {}
                }
            });
        }
    }

    async fn run(
        &self,
        provider: &RuleProvider,
        answered: &CancellationToken,
        loading: &AtomicUsize,
        stop: &CancellationToken,
    ) {
        let report = |phase| self.report(provider, phase);
        let (fetch, initial) = {
            let load = self.initial(provider);
            tokio::pin!(load);
            tokio::select! {
                initial = &mut load => (None, initial),
                () = answered.cancelled() => (Some(Fetch::start(report)), load.await),
            }
        };
        let fetch = match fetch {
            Some(fetch) => fetch,
            None => {
                answered.cancelled().await;
                Fetch::start(report)
            }
        };
        let stale = match initial {
            Ok(stale) => {
                fetch.finish(ResourcePhase::Updated);
                stale
            }
            Err(err) => {
                tracing::error!("initial rule provider {} error: {err}", provider.def.name);
                fetch.finish(ResourcePhase::Failed(err.to_string()));
                if matches!(provider.def.source, RuleSource::Http(_)) && provider.def.interval > 0 {
                    let interval = Duration::from_secs(u64::from(provider.def.interval));
                    retry_until_loaded(interval, stop, || async {
                        if self.pull_with_log(provider).await {
                            Attempt::Loaded
                        } else {
                            Attempt::Retry
                        }
                    })
                    .await;
                }
                false
            }
        };
        // mihomo collects garbage once every provider it waits for has loaded.
        if loading.fetch_sub(1, Ordering::AcqRel) == 1 {
            tokio::task::spawn_blocking(concord_platform::release_free_memory);
        }
        if let (RuleSource::File { .. }, Some(path)) = (&provider.def.source, &provider.path) {
            let mut watch = concord_platform::FileWatch::new(path.clone());
            loop {
                watch.changed().await;
                self.pull_with_log(provider).await;
            }
        }
        if provider.def.interval == 0 || !matches!(provider.def.source, RuleSource::Http(_)) {
            return;
        }
        let interval = Duration::from_secs(u64::from(provider.def.interval));
        if stale {
            tracing::warn!(
                "[Provider] {} not updated for a long time, force refresh",
                provider.def.name
            );
            self.pull_with_log(provider).await;
        }
        sleep(interval.saturating_sub(provider.since_update())).await;
        loop {
            self.pull_with_log(provider).await;
            sleep(interval).await;
        }
    }

    async fn pull_with_log(&self, provider: &RuleProvider) -> bool {
        if !self.claim(provider) {
            return false;
        }
        let pulled = self.reported(provider, self.pull(provider)).await;
        if let Err(err) = &pulled {
            tracing::warn!("[Provider] {} pull error: {err}", provider.def.name);
        }
        self.release(provider);
        pulled.is_ok()
    }
}
