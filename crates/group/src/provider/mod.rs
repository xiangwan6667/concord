mod info;
mod nodes;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use concord_common::backoff::{Attempt, provider_backoff as backoff, retry_until_loaded};
use concord_common::sync::lock;
use concord_common::{CoreEvent, Fetch, Refresh, ResourceKind, ResourcePhase, ResourceUpdate};
use concord_config::provider::{ProxyProviderDef, ProxySource, parse_provider_content};
use md5::{Digest, Md5};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

pub use info::SubscriptionInfo;
pub use nodes::ProviderNodes;

use crate::check::{Check, CheckParams, Source};
use crate::deps::{Built, NodeFactory};
use crate::error::{GroupError, ProviderError};
use crate::fetch::FetchRequest;
use crate::health::StatusRanges;
use crate::node::{Ghost, Item, Leaf, Node};
use crate::outbounds::Outbounds;
use crate::shared::Shared;

const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const INFO_SUFFIX: &str = ".subscription-info";

type Hash = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VehicleType {
    File,
    Http,
    Inline,
}

impl VehicleType {
    pub fn as_str(self) -> &'static str {
        match self {
            VehicleType::File => "File",
            VehicleType::Http => "HTTP",
            VehicleType::Inline => "Inline",
        }
    }
}

enum Vehicle {
    File {
        path: PathBuf,
    },
    Http {
        url: String,
        path: PathBuf,
        proxy: String,
        headers: Vec<(String, String)>,
        size_limit: Option<u64>,
    },
    Inline {
        payload: Vec<Map<String, Value>>,
    },
}

#[derive(Default)]
struct State {
    updated_at: Option<SystemTime>,
    hash: Option<Hash>,
    info: Option<SubscriptionInfo>,
    failures: u32,
}

pub struct ProviderView {
    pub name: Arc<str>,
    pub vehicle: VehicleType,
    pub count: usize,
    pub updated_at: Option<SystemTime>,
    pub path: String,
    pub subscription: Option<SubscriptionInfo>,
}

pub struct ProxyProvider {
    name: Arc<str>,
    def: ProxyProviderDef,
    vehicle: Vehicle,
    nodes: ArcSwap<ProviderNodes>,
    state: Mutex<State>,
    gate: tokio::sync::Mutex<()>,
    updating: AtomicBool,
    check: Arc<Check>,
    shared: Arc<Shared>,
}

fn md5(bytes: &[u8]) -> Hash {
    Md5::digest(bytes).into()
}

fn hex(hash: &Hash) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ProviderError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| ProviderError::Io(err.to_string()))
}

pub(crate) fn items_from_maps(
    def: &ProxyProviderDef,
    factory: &dyn NodeFactory,
    provider: &Arc<str>,
    maps: Vec<Map<String, Value>>,
) -> Result<Vec<Item>, String> {
    let selected = def.select_proxies(maps).map_err(|err| err.message)?;
    let mut items = Vec::with_capacity(selected.len());
    for (index, map) in selected.iter().enumerate() {
        match factory
            .build_map(map)
            .map_err(|err| format!("proxy {index} error: {err}"))?
        {
            Built::Node(outbound) => items.push(Item::Live(Node::Leaf(Leaf::new(
                outbound,
                Some(provider.clone()),
            )))),
            Built::Quarantined { name, kind, reason } => items.push(Item::Ghost(Arc::new(Ghost {
                name: Arc::from(name),
                kind: Arc::from(kind),
                reason: Arc::from(reason),
                provider: Some(provider.clone()),
            }))),
        }
    }
    Ok(items)
}

fn items_from_bytes(
    def: &ProxyProviderDef,
    factory: &dyn NodeFactory,
    provider: &Arc<str>,
    bytes: &[u8],
) -> Result<Vec<Item>, String> {
    let key = Some(def.age_secret_key.as_str()).filter(|key| !key.is_empty());
    let maps = parse_provider_content(bytes, key).map_err(|err| err.message)?;
    items_from_maps(def, factory, provider, maps)
}

impl ProxyProvider {
    pub(crate) fn new(
        def: &ProxyProviderDef,
        shared: Arc<Shared>,
    ) -> Result<Arc<ProxyProvider>, GroupError> {
        let name: Arc<str> = Arc::from(def.name.as_str());
        let fail = |message: String| GroupError::Provider {
            provider: def.name.clone(),
            message,
        };
        let confine = |path: &str| {
            shared
                .home
                .confine(path)
                .map_err(|err| fail(format!("{err}: {path}")))
        };
        let vehicle = match &def.source {
            ProxySource::File { path } => Vehicle::File {
                path: confine(path)?,
            },
            ProxySource::Http(http) => {
                let path = if http.path.is_empty() {
                    confine(&format!("proxies/{}", hex(&md5(http.url.as_bytes()))))?
                } else {
                    confine(&http.path)?
                };
                Vehicle::Http {
                    url: http.url.clone(),
                    path,
                    proxy: http.proxy.clone(),
                    headers: http
                        .header
                        .iter()
                        .flat_map(|(key, values)| {
                            values.iter().map(move |value| (key.clone(), value.clone()))
                        })
                        .collect(),
                    size_limit: u64::try_from(http.size_limit)
                        .ok()
                        .filter(|limit| *limit > 0),
                }
            }
            ProxySource::Inline { payload } => Vehicle::Inline {
                payload: payload.clone(),
            },
        };
        let payload = match &vehicle {
            Vehicle::Inline { payload } => payload,
            _ => &def.fallback,
        };
        let initial = if def.override_.expr || payload.is_empty() {
            // Loading emptied an inline one with a warning: its nodes must not run without the expressions.
            Vec::new()
        } else {
            items_from_maps(def, shared.factory.as_ref(), &name, payload.clone()).map_err(fail)?
        };
        let health = &def.health_check;
        let params = CheckParams {
            id: format!("provider:{}", def.name),
            url: health.url.clone(),
            timeout_ms: health.timeout,
            interval_secs: if health.enable { health.interval } else { 0 },
            lazy: health.lazy,
            expected: StatusRanges::parse(&health.expected_status).unwrap_or_default(),
        };
        Ok(Arc::new_cyclic(|weak: &Weak<ProxyProvider>| {
            ProxyProvider {
                name,
                def: def.clone(),
                vehicle,
                nodes: ArcSwap::from_pointee(ProviderNodes::new(0, initial)),
                state: Mutex::new(State {
                    updated_at: matches!(def.source, ProxySource::Inline { .. })
                        .then(SystemTime::now),
                    ..State::default()
                }),
                gate: tokio::sync::Mutex::new(()),
                updating: AtomicBool::new(false),
                check: Check::new(params, Source::Provider(weak.clone())),
                shared,
            }
        }))
    }

    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    pub fn vehicle_type(&self) -> VehicleType {
        match self.vehicle {
            Vehicle::File { .. } => VehicleType::File,
            Vehicle::Http { .. } => VehicleType::Http,
            Vehicle::Inline { .. } => VehicleType::Inline,
        }
    }

    /// Inline providers are not offered to the host for updating.
    pub fn is_external(&self) -> bool {
        self.vehicle_type() != VehicleType::Inline
    }

    pub fn version(&self) -> u32 {
        self.nodes.load().version()
    }

    pub fn nodes(&self) -> Arc<ProviderNodes> {
        self.nodes.load_full()
    }

    pub fn count(&self) -> usize {
        self.nodes.load().len()
    }

    pub(crate) fn check(&self) -> &Arc<Check> {
        &self.check
    }

    pub fn health_check_url(&self) -> &str {
        self.check.url()
    }

    pub fn expected_text(&self) -> &str {
        &self.def.health_check.expected_status
    }

    pub async fn health_check(&self, owner: &Outbounds) {
        self.check.check(owner).await;
    }

    pub fn path(&self) -> String {
        match &self.vehicle {
            Vehicle::File { path } | Vehicle::Http { path, .. } => {
                path.to_string_lossy().into_owned()
            }
            Vehicle::Inline { .. } => String::new(),
        }
    }

    pub fn updated_at(&self) -> Option<SystemTime> {
        self.state().updated_at
    }

    pub fn subscription_info(&self) -> Option<SubscriptionInfo> {
        self.state().info
    }

    pub fn view(&self) -> ProviderView {
        ProviderView {
            name: self.name.clone(),
            vehicle: self.vehicle_type(),
            count: self.count(),
            updated_at: self.updated_at(),
            path: self.path(),
            subscription: self.subscription_info(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        lock(&self.state)
    }

    fn file_path(&self) -> Option<&PathBuf> {
        match &self.vehicle {
            Vehicle::File { path } | Vehicle::Http { path, .. } => Some(path),
            Vehicle::Inline { .. } => None,
        }
    }

    async fn read_vehicle(&self) -> Result<(Vec<u8>, Hash), ProviderError> {
        let (url, proxy, headers, size_limit) = match &self.vehicle {
            Vehicle::File { path } => {
                let (home, path) = (self.shared.home.clone(), path.clone());
                let bytes = blocking(move || home.read(&path))
                    .await?
                    .map_err(|err| ProviderError::Io(err.to_string()))?;
                let hash = md5(&bytes);
                return Ok((bytes, hash));
            }
            Vehicle::Inline { .. } => {
                return Err(ProviderError::Io(
                    "an inline provider has no content to read".into(),
                ));
            }
            Vehicle::Http {
                url,
                proxy,
                headers,
                size_limit,
                ..
            } => (url, proxy, headers, size_limit),
        };
        let response = self
            .shared
            .fetcher
            .get(FetchRequest {
                url: url.clone(),
                headers: headers.clone(),
                via_proxy: Some(proxy.clone()).filter(|proxy| !proxy.is_empty()),
                size_limit: *size_limit,
                timeout: HTTP_TIMEOUT,
            })
            .await
            .map_err(ProviderError::Fetch)?;
        if let Some(userinfo) = response
            .header("subscription-userinfo")
            .filter(|text| !text.is_empty())
        {
            self.state().info = Some(SubscriptionInfo::parse(userinfo));
            self.save_info(userinfo);
        }
        if !(200..=299).contains(&response.status) {
            return Err(ProviderError::status(response.status));
        }
        let hash = md5(&response.body);
        Ok((response.body, hash))
    }

    fn save_info(&self, userinfo: &str) {
        if let Some(path) = self.file_path() {
            let mut name = path.clone().into_os_string();
            name.push(INFO_SUFFIX);
            if let Err(err) = self
                .shared
                .home
                .write_atomic(PathBuf::from(name), userinfo.as_bytes())
            {
                tracing::debug!("[Provider] {} keep subscription info: {err}", self.name);
            }
        }
    }

    fn restore_info(&self) {
        let Some(path) = self.file_path() else {
            return;
        };
        let mut name = path.clone().into_os_string();
        name.push(INFO_SUFFIX);
        let Ok(bytes) = self.shared.home.read(PathBuf::from(name)) else {
            return;
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut state = self.state();
        if state.info.is_none() && !text.is_empty() {
            state.info = Some(SubscriptionInfo::parse(&text));
        }
    }

    async fn parse(&self, bytes: Vec<u8>) -> Result<Vec<Item>, ProviderError> {
        let (def, factory, name) = (
            self.def.clone(),
            self.shared.factory.clone(),
            self.name.clone(),
        );
        blocking(move || items_from_bytes(&def, factory.as_ref(), &name, &bytes))
            .await?
            .map_err(ProviderError::Content)
    }

    fn apply(&self, items: Vec<Item>) {
        let version = self.nodes.load().version().wrapping_add(1);
        self.nodes
            .store(Arc::new(ProviderNodes::new(version, items)));
        if self.check.is_auto() {
            self.check.kick();
        }
        self.shared.route.moved();
        self.shared.request_refresh();
    }

    async fn load_buf(
        &self,
        bytes: Vec<u8>,
        hash: Hash,
        update_file: bool,
    ) -> Result<Refresh, ProviderError> {
        let _gate = self.gate.lock().await;
        if self.state().hash == Some(hash) {
            if update_file {
                self.touch_file().await;
            }
            let mut state = self.state();
            state.updated_at = Some(SystemTime::now());
            state.failures = 0;
            return Ok(Refresh::Unchanged);
        }
        let items = match self.parse(bytes.clone()).await {
            Ok(items) => items,
            Err(err) => {
                self.state().failures += 1;
                return Err(err);
            }
        };
        self.state().failures = 0;
        if update_file && let Some(path) = self.file_path().cloned() {
            let home = self.shared.home.clone();
            blocking(move || home.write_atomic(&path, &bytes))
                .await?
                .map_err(|err| ProviderError::Io(err.to_string()))?;
        }
        {
            let mut state = self.state();
            state.updated_at = Some(SystemTime::now());
            state.hash = Some(hash);
        }
        self.apply(items);
        Ok(Refresh::Updated)
    }

    async fn touch_file(&self) {
        let Some(path) = self.file_path().cloned() else {
            return;
        };
        let _ = blocking(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .and_then(|file| file.set_modified(SystemTime::now()))
        })
        .await;
    }

    async fn pull(&self) -> Result<Refresh, ProviderError> {
        let (bytes, hash) = match self.read_vehicle().await {
            Ok(read) => read,
            Err(err) => {
                self.state().failures += 1;
                return Err(err);
            }
        };
        let update_file = !matches!(self.vehicle, Vehicle::File { .. });
        self.load_buf(bytes, hash, update_file).await
    }

    /// Loads what is on disk, then the network if there is nothing usable.
    /// True means the file is older than the update interval.
    pub async fn initial(&self) -> Result<bool, ProviderError> {
        if matches!(self.vehicle, Vehicle::Inline { .. }) {
            return Ok(false);
        }
        self.restore_info();
        if let Some(path) = self.file_path().cloned() {
            let (home, read_path) = (self.shared.home.clone(), path.clone());
            let local = blocking(move || {
                let bytes = home.read(&read_path).ok()?;
                let modified = std::fs::metadata(&read_path)
                    .and_then(|meta| meta.modified())
                    .ok();
                Some((bytes, modified))
            })
            .await?;
            if let Some((bytes, modified)) = local {
                let hash = md5(&bytes);
                let loaded = self.load_buf(bytes, hash, false).await;
                if modified.is_some() {
                    self.state().updated_at = modified;
                }
                if loaded.is_ok() {
                    let interval = self.interval();
                    let stale = modified
                        .and_then(|at| at.elapsed().ok())
                        .is_some_and(|age| age > interval);
                    return Ok(stale);
                }
            }
        }
        self.pull().await.map(|_| false)
    }

    pub fn interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.def.interval))
    }

    /// The manual update the host asks for. Two at once are refused.
    pub async fn update(&self) -> Result<(), ProviderError> {
        let _claim = self.claim()?;
        self.reported(async {
            if let Vehicle::Inline { .. } = self.vehicle {
                self.state().updated_at = Some(SystemTime::now());
                return Ok(Refresh::Unchanged);
            }
            self.pull().await
        })
        .await
        .map(|_| ())
    }

    pub async fn side_load(&self, data: &[u8]) -> Result<(), ProviderError> {
        let _claim = self.claim()?;
        if let Vehicle::Inline { .. } = self.vehicle {
            return Err(ProviderError::Io(
                "an inline provider takes no side load".into(),
            ));
        }
        self.reported(self.load_buf(data.to_vec(), md5(data), true))
            .await
            .map(|_| ())
    }

    fn report(&self, phase: ResourcePhase) {
        self.shared.emit(|| {
            CoreEvent::Resource(ResourceUpdate {
                kind: ResourceKind::ProxyProvider,
                name: self.name.clone(),
                phase,
            })
        });
    }

    async fn reported(
        &self,
        work: impl Future<Output = Result<Refresh, ProviderError>>,
    ) -> Result<Refresh, ProviderError> {
        let fetch = Fetch::start(|phase| self.report(phase));
        let outcome = work.await;
        fetch.finish(ResourcePhase::of(&outcome));
        outcome
    }

    fn claim(&self) -> Result<Claim<'_>, ProviderError> {
        if self.updating.swap(true, Ordering::AcqRel) {
            return Err(ProviderError::Updating);
        }
        Ok(Claim(&self.updating))
    }

    /// The mapping a node of this provider was built from, with the provider's
    /// `dialer-proxy` and `override` applied. Reads the content again, because
    /// positions are not kept.
    pub async fn definition(
        &self,
        name: &str,
    ) -> Result<Option<Map<String, Value>>, ProviderError> {
        let def = self.def.clone();
        let wanted = name.to_string();
        let source = match &self.vehicle {
            Vehicle::Inline { payload } => Err(payload.clone()),
            Vehicle::File { path } | Vehicle::Http { path, .. } => {
                let (home, path) = (self.shared.home.clone(), path.clone());
                match blocking(move || home.read(&path)).await? {
                    Ok(bytes) => Ok(bytes),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        Err(self.def.fallback.clone())
                    }
                    Err(err) => return Err(ProviderError::Io(err.to_string())),
                }
            }
        };
        blocking(move || {
            let maps = match source {
                Ok(bytes) => {
                    let key = Some(def.age_secret_key.as_str()).filter(|key| !key.is_empty());
                    parse_provider_content(&bytes, key)
                        .map_err(|err| ProviderError::Content(err.message))?
                }
                Err(payload) => payload,
            };
            let Ok(selected) = def.select_proxies(maps) else {
                return Ok(None);
            };
            Ok(selected
                .into_iter()
                .find(|map| map.get("name").and_then(Value::as_str) == Some(wanted.as_str())))
        })
        .await?
    }

    async fn update_with_log(&self) {
        match self.reported(self.pull()).await {
            Ok(Refresh::Unchanged) => {
                tracing::debug!("[Provider] {}'s content doesn't change", self.name);
            }
            Ok(Refresh::Updated) => tracing::info!("[Provider] {}'s content update", self.name),
            Err(err) => tracing::warn!("[Provider] {} pull error: {err}", self.name),
        }
    }

    fn pull_delay(&self, interval: Duration) -> Duration {
        let failures = self.state().failures;
        if failures > 0 {
            backoff(failures, interval).min(interval)
        } else {
            interval
        }
    }

    fn since_update(&self) -> Duration {
        self.state()
            .updated_at
            .and_then(|at| at.elapsed().ok())
            .unwrap_or(Duration::MAX)
    }
}

struct Claim<'a>(&'a AtomicBool);

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Loads the provider, then keeps it fresh on its interval. The loader
/// slot is held for the load only. Every step of the first load waits for
/// `answered`, so a host hears of the provider only once the apply that made it
/// has finished.
pub(crate) async fn run(
    provider: Weak<ProxyProvider>,
    stop: CancellationToken,
    answered: CancellationToken,
) {
    let (initial, interval) = {
        let Some(strong) = provider.upgrade() else {
            return;
        };
        let loaded = {
            let report = |phase| strong.report(phase);
            let load = strong.initial();
            tokio::pin!(load);
            let (fetch, loaded) = tokio::select! {
                _ = stop.cancelled() => return,
                loaded = &mut load => (None, loaded),
                () = answered.cancelled() => {
                    let fetch = Fetch::start(report);
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        loaded = &mut load => (Some(fetch), loaded),
                    }
                }
            };
            let fetch = match fetch {
                Some(fetch) => fetch,
                None => {
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        () = answered.cancelled() => {}
                    }
                    Fetch::start(report)
                }
            };
            match &loaded {
                Ok(_) => fetch.finish(ResourcePhase::Updated),
                Err(err) => {
                    tracing::warn!("initial proxy provider {} error: {err}", strong.name);
                    fetch.finish(ResourcePhase::Failed(err.to_string()));
                }
            }
            loaded
        };
        if let Vehicle::File { path } = &strong.vehicle {
            let watch = concord_platform::FileWatch::new(path.clone());
            drop(strong);
            watch_file(provider, watch, stop).await;
            return;
        }
        if !matches!(strong.vehicle, Vehicle::Http { .. }) {
            return;
        }
        (loaded, strong.interval())
    };
    if initial.is_err() {
        let loaded = retry_until_loaded(interval, &stop, || async {
            let Some(strong) = provider.upgrade() else {
                return Attempt::Gone;
            };
            match strong.reported(strong.pull()).await {
                Ok(_) => Attempt::Loaded,
                Err(err) => {
                    tracing::warn!("[Provider] {} pull error: {err}", strong.name);
                    Attempt::Retry
                }
            }
        })
        .await;
        if !loaded {
            return;
        }
    }
    if interval.is_zero() {
        return;
    }
    let force = initial.unwrap_or_default();
    let mut delay = {
        let Some(strong) = provider.upgrade() else {
            return;
        };
        let remaining = interval.saturating_sub(strong.since_update()).min(interval);
        if force {
            strong.update_with_log().await;
        }
        if strong.state().failures > 0 {
            remaining.min(backoff(strong.state().failures, interval))
        } else {
            remaining
        }
    };
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
        let Some(strong) = provider.upgrade() else {
            return;
        };
        strong.update_with_log().await;
        delay = strong.pull_delay(interval);
    }
}

/// A file provider has no interval; mihomo reloads it when the file changes.
async fn watch_file(
    provider: Weak<ProxyProvider>,
    mut watch: concord_platform::FileWatch,
    stop: CancellationToken,
) {
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            () = watch.changed() => {}
        }
        let Some(strong) = provider.upgrade() else {
            return;
        };
        strong.update_with_log().await;
    }
}
