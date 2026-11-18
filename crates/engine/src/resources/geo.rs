use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use concord_common::backoff::{GEO_RETRY_CAP, provider_backoff};
use concord_common::sync::lock;
use concord_common::{
    CoreEvent, EventSink, Fetch, Refresh, ResourceKind, ResourcePhase, ResourceUpdate,
};
use concord_config::geox::GeoConfig;
use concord_group::{FetchRequest, Fetcher};
use concord_platform::HomeDir;
use concord_rules::geo::{GeoFile, GeoStore};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::fetch::{download, touch};
use crate::error::{GeoUpdateError, WriteError};
use crate::route::RouteCounters;

const GEO_TIMEOUT: Duration = Duration::from_secs(90);
/// Rounds of fetching geo files and parsing again; each round can only add the files a rule-set needs.
pub(super) const GEO_REPARSES: usize = 2;

#[derive(Clone, Debug, Default)]
pub(crate) struct GeoUrls {
    pub mmdb: String,
    pub asn: String,
    pub geosite: String,
}

impl GeoUrls {
    pub fn from_config(config: &GeoConfig) -> Self {
        GeoUrls {
            mmdb: config.mmdb_url.clone(),
            asn: config.asn_url.clone(),
            geosite: config.geosite_url.clone(),
        }
    }

    /// Each URL under its `geox-url` key.
    pub fn entries(&self) -> [(&'static str, &str); 3] {
        [
            ("mmdb", &self.mmdb),
            ("asn", &self.asn),
            ("geosite", &self.geosite),
        ]
    }

    pub fn url(&self, file: GeoFile) -> &str {
        match file {
            GeoFile::Mmdb => &self.mmdb,
            GeoFile::Asn => &self.asn,
            GeoFile::GeoSite => &self.geosite,
        }
    }

    pub fn set(&mut self, kind: &str, link: String) -> bool {
        let slot = match kind.to_ascii_uppercase().as_str() {
            "MMDB" => &mut self.mmdb,
            "ASN" => &mut self.asn,
            "GEOSITE" => &mut self.geosite,
            _ => return false,
        };
        if !link.is_empty() {
            *slot = link;
        }
        true
    }
}

pub(crate) fn geo_file_of(kind: &str) -> Option<GeoFile> {
    match kind {
        "MMDB" => Some(GeoFile::Mmdb),
        "ASN" => Some(GeoFile::Asn),
        "GEOSITE" => Some(GeoFile::GeoSite),
        _ => None,
    }
}

fn geo_kind_of(file: GeoFile) -> &'static str {
    match file {
        GeoFile::Mmdb => "MMDB",
        GeoFile::Asn => "ASN",
        GeoFile::GeoSite => "GEOSITE",
    }
}

fn geo_label(file: GeoFile) -> &'static str {
    match file {
        GeoFile::Mmdb => "MMDB",
        GeoFile::Asn => "ASN",
        GeoFile::GeoSite => "GeoSite",
    }
}

fn geo_file_name(file: GeoFile) -> &'static str {
    match file {
        GeoFile::Mmdb => "MMDB",
        GeoFile::Asn => "ASN",
        GeoFile::GeoSite => "GeoSite.dat",
    }
}

fn geo_request(url: &str) -> FetchRequest {
    FetchRequest {
        url: url.to_string(),
        headers: Vec::new(),
        via_proxy: None,
        size_limit: None,
        timeout: GEO_TIMEOUT,
    }
}

/// Geo data outlives configs, and one resource updates at a time.
pub(crate) struct GeoUpdater {
    pub store: Arc<GeoStore>,
    pub urls: ArcSwap<GeoUrls>,
    claims: Mutex<HashSet<&'static str>>,
    home: Mutex<Option<Arc<HomeDir>>>,
    events: Arc<dyn EventSink>,
    route: Arc<RouteCounters>,
    auto: Mutex<Option<(CancellationToken, u32)>>,
    /// Ends every update and the schedule; shutdown cancels it and init renews it, so
    /// none of them holds up shutdown or outlives the engine's task tracker.
    stop: Mutex<CancellationToken>,
}

/// One resource held for one update. Dropping it, when the update finishes or is
/// cancelled, gives the resource back.
pub(crate) struct Claim {
    updater: Arc<GeoUpdater>,
    file: GeoFile,
}

impl Drop for Claim {
    fn drop(&mut self) {
        lock(&self.updater.claims).remove(geo_kind_of(self.file));
    }
}

impl GeoUpdater {
    pub fn new(
        store: Arc<GeoStore>,
        events: Arc<dyn EventSink>,
        route: Arc<RouteCounters>,
    ) -> Arc<Self> {
        Arc::new(GeoUpdater {
            store,
            urls: ArcSwap::from_pointee(GeoUrls::default()),
            claims: Mutex::new(HashSet::new()),
            home: Mutex::new(None),
            events,
            route,
            auto: Mutex::new(None),
            stop: Mutex::new(CancellationToken::new()),
        })
    }

    pub fn set_home(&self, home: Arc<HomeDir>) {
        {
            let mut slot = lock(&self.home);
            *slot = Some(home);
        }
    }

    pub fn claim(self: &Arc<Self>, file: GeoFile) -> Option<Claim> {
        lock(&self.claims).insert(geo_kind_of(file)).then(|| Claim {
            updater: self.clone(),
            file,
        })
    }

    fn report(&self, file: GeoFile, phase: ResourcePhase) {
        if self.events.enabled() {
            self.events.publish(CoreEvent::Resource(ResourceUpdate {
                kind: ResourceKind::Geo,
                name: Arc::from(geo_kind_of(file)),
                phase,
            }));
        }
    }

    /// The first download of a file a config needs: no events, no comparison.
    async fn reported(
        &self,
        file: GeoFile,
        work: impl Future<Output = Result<(), GeoUpdateError>>,
    ) -> Result<(), GeoUpdateError> {
        let fetch = Fetch::start(|phase| self.report(file, phase));
        let outcome = work.await;
        fetch.finish(match &outcome {
            Ok(()) => ResourcePhase::Updated,
            Err(err) => ResourcePhase::Failed(err.to_string()),
        });
        outcome
    }

    pub async fn fetch_missing(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<(), GeoUpdateError> {
        self.reported(file, self.download_missing(file, fetcher))
            .await
    }

    async fn download_missing(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<(), GeoUpdateError> {
        let name = geo_file_name(file);
        tracing::info!("Can't find {name}, start download");
        let urls = self.urls.load_full();
        let bytes = download(fetcher, geo_request(urls.url(file)))
            .await
            .map_err(|source| GeoUpdateError::Download {
                what: name.to_string(),
                source,
            })?;
        self.write(file, &bytes)?;
        Ok(self.store.ensure(file)?)
    }

    /// Files the rules wait for instead of holding the apply, fetched once it has answered.
    pub fn fetch_deferred(
        self: &Arc<Self>,
        files: &[GeoFile],
        fetcher: Arc<dyn Fetcher>,
        stop: &CancellationToken,
        answered: &CancellationToken,
        tasks: &TaskTracker,
    ) {
        for &file in files {
            let updater = self.clone();
            let fetcher = fetcher.clone();
            let stop = stop.clone();
            let answered = answered.clone();
            tasks.spawn(async move {
                tokio::select! {
                    () = stop.cancelled() => {}
                    () = updater.fetch_until_loaded(file, &*fetcher, &answered) => {}
                }
            });
        }
    }

    async fn fetch_until_loaded(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
        answered: &CancellationToken,
    ) {
        answered.cancelled().await;
        let mut failures = 0;
        while self.store.ensure(file).is_err() {
            if let Err(err) = self.fetch_missing(file, fetcher).await {
                tracing::warn!("[GEO] {err}");
                sleep(provider_backoff(failures, GEO_RETRY_CAP)).await;
                failures = failures.saturating_add(1);
            }
        }
    }

    /// A file on disk that does not parse is replaced, as `geodata.InitGeoSite` does.
    pub async fn replace_invalid(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<(), GeoUpdateError> {
        self.reported(file, self.download_replacement(file, fetcher))
            .await
    }

    async fn download_replacement(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<(), GeoUpdateError> {
        let name = geo_file_name(file);
        tracing::warn!("{name} invalid, remove and download");
        let urls = self.urls.load_full();
        let bytes = download(fetcher, geo_request(urls.url(file)))
            .await
            .map_err(|source| GeoUpdateError::Download {
                what: name.to_string(),
                source,
            })?;
        self.write(file, &bytes)?;
        Ok(self.store.reload(file)?)
    }

    fn write(&self, file: GeoFile, bytes: &[u8]) -> Result<(), WriteError> {
        let home = lock(&self.home).clone().ok_or(WriteError::NotInitialized)?;
        Ok(home.write_atomic(self.store.path(file), bytes)?)
    }

    pub fn spawn_update(
        self: &Arc<Self>,
        claim: Claim,
        fetcher: Arc<dyn Fetcher>,
        tasks: &TaskTracker,
    ) {
        let stop = lock(&self.stop).clone();
        let updater = self.clone();
        tasks.spawn(async move {
            tokio::select! {
                () = stop.cancelled() => {}
                () = updater.update(claim, &*fetcher) => {}
            }
        });
    }

    async fn update(&self, claim: Claim, fetcher: &dyn Fetcher) {
        let file = claim.file;
        let kind = geo_kind_of(file);
        let fetch = Fetch::start(|phase| self.report(file, phase));
        let outcome = self.update_inner(file, fetcher).await;
        drop(claim);
        match &outcome {
            Ok(Refresh::Updated) => self.route.moved(),
            Ok(Refresh::Unchanged) => {}
            Err(err) => tracing::error!("updateGeoData({kind}) error: {err}"),
        }
        fetch.finish(ResourcePhase::of(&outcome));
    }

    async fn update_inner(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<Refresh, GeoUpdateError> {
        let label = geo_label(file);
        let path = self.store.path(file);
        let urls = self.urls.load_full();
        let bytes = download(fetcher, geo_request(urls.url(file)))
            .await
            .map_err(|source| GeoUpdateError::Download {
                what: format!("{label} database file"),
                source,
            })?;
        let same = tokio::fs::read(&path).await.is_ok_and(|old| old == bytes);
        if same {
            let _ = tokio::task::spawn_blocking(move || touch(&path)).await;
            return Ok(Refresh::Unchanged);
        }
        if bytes.is_empty() {
            return Err(GeoUpdateError::NoData { label });
        }
        let bytes =
            tokio::task::spawn_blocking(move || GeoStore::validate(file, &bytes).map(|()| bytes))
                .await?
                .map_err(|message| GeoUpdateError::Invalid { label, message })?;
        self.write(file, &bytes)
            .map_err(|source| GeoUpdateError::Save { label, source })?;
        self.store.reload(file)?;
        Ok(Refresh::Updated)
    }

    pub fn sync_auto(
        self: &Arc<Self>,
        enabled: bool,
        hours: u32,
        fetcher: Arc<dyn Fetcher>,
        tasks: &TaskTracker,
    ) {
        let mut auto = lock(&self.auto);
        if enabled && auto.as_ref().is_some_and(|(_, current)| *current == hours) {
            return;
        }
        if let Some((stop, _)) = auto.take() {
            stop.cancel();
        }
        if !enabled {
            return;
        }
        if hours == 0 {
            tracing::info!("[GEO] Invalid update interval: {hours}");
            return;
        }
        let stop = lock(&self.stop).child_token();
        *auto = Some((stop.clone(), hours));
        let updater = self.clone();
        tasks.spawn(async move {
            tokio::select! {
                () = stop.cancelled() => {}
                () = updater.auto_loop(hours, fetcher) => {}
            }
        });
    }

    fn last_update(&self) -> Option<SystemTime> {
        [GeoFile::Mmdb, GeoFile::Asn, GeoFile::GeoSite]
            .into_iter()
            .find_map(|file| {
                std::fs::metadata(self.store.path(file))
                    .and_then(|meta| meta.modified())
                    .ok()
            })
    }

    async fn update_all(self: &Arc<Self>, fetcher: &dyn Fetcher) {
        tracing::info!("[GEO] Updating GEO database");
        for file in [GeoFile::Mmdb, GeoFile::Asn, GeoFile::GeoSite] {
            if self.store.in_use(file)
                && let Some(claim) = self.claim(file)
            {
                self.update(claim, fetcher).await;
            }
        }
    }

    /// mihomo gives up for good when the first update fails; this keeps its schedule.
    async fn auto_loop(self: &Arc<Self>, hours: u32, fetcher: Arc<dyn Fetcher>) {
        let interval = Duration::from_secs(u64::from(hours) * 3600);
        let Some(last) = self.last_update() else {
            tracing::info!("[GEO] Get GEO database update time error");
            return;
        };
        if last.elapsed().is_ok_and(|age| age > interval) {
            tracing::info!("[GEO] Database has not been updated for {hours}h, update now");
            self.update_all(&*fetcher).await;
        }
        loop {
            sleep(interval).await;
            self.update_all(&*fetcher).await;
        }
    }

    /// Ends the schedule and every update in flight; each gives its claim back.
    pub fn close(&self) {
        lock(&self.stop).cancel();
        lock(&self.auto).take();
    }

    pub fn reopen(&self) {
        let mut stop = lock(&self.stop);
        if stop.is_cancelled() {
            *stop = CancellationToken::new();
        }
    }
}

#[cfg(test)]
mod tests {
    use concord_common::NullSink;
    use concord_group::{FetchError, FetchResponse};

    use super::*;

    struct Unanswered;

    #[async_trait::async_trait]
    impl Fetcher for Unanswered {
        async fn get(&self, _request: FetchRequest) -> Result<FetchResponse, FetchError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn close_ends_the_schedule_and_an_update_in_flight_and_gives_the_claim_back() {
        let dir = tempfile::tempdir().unwrap();
        let sink: Arc<dyn EventSink> = Arc::new(NullSink);
        let geo = GeoUpdater::new(
            Arc::new(GeoStore::new(dir.path())),
            sink.clone(),
            Arc::new(RouteCounters::new(sink)),
        );
        std::fs::write(geo.store.path(GeoFile::Mmdb), b"fresh").unwrap();
        let tasks = TaskTracker::new();
        let fetcher: Arc<dyn Fetcher> = Arc::new(Unanswered);
        geo.sync_auto(true, 1, fetcher.clone(), &tasks);
        let claim = geo.claim(GeoFile::Asn).unwrap();
        geo.spawn_update(claim, fetcher.clone(), &tasks);
        tokio::task::yield_now().await;
        assert_eq!(tasks.len(), 2);

        geo.close();
        tasks.close();
        tokio::time::timeout(Duration::from_secs(5), tasks.wait())
            .await
            .expect("the schedule or the update outlived close");
        assert!(geo.claim(GeoFile::Asn).is_some());

        tasks.reopen();
        geo.reopen();
        geo.sync_auto(true, 1, fetcher, &tasks);
        tokio::task::yield_now().await;
        assert_eq!(tasks.len(), 1, "the schedule runs again after reopen");
        geo.close();
    }

    #[test]
    fn a_panicked_holder_leaves_the_home_and_the_claims_usable() {
        let dir = tempfile::tempdir().unwrap();
        let sink: Arc<dyn EventSink> = Arc::new(NullSink);
        let geo = GeoUpdater::new(
            Arc::new(GeoStore::new(dir.path())),
            sink.clone(),
            Arc::new(RouteCounters::new(sink)),
        );
        concord_test_support::poison(&geo.home);
        geo.set_home(Arc::new(HomeDir::new(dir.path())));
        geo.write(GeoFile::Mmdb, b"written").unwrap();
        assert_eq!(
            std::fs::read(geo.store.path(GeoFile::Mmdb)).unwrap(),
            b"written"
        );

        concord_test_support::poison(&geo.claims);
        let held = geo.claim(GeoFile::Mmdb).unwrap();
        assert!(geo.claim(GeoFile::Mmdb).is_none());
        drop(held);
        assert!(geo.claim(GeoFile::Mmdb).is_some());
    }
}
