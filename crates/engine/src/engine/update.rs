use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use concord_common::{Change, FindProcessMode, GeneralChange, LogLevel, Origin, TunnelMode};

use super::views::users_of;
use super::{Engine, UpdateRequest};
use crate::apply::Applied;
use crate::error::Failure;
use crate::lan::LanPatch;
use crate::resources::GeoUrls;

impl Engine {
    pub async fn update(&self, request: UpdateRequest) -> Result<(), Failure> {
        self.update_as(Origin::Host, request).await.map(|_| ())
    }

    /// Returns the change it made, or the last change when it made none.
    pub async fn update_as(&self, origin: Origin, request: UpdateRequest) -> Result<u64, Failure> {
        let mut state = self.state.lock().await;
        let Some(applied) = state.as_mut() else {
            return Err(Failure::core("config is not applied"));
        };
        let lan = LanPatch::of(&request)?;
        let before = Settled::of(applied, &self.shared.geo.urls.load());
        let general = &mut applied.general;
        if let Some(port) = request.mixed_port {
            general.mixed_port = port;
        }
        if let Some(allow) = request.allow_lan {
            general.allow_lan = allow;
        }
        lan.apply(general);
        let mut live = self.shared.tunnel.live();
        if let Some(mode) = request
            .find_process_mode
            .as_deref()
            .and_then(FindProcessMode::parse)
        {
            general.find_process_mode = mode;
            live.find_process_mode = mode;
        }
        if let Some(enabled) = request.tcp_concurrent {
            general.tcp_concurrent = enabled;
        }
        if let Some(enabled) = request.unified_delay {
            general.unified_delay = enabled;
            self.shared
                .options
                .unified_delay
                .store(enabled, Ordering::Relaxed);
        }
        let (mut moved, mut reset) = (false, false);
        if let Some(mode) = request.mode.as_deref().and_then(TunnelMode::parse) {
            moved = general.mode != mode;
            general.mode = mode;
            live.mode = mode;
        }
        if let Some(level) = request
            .log_level
            .as_deref()
            .and_then(concord_common::LogLevel::parse)
        {
            general.log_level = level;
        }
        if let Some(enabled) = request.ipv6 {
            reset = general.ipv6 != enabled;
            general.ipv6 = enabled;
        }
        self.shared.tunnel.set_live(live);
        if let Some(runtime) = self.runtime() {
            runtime.dns.set_ipv6(general.ipv6);
            runtime
                .outbounds
                .set_dial_flags(general.tcp_concurrent, general.ipv6);
        }
        if let Some(patch) = request.tun {
            applied.tun.enable = patch.enable;
            if let Some(auto_route) = patch.auto_route {
                applied.tun.auto_route = auto_route;
            }
            if let Some(device) = patch.device {
                applied.tun.device = device;
            }
            if let Some(stack) = patch.stack {
                applied.tun.stack_name = stack;
            }
        }
        let general = &mut applied.general;
        if let Some(lines) = request.authentication {
            general.authentication = lines
                .iter()
                .filter_map(|line| line.split_once(':'))
                .map(|(user, pass)| concord_config::general::Credential {
                    user: user.to_string(),
                    pass: pass.to_string(),
                })
                .collect();
        }
        if let Some(options) = &request.options {
            self.apply_options(options);
        }
        self.reconcile_listeners(applied).await;
        let general = &mut applied.general;
        let mut urls = (**self.shared.geo.urls.load()).clone();
        for (kind, link) in request.geox_url {
            if !urls.set(&kind, link) {
                tracing::warn!("geox-url: unknown geo resource {kind:?}");
            }
        }
        self.shared.geo.urls.store(Arc::new(urls));
        if let Some(enabled) = request.geo_auto_update {
            general.geo_auto_update = enabled;
        }
        if let Some(hours) = request
            .geo_update_interval
            .and_then(|hours| u32::try_from(hours).ok())
        {
            general.geo_update_interval = hours;
        }
        self.shared.geo.sync_auto(
            general.geo_auto_update,
            general.geo_update_interval,
            self.shared.fetcher.clone(),
            &self.tasks,
        );
        if reset {
            self.route.reset(self.is_running());
        } else if moved {
            self.route.moved();
        }
        let change = before.change_to(&Settled::of(applied, &self.shared.geo.urls.load()));
        let mut seq = self.intent.lock().await;
        if !change.is_empty() {
            self.publish_change(&mut seq, origin, Change::General(change));
        }
        Ok(*seq)
    }
}

/// What `update` can change that a host keeps, so a patch reports only what moved.
struct Settled {
    mode: TunnelMode,
    log_level: LogLevel,
    allow_lan: bool,
    ipv6: bool,
    mixed_port: u16,
    tcp_concurrent: bool,
    find_process_mode: FindProcessMode,
    unified_delay: bool,
    users: Vec<String>,
    geo_auto_update: bool,
    geo_update_interval: u32,
    geox_url: BTreeMap<String, String>,
    tun_enable: bool,
    tun_device: String,
    tun_stack: String,
    tun_auto_route: bool,
}

impl Settled {
    fn of(applied: &Applied, urls: &GeoUrls) -> Self {
        let general = &applied.general;
        Settled {
            mode: general.mode,
            log_level: general.log_level,
            allow_lan: general.allow_lan,
            ipv6: general.ipv6,
            mixed_port: general.mixed_port,
            tcp_concurrent: general.tcp_concurrent,
            find_process_mode: general.find_process_mode,
            unified_delay: general.unified_delay,
            users: users_of(general),
            geo_auto_update: general.geo_auto_update,
            geo_update_interval: general.geo_update_interval,
            geox_url: geox_url_of(urls),
            tun_enable: applied.tun.enable,
            tun_device: applied.tun.device.clone(),
            tun_stack: applied.tun.stack_name.clone(),
            tun_auto_route: applied.tun.auto_route,
        }
    }

    fn change_to(&self, after: &Settled) -> GeneralChange {
        fn moved<T: PartialEq + Clone>(before: &T, after: &T) -> Option<T> {
            (before != after).then(|| after.clone())
        }
        GeneralChange {
            mode: moved(&self.mode, &after.mode),
            log_level: moved(&self.log_level, &after.log_level),
            allow_lan: moved(&self.allow_lan, &after.allow_lan),
            ipv6: moved(&self.ipv6, &after.ipv6),
            mixed_port: moved(&self.mixed_port, &after.mixed_port),
            tcp_concurrent: moved(&self.tcp_concurrent, &after.tcp_concurrent),
            find_process_mode: moved(&self.find_process_mode, &after.find_process_mode),
            unified_delay: moved(&self.unified_delay, &after.unified_delay),
            authentication: moved(&self.users, &after.users),
            geo_auto_update: moved(&self.geo_auto_update, &after.geo_auto_update),
            geo_update_interval: moved(&self.geo_update_interval, &after.geo_update_interval),
            geox_url: moved(&self.geox_url, &after.geox_url),
            tun_enable: moved(&self.tun_enable, &after.tun_enable),
            tun_device: moved(&self.tun_device, &after.tun_device),
            tun_stack: moved(&self.tun_stack, &after.tun_stack),
            tun_auto_route: moved(&self.tun_auto_route, &after.tun_auto_route),
        }
    }
}

fn geox_url_of(urls: &GeoUrls) -> BTreeMap<String, String> {
    urls.entries()
        .into_iter()
        .map(|(key, url)| (key.to_string(), url.to_string()))
        .collect()
}
