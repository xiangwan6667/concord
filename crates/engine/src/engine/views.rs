use concord_common::{LogLevel, RouteView};
use concord_config::general::ControllerCors;
use concord_tun::Congestion;

use super::{Engine, MitmService};
use crate::apply;
use crate::faults::ServiceFault;
use crate::lan;
use crate::views::{
    Capabilities, Features, GeneralView, MemoryStats, RuleView, TunView, WarningView,
};

impl Engine {
    pub fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            rss: concord_platform::resident_memory(),
            ..Default::default()
        }
    }

    pub fn capabilities(&self) -> Capabilities {
        let config = apply::capabilities();
        Capabilities {
            implementation: concord_common::CORE_NAME,
            version: env!("CARGO_PKG_VERSION"),
            proxy_types: config.proxy_types,
            transports: config.transports,
            rule_types: config.rule_types,
            ss_plugins: config.ss_plugins,
            congestion_controllers: Congestion::NAMES.to_vec(),
            features: Features {
                mitm: MitmService::ENABLED,
                ech: config.ech,
                system_stack: false,
            },
        }
    }

    pub fn clock_offset_nanos(&self) -> i64 {
        self.shared.clock.nanos()
    }

    pub async fn log_level(&self) -> Option<LogLevel> {
        self.state
            .lock()
            .await
            .as_ref()
            .map(|applied| applied.general.log_level)
    }

    /// The profile's `external-controller` and `secret`; empty while a host owns them.
    pub async fn profile_controller(&self) -> (String, String, ControllerCors) {
        self.state
            .lock()
            .await
            .as_ref()
            .map(|applied| {
                (
                    applied.general.external_controller.clone(),
                    applied.general.secret.clone(),
                    applied.general.external_controller_cors.clone(),
                )
            })
            .unwrap_or_default()
    }

    pub async fn general(&self) -> Option<GeneralView> {
        let state = self.state.lock().await;
        let applied = state.as_ref()?;
        let seq = *self.intent.lock().await;
        let general = &applied.general;
        let urls = self.shared.geo.urls.load();
        Some(GeneralView {
            seq,
            port: general.port,
            socks_port: general.socks_port,
            redir_port: general.redir_port,
            tproxy_port: general.tproxy_port,
            mixed_port: general.mixed_port,
            allow_lan: general.allow_lan,
            bind_address: general.bind_address.clone(),
            lan_allowed_ips: lan::texts(&general.lan_allowed_ips),
            lan_disallowed_ips: lan::texts(&general.lan_disallowed_ips),
            users: users_of(general),
            skip_auth_prefixes: general
                .skip_auth_prefixes
                .iter()
                .map(ToString::to_string)
                .collect(),
            mode: general.mode,
            log_level: general.log_level,
            ipv6: general.ipv6,
            tcp_concurrent: general.tcp_concurrent,
            unified_delay: general.unified_delay,
            find_process_mode: general.find_process_mode,
            interface_name: general.interface_name.clone(),
            routing_mark: general.routing_mark,
            sniffing: applied.sniffing,
            global_ua: general.global_ua.clone(),
            keep_alive_idle: general.keep_alive_idle,
            keep_alive_interval: general.keep_alive_interval,
            disable_keep_alive: general.disable_keep_alive,
            geo_auto_update: general.geo_auto_update,
            geo_update_interval: general.geo_update_interval,
            geox_url: urls
                .entries()
                .map(|(key, url)| (key, url.to_string()))
                .to_vec(),
            tun: TunView {
                enable: applied.tun.enable,
                device: applied.tun.device.clone(),
                stack: applied.tun.stack_name.clone(),
                auto_route: applied.tun.auto_route,
                auto_detect_interface: applied.tun.auto_detect_interface,
                dns_hijack: applied.tun.dns_hijack.clone(),
                mtu: applied.tun.mtu,
            },
            selections: self
                .outbounds()
                .map(|outbounds| outbounds.selections())
                .unwrap_or_default(),
        })
    }

    pub fn rules(&self) -> Vec<RuleView> {
        let Some(runtime) = self.runtime() else {
            return Vec::new();
        };
        runtime
            .program
            .rules()
            .map(|(rule, target)| RuleView {
                kind: rule.type_name.to_string(),
                payload: rule.payload.to_string(),
                target: target.to_string(),
            })
            .collect()
    }

    pub fn warnings(&self) -> Vec<WarningView> {
        (**self.warnings.load()).clone()
    }

    pub fn route_view(&self) -> RouteView {
        self.route.view()
    }

    /// Services asked to run that did not start, as of the last apply, update, start or stop.
    pub fn faults(&self) -> Vec<ServiceFault> {
        self.faults.list()
    }

    pub fn tun_fault(&self) -> Option<ServiceFault> {
        self.faults.tun()
    }
}

pub(super) fn users_of(general: &concord_config::general::General) -> Vec<String> {
    general
        .authentication
        .iter()
        .map(|credential| credential.user.clone())
        .collect()
}
