use std::sync::Arc;
use std::time::SystemTime;

use concord_group::{FetchErrorKind, Outbounds, ProviderError, ProxyProvider};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::Engine;
use crate::error::{Failure, ResourceError};
use crate::resources::{RuleProvider, RuleProviders, behavior_of};
use crate::views::{ProviderView, SubscriptionInfo};

/// The proxy and rule providers of the config in force.
pub struct Providers<'a> {
    pub(super) engine: &'a Engine,
}

impl Providers<'_> {
    fn rule_providers(&self) -> Option<Arc<RuleProviders>> {
        self.engine.shared.rule_providers.load_full()
    }

    fn outbounds(&self) -> Option<Arc<Outbounds>> {
        self.engine.outbounds()
    }

    pub fn list(&self) -> Vec<ProviderView> {
        let mut views: Vec<ProviderView> = Vec::new();
        if let Some(outbounds) = self.outbounds() {
            for provider in outbounds.providers() {
                if provider.is_external() {
                    views.push(proxy_provider_view(&provider));
                }
            }
        }
        if let Some(rules) = self.rule_providers() {
            for provider in &rules.list {
                if provider.is_listed() {
                    views.push(rule_provider_view(provider));
                }
            }
        }
        views.sort_by(|a, b| a.name.cmp(&b.name));
        views
    }

    pub fn get(&self, name: &str) -> Option<ProviderView> {
        if let Some(rules) = self.rule_providers()
            && let Some(provider) = rules.get(name)
        {
            return provider.is_listed().then(|| rule_provider_view(provider));
        }
        let provider = self.outbounds()?.provider(name)?;
        provider
            .is_external()
            .then(|| proxy_provider_view(&provider))
    }

    pub async fn update(&self, name: &str) -> Result<(), Failure> {
        if let Some(rules) = self.rule_providers()
            && let Some(provider) = rules.get(name)
        {
            let provider: Arc<RuleProvider> = provider.clone();
            if !rules.claim(&provider) {
                return Err(updating_failure(name));
            }
            let outcome = rules.reported(&provider, rules.pull(&provider)).await;
            rules.release(&provider);
            outcome.map_err(|err| rule_update_failure(name, &err))?;
            self.refresh_route();
            return Ok(());
        }
        self.proxy_provider(name)?
            .update()
            .await
            .map_err(|err| proxy_update_failure(name, &err))?;
        self.refresh_route();
        Ok(())
    }

    /// Tests every node of a proxy provider at its own URL, as its timer would.
    pub async fn health_check(&self, name: &str) -> Result<(), Failure> {
        let provider = self.proxy_provider(name)?;
        let outbounds = self
            .outbounds()
            .ok_or_else(|| provider_failure("provider_not_found", name, "no config in force"))?;
        provider.health_check(&outbounds).await;
        Ok(())
    }

    pub async fn side_load(&self, name: &str, data: String) -> Result<(), Failure> {
        if let Some(rules) = self.rule_providers()
            && let Some(provider) = rules.get(name)
        {
            if !provider.is_listed() {
                return Err(provider_failure(
                    "provider_update_error",
                    name,
                    "not external provider",
                ));
            }
            let provider: Arc<RuleProvider> = provider.clone();
            if !rules.claim(&provider) {
                return Err(updating_failure(name));
            }
            let outcome = rules.side_load(&provider, data.into_bytes()).await;
            rules.release(&provider);
            outcome
                .map_err(|err| provider_failure("provider_update_error", name, &err.to_string()))?;
            self.refresh_route();
            return Ok(());
        }
        self.proxy_provider(name)?
            .side_load(data.as_bytes())
            .await
            .map_err(|err| match err {
                ProviderError::Updating => updating_failure(name),
                other => provider_failure("provider_update_error", name, &other.to_string()),
            })?;
        self.refresh_route();
        Ok(())
    }

    fn proxy_provider(&self, name: &str) -> Result<Arc<ProxyProvider>, Failure> {
        self.outbounds()
            .and_then(|outbounds| outbounds.provider(name))
            .ok_or_else(|| {
                provider_failure(
                    "provider_not_found",
                    name,
                    "external provider does not exist",
                )
            })
    }

    fn refresh_route(&self) {
        if let Some(outbounds) = self.outbounds() {
            outbounds.refresh_picks();
        }
    }
}

fn time_text(at: Option<SystemTime>) -> String {
    at.and_then(|at| OffsetDateTime::from(at).format(&Rfc3339).ok())
        .unwrap_or_else(|| "0001-01-01T00:00:00Z".to_string())
}

fn proxy_provider_view(provider: &ProxyProvider) -> ProviderView {
    ProviderView {
        name: provider.name().to_string(),
        kind: "Proxy",
        vehicle_type: provider.vehicle_type().as_str(),
        count: provider.count(),
        path: provider.path(),
        update_at: time_text(provider.updated_at()),
        subscription_info: provider.subscription_info().map(|info| SubscriptionInfo {
            upload: info.upload,
            download: info.download,
            total: info.total,
            expire: info.expire,
        }),
        test_url: provider.health_check_url().to_string(),
        expected_status: provider.expected_text().to_string(),
        behavior: "",
        format: "",
    }
}

fn rule_provider_view(provider: &RuleProvider) -> ProviderView {
    ProviderView {
        name: provider.def.name.clone(),
        kind: "Rule",
        vehicle_type: provider.vehicle(),
        count: provider.handle.count(),
        path: provider.path_text(),
        update_at: time_text(provider.updated_at()),
        subscription_info: None,
        test_url: String::new(),
        expected_status: String::new(),
        behavior: behavior_of(provider.def.behavior).name(),
        format: concord_rules::Format::from(provider.def.format).name(),
    }
}

fn updating_failure(name: &str) -> Failure {
    provider_failure("provider_updating", name, "external provider is updating")
}

fn provider_failure(code: &str, name: &str, message: &str) -> Failure {
    Failure::new(code, message).with_details(json!({"providerName": name}))
}

fn kind_reason(kind: &FetchErrorKind) -> Option<&'static str> {
    match kind {
        FetchErrorKind::Tls => Some("tls"),
        FetchErrorKind::Dns => Some("dns"),
        FetchErrorKind::Timeout => Some("timeout"),
        FetchErrorKind::Connection => Some("connection"),
        FetchErrorKind::Other => None,
    }
}

/// The reason values are matched by `lib/common/network_error.dart`.
pub(super) fn request_failure(err: &ResourceError, mut details: Value) -> Failure {
    match err {
        ResourceError::Status(code) => {
            details["statusCode"] = json!(code);
            Failure::new("request_bad_response", err.to_string()).with_details(details)
        }
        ResourceError::Fetch(fetch) => {
            if let Some(reason) = kind_reason(&fetch.kind) {
                details["reason"] = json!(reason);
            }
            Failure::new("request_error", err.to_string()).with_details(details)
        }
        ResourceError::Other(message) => Failure::core(message.clone()),
        ResourceError::Load(load) => Failure::core(load.to_string()),
    }
}

fn rule_update_failure(name: &str, err: &ResourceError) -> Failure {
    match err {
        ResourceError::Other(message) => provider_failure("provider_update_error", name, message),
        ResourceError::Load(load) => {
            provider_failure("provider_update_error", name, &load.to_string())
        }
        _ => request_failure(err, json!({"providerName": name})),
    }
}

fn proxy_update_failure(name: &str, err: &ProviderError) -> Failure {
    match err {
        ProviderError::NotFound => provider_failure(
            "provider_not_found",
            name,
            "external provider does not exist",
        ),
        ProviderError::Updating => updating_failure(name),
        ProviderError::Status(_) => {
            let mut details = json!({"providerName": name});
            if let Some(code) = err.status_code() {
                details["statusCode"] = json!(code);
            }
            Failure::new("request_bad_response", err.to_string()).with_details(details)
        }
        ProviderError::Fetch(fetch) => {
            let mut details = json!({"providerName": name});
            if let Some(reason) = kind_reason(&fetch.kind) {
                details["reason"] = json!(reason);
            }
            Failure::new("request_error", err.to_string()).with_details(details)
        }
        other => provider_failure("provider_update_error", name, &other.to_string()),
    }
}
