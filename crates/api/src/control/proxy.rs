use concord_common::Origin;
use concord_engine::StatusRanges;
use concord_proto::ApiError;
use concord_proto::types::*;

use super::{Control, data_error};
use crate::convert;
use crate::stream::Subscription;
use crate::watch as streams;

/// Whether `expected` of a delay test reads as status ranges.
pub fn valid_status_ranges(text: &str) -> bool {
    StatusRanges::parse(text).is_some()
}

fn expected_statuses(text: Option<&str>) -> Result<StatusRanges, ApiError> {
    StatusRanges::parse(text.unwrap_or_default())
        .ok_or_else(|| ApiError::invalid_field("expected", "invalid status ranges"))
}

impl Control {
    pub async fn proxy_select_as(
        &self,
        origin: Origin,
        params: ProxySelectParams,
    ) -> Result<ProxySelectResult, ApiError> {
        let outcome = self
            .engine
            .select_as(origin, &params.group, &params.proxy)
            .await;
        match outcome.message.as_str() {
            "" => Ok(ProxySelectResult {
                changed: outcome.changed,
                seq: outcome.seq,
            }),
            "Not found group" => Err(ApiError::not_found("group", params.group)),
            "proxy not exist" => Err(ApiError::not_found("proxy", params.proxy)),
            "Group is not selectable" => Err(ApiError::conflict(
                "not_selectable",
                format!("group {} is not selectable", params.group),
            )),
            other => Err(ApiError::conflict("select", other)),
        }
    }

    pub(super) async fn proxy_groups(&self, _params: Empty) -> Result<ProxyGroups, ApiError> {
        Ok(streams::proxy_groups(&self.engine))
    }

    pub(super) async fn proxy_watch(
        &self,
        _params: ProxyWatchParams,
    ) -> Result<Subscription<ProxyGroups, ProxyDelta>, ApiError> {
        Ok(streams::proxies(self.engine.clone(), &self.bus))
    }

    pub(super) async fn proxy_select(
        &self,
        params: ProxySelectParams,
    ) -> Result<ProxySelectResult, ApiError> {
        self.proxy_select_as(Origin::Host, params).await
    }

    pub(super) async fn proxy_states(
        &self,
        params: ProxyStatesParams,
    ) -> Result<ProxyStates, ApiError> {
        Ok(ProxyStates {
            proxies: self
                .engine
                .node_states(params.names.as_deref())
                .into_iter()
                .map(convert::proxy_state)
                .collect(),
        })
    }

    pub(super) async fn proxy_definition(
        &self,
        params: ProxyDefinitionParams,
    ) -> Result<ProxyDefinition, ApiError> {
        self.require_initialized()?;
        match self
            .engine
            .proxy_definition(params.name.clone())
            .await
            .map_err(data_error)?
        {
            Some(proxy) => Ok(ProxyDefinition { proxy }),
            None => Err(ApiError::not_found("proxy", params.name)),
        }
    }

    pub(super) async fn delay_test(
        &self,
        params: DelayTestParams,
    ) -> Result<DelayResult, ApiError> {
        let expected = expected_statuses(params.expected.as_deref())?;
        let url = params.url.unwrap_or_default();
        let timeout = params
            .timeout
            .map_or(0, |ms| i64::try_from(ms).unwrap_or(i64::MAX));
        let result = self
            .engine
            .test_delay_expecting(&params.proxy, &url, &expected, timeout)
            .await;
        Ok(DelayResult {
            name: result.name,
            url: result.url,
            value: result.value,
        })
    }

    pub(super) async fn delay_run(
        &self,
        params: DelayRunParams,
    ) -> Result<Subscription<Empty, DelayRunEvent>, ApiError> {
        let expected = expected_statuses(params.expected.as_deref())?;
        let timeout = params
            .timeout
            .map_or(0, |ms| i64::try_from(ms).unwrap_or(i64::MAX));
        Ok(Subscription::new(
            None,
            streams::delay_run(
                self.engine.clone(),
                params.proxies,
                params.url.unwrap_or_default(),
                expected,
                timeout,
                params.concurrency,
            ),
        ))
    }

    pub(super) async fn probe_outbound_ip(
        &self,
        params: OutboundIpParams,
    ) -> Result<OutboundIp, ApiError> {
        let timeout = params
            .timeout
            .map_or(0, |ms| i64::try_from(ms).unwrap_or(i64::MAX));
        let value = self
            .engine
            .probe_outbound_ip(params.proxy, params.urls, timeout)
            .await;
        serde_json::from_value(value).map_err(|err| ApiError::internal(err.to_string()))
    }

    pub(super) async fn probe_services(
        &self,
        params: ServicesParams,
    ) -> Result<ServiceList, ApiError> {
        let timeout = params
            .timeout
            .map_or(0, |ms| i64::try_from(ms).unwrap_or(i64::MAX));
        let value = self
            .engine
            .probe_services(params.proxy, params.names, timeout)
            .await;
        Ok(ServiceList {
            items: serde_json::from_value(value)
                .map_err(|err| ApiError::internal(err.to_string()))?,
        })
    }
}
