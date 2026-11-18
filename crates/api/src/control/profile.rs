use concord_engine::ops;
use concord_proto::ApiError;
use concord_proto::types::*;
use serde_json::{Map, Value};

use super::{Control, core_error, data_error};
use crate::convert;

fn mappings(values: Vec<Value>, field: &str) -> Result<Vec<Map<String, Value>>, ApiError> {
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            convert::value_to_object(value).ok_or_else(|| {
                ApiError::invalid_field(format!("{field}[{index}]"), "a proxy must be a mapping")
            })
        })
        .collect()
}

fn issues(found: Vec<concord_engine::ValidationIssue>) -> IssueList {
    IssueList {
        issues: found
            .into_iter()
            .map(|issue| IndexedIssue {
                index: u32::try_from(issue.index).unwrap_or(u32::MAX),
                message: issue.message,
            })
            .collect(),
    }
}

impl Control {
    pub(super) async fn profile_inspect(
        &self,
        params: ProfileParams,
    ) -> Result<ProfileInspect, ApiError> {
        let value = ops::profile_base(params.profile.path)
            .await
            .map_err(data_error)?;
        serde_json::from_value(value).map_err(|err| ApiError::internal(err.to_string()))
    }

    pub(super) async fn profile_outbounds(
        &self,
        params: ProfileParams,
    ) -> Result<ProfileOutbounds, ApiError> {
        let value = ops::profile_outbounds(params.profile.path)
            .await
            .map_err(data_error)?;
        serde_json::from_value(value).map_err(|err| ApiError::internal(err.to_string()))
    }

    pub(super) async fn profile_build(
        &self,
        params: ProfileBuildParams,
    ) -> Result<TextResult, ApiError> {
        let merged = ops::merge_profile(params.profile.path, params.overlay.to_string())
            .await
            .map_err(data_error)?;
        self.text_result(params.output, merged)
    }

    pub(super) async fn profile_clear_effect(
        &self,
        params: ClearEffectParams,
    ) -> Result<Empty, ApiError> {
        if params.profile_id <= 0 {
            return Err(ApiError::invalid_field("profileId", "must be positive"));
        }
        self.require_initialized()?;
        self.engine
            .clear_effect(params.profile_id)
            .map_err(core_error)?;
        Ok(Empty {})
    }

    pub(super) async fn validate_proxies(
        &self,
        params: ValidateProxiesParams,
    ) -> Result<IssueList, ApiError> {
        let proxies = mappings(params.proxies, "proxies")?;
        Ok(issues(ops::validate_proxies(&proxies)))
    }

    pub(super) async fn validate_filters(
        &self,
        params: ValidateFiltersParams,
    ) -> Result<IssueList, ApiError> {
        Ok(issues(ops::validate_filters(&params.filters)))
    }

    pub(super) async fn convert_subscription(
        &self,
        params: ConvertSubscriptionParams,
    ) -> Result<ProxyList, ApiError> {
        let proxies = ops::convert_proxies(params.profile.path)
            .await
            .map_err(data_error)?;
        Ok(ProxyList {
            proxies: proxies.into_iter().map(Value::Object).collect(),
        })
    }

    pub(super) async fn convert_encode_links(
        &self,
        params: EncodeLinksParams,
    ) -> Result<LinkList, ApiError> {
        let proxies = mappings(params.proxies, "proxies")?;
        Ok(LinkList {
            links: ops::encode_share_links(&proxies),
        })
    }

    pub(super) async fn convert_decode_links(
        &self,
        params: DecodeLinksParams,
    ) -> Result<DecodedLinks, ApiError> {
        Ok(DecodedLinks {
            results: ops::decode_share_links(&params.lines)
                .into_iter()
                .map(|line| line.into_iter().map(Value::Object).collect())
                .collect(),
        })
    }
}
