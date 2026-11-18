use concord_engine::ops;
use concord_proto::ApiError;
use concord_proto::types::*;

use super::{Control, core_error, data_error};
use crate::convert;

impl Control {
    pub(super) async fn provider_list(&self, _params: Empty) -> Result<ProviderList, ApiError> {
        Ok(ProviderList {
            providers: self
                .engine
                .providers()
                .list()
                .into_iter()
                .map(convert::provider_info)
                .collect(),
        })
    }

    pub(super) async fn provider_get(
        &self,
        params: ProviderNameParams,
    ) -> Result<ProviderInfo, ApiError> {
        self.engine
            .providers()
            .get(&params.name)
            .map(convert::provider_info)
            .ok_or_else(|| ApiError::not_found("provider", params.name))
    }

    pub(super) async fn provider_update(
        &self,
        params: ProviderNameParams,
    ) -> Result<Empty, ApiError> {
        self.engine
            .providers()
            .update(&params.name)
            .await
            .map_err(core_error)?;
        Ok(Empty {})
    }

    pub(super) async fn provider_side_load(
        &self,
        params: ProviderSideLoadParams,
    ) -> Result<Empty, ApiError> {
        self.engine
            .providers()
            .side_load(&params.name, params.data)
            .await
            .map_err(core_error)?;
        Ok(Empty {})
    }

    pub(super) async fn provider_health_check(
        &self,
        params: ProviderNameParams,
    ) -> Result<Empty, ApiError> {
        self.engine
            .providers()
            .health_check(&params.name)
            .await
            .map_err(core_error)?;
        Ok(Empty {})
    }

    pub(super) async fn rule_list(&self, _params: Empty) -> Result<RuleList, ApiError> {
        Ok(RuleList {
            rules: self
                .engine
                .rules()
                .into_iter()
                .map(|rule| RuleEntry {
                    kind: rule.kind,
                    payload: rule.payload,
                    target: rule.target,
                })
                .collect(),
        })
    }

    pub(super) async fn rule_set_dump(
        &self,
        params: RuleSetDumpParams,
    ) -> Result<TextResult, ApiError> {
        let text = ops::dump_rule_set(params.profile.path)
            .await
            .map_err(data_error)?;
        self.text_result(params.output, text)
    }

    pub(super) async fn rule_set_compile(
        &self,
        params: RuleSetCompileParams,
    ) -> Result<RuleSetInfo, ApiError> {
        self.require_initialized()?;
        let info = self
            .engine
            .compile_rule_set(&params.name, &params.url.unwrap_or_default())
            .await
            .map_err(core_error)?;
        Ok(RuleSetInfo {
            behavior: info.behavior.to_string(),
            format: info.format.to_string(),
        })
    }

    pub(super) async fn geo_update(&self, params: GeoUpdateParams) -> Result<Empty, ApiError> {
        self.engine.geo_update(&params.kind).map_err(|failure| {
            if failure
                .message
                .starts_with("geo update already in progress")
            {
                ApiError::conflict("updating", failure.message)
            } else {
                ApiError::invalid_field("type", failure.message)
            }
        })?;
        Ok(Empty {})
    }
}
