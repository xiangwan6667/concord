use concord_engine::{Engine, Failure};
use concord_proto::ApiError;
use concord_proto::types::*;

use super::{Control, core_error};

impl Control {
    fn mitm_enabled(&self) -> Result<(), ApiError> {
        if self.engine.capabilities().features.mitm {
            Ok(())
        } else {
            Err(ApiError::unsupported_capability(
                "mitm",
                "this build has no MITM",
            ))
        }
    }

    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Engine) -> Result<T, Failure> + Send + 'static,
    ) -> Result<T, ApiError> {
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || work(&engine))
            .await
            .map_err(|err| ApiError::internal(err.to_string()))?
            .map_err(core_error)
    }

    pub(super) async fn mitm_certificate(
        &self,
        _params: Empty,
    ) -> Result<MitmCertificate, ApiError> {
        self.mitm_enabled()?;
        let certificate = self.blocking(|engine| engine.mitm().certificate()).await?;
        Ok(MitmCertificate { certificate })
    }

    pub(super) async fn mitm_generate_certificate(
        &self,
        _params: Empty,
    ) -> Result<MitmCertificate, ApiError> {
        self.mitm_enabled()?;
        let certificate = self
            .blocking(|engine| engine.mitm().generate_certificate())
            .await?;
        Ok(MitmCertificate {
            certificate: Some(certificate),
        })
    }

    pub(super) async fn mitm_validate(
        &self,
        params: MitmValidateParams,
    ) -> Result<MitmValidateResult, ApiError> {
        self.mitm_enabled()?;
        let validation = self
            .blocking(move |engine| engine.mitm().validate(params.config))
            .await?;
        serde_json::from_value(validation).map_err(|err| ApiError::internal(err.to_string()))
    }

    pub(super) async fn mitm_issue_certificate(
        &self,
        params: MitmIssueParams,
    ) -> Result<MitmPem, ApiError> {
        self.mitm_enabled()?;
        if params.host.is_empty() {
            return Err(ApiError::invalid_field("host", "host must not be empty"));
        }
        let pem = self
            .blocking(move |engine| engine.mitm().issue_certificate(&params.host))
            .await?;
        Ok(MitmPem { pem })
    }

    pub(super) async fn mitm_run_script(
        &self,
        params: MitmScriptParams,
    ) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let result = self
            .engine
            .mitm()
            .run_script(&params.name)
            .await
            .map_err(core_error)?;
        Ok(MitmResult { result })
    }

    pub(super) async fn mitm_exchanges(
        &self,
        params: MitmExchangesParams,
    ) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let id = self
            .engine
            .connection_id(params.connection)
            .ok_or_else(|| ApiError::not_found("connection", params.connection.to_string()))?;
        let result = self.engine.mitm().exchanges(&id).map_err(core_error)?;
        Ok(MitmResult { result })
    }

    pub(super) async fn mitm_exchange(
        &self,
        params: MitmExchangeParams,
    ) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let result = self.engine.mitm().exchange(params.id).map_err(core_error)?;
        Ok(MitmResult { result })
    }

    pub(super) async fn mitm_body(&self, params: MitmBodyParams) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let result = self
            .engine
            .mitm()
            .body(params.id, params.response)
            .map_err(core_error)?;
        Ok(MitmResult { result })
    }
}
