use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use concord_common::sync::lock;
use concord_common::{CoreOptions, Origin};
use concord_engine::{
    ControllerCors, SetupRequest, TunPatch as EngineTunPatch, UpdateRequest, ops,
};
use concord_proto::types::*;
use concord_proto::{ApiError, ErrorData};
use serde_json::Value;

use super::{Control, core_error, data_error};
use crate::convert;

/// The working profile an apply without a `profile` reads.
const CONFIG_FILE: &str = "config.yaml";
const STAGED_FILE: &str = "config.reload.yaml";

/// What `reload_profile_as` reads.
pub enum Reload {
    Text(String),
    Path(String),
    /// The file the core was started with, or the working profile.
    Started,
}

fn core_options(options: Options) -> CoreOptions {
    CoreOptions {
        test_url: options.test_url,
        skip_cert_verify: options.skip_cert_verify,
        delay_test_timeout: options.delay_test_timeout,
        mitm_capture: options.mitm_capture,
    }
}

impl Control {
    /// The picks in force, which a reload of the profile carries over as
    /// mihomo's cache file does.
    pub fn selections(&self) -> BTreeMap<String, String> {
        self.engine.selections()
    }

    /// The file a core running on its own was started with, which a reload
    /// that names no profile reads again, as mihomo's does.
    pub fn set_profile_source(&self, path: PathBuf) {
        *lock(&self.profile_source) = Some(path);
    }

    /// mihomo's `PUT /configs` for a core running on its own: the profile
    /// replaces the working `config.yaml` whole, after it validates, and is
    /// applied as `concord run` applies it. A path must be absolute and inside
    /// the home directory, as mihomo's safe paths are by default.
    pub async fn reload_profile_as(
        &self,
        origin: Origin,
        reload: Reload,
    ) -> Result<ConfigApplyResult, ApiError> {
        self.require_initialized()?;
        if self.host_owned() {
            return Err(ApiError::unsupported_capability(
                "profile_reload",
                "the host owns the profile",
            ));
        }
        let _reloading = self.reloading.lock().await;
        let home = self
            .engine
            .home()
            .ok_or_else(|| ApiError::internal("not initialized"))?;
        let started = lock(&self.profile_source).clone();
        let working = home.join(CONFIG_FILE);
        let staged = home.join(STAGED_FILE);
        let (read_home, write_to) = (home.clone(), staged.clone());
        let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, ApiError> {
            let bytes = match reload {
                Reload::Text(text) => text.into_bytes(),
                Reload::Path(path) => {
                    if !Path::new(&path).is_absolute() {
                        return Err(ApiError::invalid_field(
                            "path",
                            "path is not a absolute path",
                        ));
                    }
                    read_home
                        .read(&path)
                        .map_err(|err| ApiError::invalid_field("path", format!("{path}: {err}")))?
                }
                Reload::Started => std::fs::read(started.as_deref().unwrap_or(&working))
                    .map_err(|err| ApiError::internal(err.to_string()))?,
            };
            read_home
                .write_atomic(&write_to, &bytes)
                .map_err(|err| ApiError::internal(err.to_string()))?;
            Ok(bytes)
        })
        .await
        .map_err(|err| ApiError::internal(err.to_string()))??;
        let validated = self
            .config_validate(ConfigValidateParams {
                profile: ProfileRef {
                    path: staged.to_string_lossy().into_owned(),
                },
            })
            .await;
        let _ = tokio::fs::remove_file(&staged).await;
        if let Some(issue) = validated?.issues.into_iter().next() {
            return Err(ApiError::invalid_field("profile", issue.message));
        }
        home.write_atomic(home.join(CONFIG_FILE), &bytes)
            .map_err(|err| ApiError::internal(err.to_string()))?;
        let params = ConfigApplyParams {
            selection: self.selections(),
            ..ConfigApplyParams::default()
        };
        self.config_apply_as(origin, params).await
    }

    pub async fn config_apply_as(
        &self,
        origin: Origin,
        params: ConfigApplyParams,
    ) -> Result<ConfigApplyResult, ApiError> {
        self.require_initialized()?;
        let _answering = self.engine.hold_first_loads();
        let base = match (params.profile, params.overlay) {
            (Some(profile), overlay) => Some((
                profile.path,
                overlay
                    .map(|overlay| overlay.to_string())
                    .unwrap_or_default(),
            )),
            (None, Some(_)) => {
                return Err(ApiError::invalid_field(
                    "overlay",
                    "an overlay needs the profile it is applied to",
                ));
            }
            (None, None) => None,
        };
        let applied = self
            .engine
            .setup_as(
                origin,
                SetupRequest {
                    base,
                    selected: params.selection,
                    options: core_options(params.options),
                },
            )
            .await;
        if let Some(level) = self.engine.log_level().await {
            self.bus.gate().set_level(level);
        }
        match applied {
            Ok(()) => {
                self.configured.store(true, Ordering::SeqCst);
                self.clear_failure();
                self.refresh();
                Ok(ConfigApplyResult {
                    warnings: self
                        .engine
                        .warnings()
                        .into_iter()
                        .map(convert::warning)
                        .collect(),
                })
            }
            Err(failure) => {
                let error = core_error(failure);
                if matches!(error.data, ErrorData::Rejected { .. }) {
                    self.configured.store(true, Ordering::SeqCst);
                    self.clear_failure();
                    self.refresh();
                } else {
                    self.fail(&error);
                }
                Err(error)
            }
        }
    }

    pub async fn config_patch_as(
        &self,
        origin: Origin,
        params: ConfigPatchParams,
    ) -> Result<ChangeSeq, ApiError> {
        self.require_configured()?;
        if let Some(level) = params.log_level {
            self.bus.gate().set_level(convert::engine_level(level));
        }
        let request = UpdateRequest {
            tun: params.tun.map(|tun| EngineTunPatch {
                enable: tun.enable,
                device: tun.device,
                stack: tun.stack,
                auto_route: tun.auto_route,
            }),
            allow_lan: params.allow_lan,
            bind_address: params.bind_address,
            lan_allowed_ips: params.lan_allowed_ips,
            lan_disallowed_ips: params.lan_disallowed_ips,
            mixed_port: params.mixed_port,
            find_process_mode: params.find_process_mode,
            mode: params.mode,
            log_level: params
                .log_level
                .map(|level| convert::engine_level(level).as_str().to_string()),
            ipv6: params.ipv6,
            tcp_concurrent: params.tcp_concurrent,
            unified_delay: params.unified_delay,
            authentication: params.authentication,
            geo_auto_update: params.geo_auto_update,
            geo_update_interval: params.geo_update_interval,
            geox_url: params.geox_url,
            options: params.options.map(core_options),
        };
        let updated = self
            .engine
            .update_as(origin, request)
            .await
            .map_err(core_error);
        self.refresh();
        updated.map(|seq| ChangeSeq { seq })
    }

    pub(super) async fn config_apply(
        &self,
        params: ConfigApplyParams,
    ) -> Result<ConfigApplyResult, ApiError> {
        self.config_apply_as(Origin::Host, params).await
    }

    pub(super) async fn config_patch(
        &self,
        params: ConfigPatchParams,
    ) -> Result<ChangeSeq, ApiError> {
        let (address, secret) = (params.external_controller.clone(), params.secret.clone());
        let cors = params.external_controller_cors.clone();
        let patched = self.config_patch_as(Origin::Host, params).await?;
        if self.host_owned() && (address.is_some() || secret.is_some() || cors.is_some()) {
            let mut next = self.controller.borrow().clone();
            if let Some(address) = address {
                next.address = address;
            }
            if let Some(secret) = secret {
                next.secret = secret;
            }
            if let Some(cors) = cors {
                next.cors =
                    ControllerCors::or_defaults(cors.allow_origins, cors.allow_private_network);
            }
            self.set_external_controller(next);
        }
        Ok(patched)
    }

    pub(super) async fn config_general(&self, _params: Empty) -> Result<GeneralState, ApiError> {
        self.require_configured()?;
        self.engine
            .general()
            .await
            .map(convert::general_state)
            .ok_or_else(|| ApiError::conflict("initialized", "config.apply has not run"))
    }

    pub(super) async fn config_validate(
        &self,
        params: ConfigValidateParams,
    ) -> Result<ConfigValidateResult, ApiError> {
        let message = ops::validate_config(params.profile.path)
            .await
            .map_err(data_error)?;
        Ok(ConfigValidateResult {
            issues: message.into_iter().map(Issue::message).collect(),
        })
    }

    pub(super) async fn config_decrypt(
        &self,
        params: ConfigDecryptParams,
    ) -> Result<TextResult, ApiError> {
        let text = ops::decrypt_config(params.profile.path, params.key)
            .await
            .map_err(data_error)?;
        self.text_result(params.output, text)
    }

    pub(super) async fn config_read(
        &self,
        params: ConfigReadParams,
    ) -> Result<ConfigReadResult, ApiError> {
        let mut config = ops::read_config(params.profile.path)
            .await
            .map_err(data_error)?;
        if let Value::Object(map) = &mut config
            && let Some(rules) = map.remove("rule")
        {
            map.insert("rules".to_string(), rules);
        }
        match params.output {
            Output::Inline { .. } => Ok(ConfigReadResult {
                config: Some(config),
                file: None,
                size: None,
            }),
            Output::File { file } => {
                let bytes = serde_json::to_vec(&config)
                    .map_err(|err| ApiError::internal(err.to_string()))?;
                let size = self.write_output(&file, &bytes)?;
                Ok(ConfigReadResult {
                    config: None,
                    file: Some(file),
                    size: Some(size),
                })
            }
        }
    }
}
