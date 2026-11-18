#[cfg(unix)]
use concord_engine::InheritedTun;
use concord_engine::TunStartError;
use concord_proto::ApiError;
use concord_proto::types::*;

use super::{Control, core_error};

fn tun_error(error: TunStartError) -> ApiError {
    match error {
        TunStartError::Unavailable(message) => ApiError::unavailable("tun", message),
        TunStartError::Failed(failure) => core_error(failure),
        #[cfg(unix)]
        TunStartError::Request(_) | TunStartError::Start(_) => {
            ApiError::unavailable("tun", error.to_string())
        }
    }
}

impl Control {
    pub(super) async fn tun_start(&self, params: TunStartParams) -> Result<Empty, ApiError> {
        self.require_initialized()?;
        match params.source {
            TunSource::Device { name } => {
                if !self.engine.named_tun_supported() {
                    return Err(ApiError::unsupported_capability(
                        "tun.device",
                        "this platform hands the core a descriptor instead",
                    ));
                }
                self.require_configured()?;
                self.engine
                    .start_named_tun(name, params.stack)
                    .await
                    .map_err(tun_error)?;
            }
            TunSource::Inherited { handle } => {
                #[cfg(unix)]
                {
                    let fd = self
                        .fds
                        .take(handle)
                        .ok_or_else(|| ApiError::not_found("handle", handle.to_string()))?;
                    self.engine
                        .start_inherited_tun(
                            fd,
                            InheritedTun {
                                mtu: params.mtu,
                                address: params.address,
                                dns: params.dns,
                                congestion_controller: params.congestion_controller,
                            },
                        )
                        .await
                        .map_err(tun_error)?;
                }
                #[cfg(not(unix))]
                {
                    let _ = handle;
                    return Err(ApiError::unsupported_capability(
                        "tun.inherited",
                        "this platform has no descriptors to inherit",
                    ));
                }
            }
        }
        self.refresh();
        Ok(Empty {})
    }

    pub(super) async fn tun_stop(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.require_initialized()?;
        if self.engine.is_android() {
            #[cfg(unix)]
            self.engine.stop_vpn_tun().await;
        } else {
            self.require_configured()?;
            self.engine.disable_tun().await.map_err(core_error)?;
        }
        self.refresh();
        Ok(Empty {})
    }
}
