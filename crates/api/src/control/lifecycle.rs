use concord_proto::ApiError;
use concord_proto::types::*;

use super::{Control, core_error};
use crate::convert;
use crate::service::ServiceInfo;
use crate::stream::Subscription;
use crate::watch as streams;

impl Control {
    pub(super) fn info(&self) -> ServiceInfo {
        let capabilities = self.engine.capabilities();
        ServiceInfo {
            server: ServerInfo {
                implementation: concord_common::CORE_NAME.to_string(),
                version: capabilities.version.to_string(),
                build: self.options.build.clone(),
            },
            platform: PlatformInfo {
                os: if self.engine.is_android() {
                    "android".to_string()
                } else {
                    std::env::consts::OS.to_string()
                },
                privileged: self.options.privileged,
                capabilities: self.options.capabilities.clone(),
            },
            features: Features {
                mitm: capabilities.features.mitm,
                ech: capabilities.features.ech,
                system_stack: capabilities.features.system_stack,
            },
            engine: self.state(),
            debug: cfg!(feature = "debug"),
        }
    }

    pub(super) async fn core_init(&self, params: CoreInitParams) -> Result<Empty, ApiError> {
        if params.home.is_empty() {
            return Err(ApiError::invalid_field("home", "home must not be empty"));
        }
        let outcome = self
            .engine
            .init(&params.home, params.sdk_int.unwrap_or(0))
            .map_err(core_error);
        match outcome {
            Ok(()) => {
                self.clear_failure();
                self.refresh();
                Ok(Empty {})
            }
            Err(error) => {
                self.fail(&error);
                Err(error)
            }
        }
    }

    pub(super) async fn core_release_memory(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.release_memory();
        Ok(Empty {})
    }

    pub(super) async fn core_stats(&self, _params: Empty) -> Result<CoreStats, ApiError> {
        Ok(CoreStats {
            rss: self.engine.memory_stats().rss,
        })
    }

    pub(super) async fn core_capabilities(&self, _params: Empty) -> Result<Capabilities, ApiError> {
        Ok(convert::capabilities(self.engine.capabilities()))
    }

    pub(super) async fn core_set_pressure(
        &self,
        params: SetPressureParams,
    ) -> Result<Empty, ApiError> {
        self.engine.mitm().set_pressure(params.level);
        Ok(Empty {})
    }

    pub(super) async fn core_last_warnings(&self, _params: Empty) -> Result<WarningList, ApiError> {
        Ok(WarningList {
            warnings: self
                .engine
                .warnings()
                .into_iter()
                .map(convert::warning)
                .collect(),
        })
    }

    #[cfg(feature = "debug")]
    pub(super) async fn debug_crash(&self, _params: Empty) -> Result<Empty, ApiError> {
        eprintln!("[ERROR] debug.crash");
        std::process::abort()
    }

    pub(super) async fn log_watch(
        &self,
        params: LogWatchParams,
    ) -> Result<Subscription<Empty, LogEntry>, ApiError> {
        let events = streams::map_stream(
            self.bus.watch_log(params.level.unwrap_or_default()),
            |entry| entry,
        );
        Ok(Subscription::new(None, events))
    }

    pub(super) async fn events_watch(
        &self,
        params: EventsWatchParams,
    ) -> Result<Subscription<Empty, concord_proto::types::CoreEvent>, ApiError> {
        let events = streams::map_stream(
            self.bus.watch_events(params.delays, params.state),
            |event| event,
        );
        Ok(Subscription::new(None, events))
    }

    pub(super) async fn engine_state(
        &self,
        _params: EngineStateParams,
    ) -> Result<Subscription<EngineStatus, EngineStatus>, ApiError> {
        Ok(streams::engine_state(self.status.subscribe()))
    }

    pub(super) async fn engine_start(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.require_initialized()?;
        self.engine.start_listeners().await;
        self.refresh();
        Ok(Empty {})
    }

    pub(super) async fn engine_stop(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.require_initialized()?;
        self.engine.stop_listeners().await;
        self.refresh();
        Ok(Empty {})
    }
}
