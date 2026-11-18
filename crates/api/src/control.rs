use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use concord_common::sync::lock;
use concord_engine::{ControllerCors, Engine, Failure};
use concord_proto::ApiError;
use concord_proto::types::*;
use tokio::sync::{Mutex as AsyncMutex, watch};

use crate::bus::EventBus;
use crate::convert::{self, Blame, api_error};
use crate::service::ServiceInfo;
use crate::stream::Subscription;

#[cfg(unix)]
use crate::fds::AdoptedFds;

mod config;
mod lifecycle;
mod mitm;
mod network;
mod profile;
mod provider;
mod proxy;
mod tun;

pub use config::Reload;
pub use proxy::valid_status_ranges;

/// What the process that embeds the core knows and the core cannot find out.
#[derive(Clone, Debug, Default)]
pub struct ControlOptions {
    pub privileged: bool,
    /// What the host lets the core do, such as `tun.inherited`.
    pub capabilities: Vec<String>,
    pub build: String,
    /// The core runs on its own, so the profile's `external-controller` and
    /// `secret` count; otherwise only `config.patch` sets them.
    pub profile_controller: bool,
}

/// Where the external controller listens; an empty address opens nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControllerSettings {
    pub address: String,
    pub secret: String,
    pub cors: ControllerCors,
}

pub struct Control {
    engine: Arc<Engine>,
    bus: Arc<EventBus>,
    options: ControlOptions,
    status: watch::Sender<EngineStatus>,
    configured: AtomicBool,
    failed: Mutex<Option<String>>,
    controller: watch::Sender<ControllerSettings>,
    profile_source: Mutex<Option<PathBuf>>,
    /// One reload at a time, as they share the staged file.
    reloading: AsyncMutex<()>,
    #[cfg(unix)]
    fds: AdoptedFds,
}

fn data_error(failure: Failure) -> ApiError {
    api_error(failure, Blame::Data)
}

fn core_error(failure: Failure) -> ApiError {
    api_error(failure, Blame::Core)
}

impl Control {
    /// `engine` must have been built with `bus` as its sink.
    pub fn new(engine: Arc<Engine>, bus: Arc<EventBus>, options: ControlOptions) -> Arc<Self> {
        bus.attach(&engine);
        engine.set_profile_controller(options.profile_controller);
        let (status, _) = watch::channel(EngineStatus {
            state: EngineState::Created,
            kind: None,
            faults: Vec::new(),
        });
        Arc::new(Control {
            engine,
            bus,
            options,
            status,
            configured: AtomicBool::new(false),
            failed: Mutex::new(None),
            controller: watch::Sender::new(ControllerSettings::default()),
            profile_source: Mutex::new(None),
            reloading: AsyncMutex::new(()),
            #[cfg(unix)]
            fds: AdoptedFds::default(),
        })
    }

    pub fn external_controller(&self) -> watch::Receiver<ControllerSettings> {
        self.controller.subscribe()
    }

    /// A host owns the profile, the selections and TUN; a dashboard may change
    /// what it can sync back, and the host learns of it from `events.watch`.
    pub fn host_owned(&self) -> bool {
        !self.options.profile_controller
    }

    fn set_external_controller(&self, next: ControllerSettings) {
        self.controller.send_if_modified(|current| {
            if *current == next {
                return false;
            }
            *current = next;
            true
        });
    }

    /// Takes the controller from the profile in force. A core running on its own
    /// calls this when it loads its profile, not on a dashboard's reload, as
    /// mihomo recreates the controller only when it parses its config.
    pub async fn adopt_profile_controller(&self) {
        if self.host_owned() {
            return;
        }
        let (address, secret, cors) = self.engine.profile_controller().await;
        self.set_external_controller(ControllerSettings {
            address,
            secret,
            cors,
        });
    }
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    pub fn bus(&self) -> &Arc<EventBus> {
        &self.bus
    }

    #[cfg(unix)]
    pub fn adopted_fds(&self) -> &AdoptedFds {
        &self.fds
    }

    pub async fn shutdown(&self) {
        self.engine.shutdown().await;
        self.configured.store(false, Ordering::SeqCst);
        self.refresh();
    }
    fn state(&self) -> EngineStatus {
        let failed = lock(&self.failed).clone();
        let state = if failed.is_some() {
            EngineState::Failed
        } else if self.engine.is_running() {
            EngineState::Running
        } else if self.configured.load(Ordering::SeqCst) {
            EngineState::Configured
        } else if self.engine.is_initialized() {
            EngineState::Initialized
        } else {
            EngineState::Created
        };
        EngineStatus {
            state,
            kind: failed,
            faults: self
                .engine
                .faults()
                .into_iter()
                .map(convert::fault)
                .collect(),
        }
    }

    /// For hosts that change the engine behind the protocol's back, such as a VPN service.
    pub fn refresh_state(&self) {
        self.refresh();
    }

    fn refresh(&self) {
        let next = self.state();
        self.status.send_if_modified(|current| {
            if *current == next {
                return false;
            }
            *current = next;
            true
        });
    }

    fn fail(&self, error: &ApiError) {
        {
            let mut failed = lock(&self.failed);
            *failed = Some(error.data.kind().to_string());
        }
        self.refresh();
    }

    fn clear_failure(&self) {
        {
            let mut failed = lock(&self.failed);
            *failed = None;
        }
    }

    fn require_initialized(&self) -> Result<(), ApiError> {
        if self.engine.is_initialized() {
            Ok(())
        } else {
            Err(ApiError::conflict("created", "core.init has not run"))
        }
    }

    fn require_configured(&self) -> Result<(), ApiError> {
        self.require_initialized()?;
        if self.configured.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ApiError::conflict(
                "initialized",
                "config.apply has not run",
            ))
        }
    }

    fn output_error(err: &std::io::Error) -> ApiError {
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            ApiError::invalid_field("output.file", err.to_string())
        } else {
            ApiError::internal(err.to_string())
        }
    }

    fn write_output(&self, file: &str, bytes: &[u8]) -> Result<u64, ApiError> {
        self.require_initialized()?;
        let home = self
            .engine
            .home()
            .ok_or_else(|| ApiError::conflict("created", "core.init has not run"))?;
        home.write_atomic(file, bytes)
            .map_err(|err| Self::output_error(&err))?;
        Ok(bytes.len() as u64)
    }

    fn text_result(&self, output: Output, text: String) -> Result<TextResult, ApiError> {
        match output {
            Output::Inline { .. } => Ok(TextResult {
                text: Some(text),
                file: None,
                size: None,
            }),
            Output::File { file } => {
                let size = self.write_output(&file, text.as_bytes())?;
                Ok(TextResult {
                    text: None,
                    file: Some(file),
                    size: Some(size),
                })
            }
        }
    }
}

macro_rules! method {
    ($mode:ident, rpc, $fun:ident, $params:ty, $result:ty, $event:ty) => {};
    ($mode:ident, unary, debug_crash, $params:ty, $result:ty, $event:ty) => {
        #[cfg(feature = "debug")]
        $mode!(debug_crash, $params, $result);
    };
    ($mode:ident, unary, $fun:ident, $params:ty, $result:ty, $event:ty) => {
        $mode!($fun, $params, $result);
    };
    ($mode:ident, stream, $fun:ident, $params:ty, $result:ty, $event:ty) => {
        $mode!($fun, $params, Subscription<$result, $event>);
    };
}

macro_rules! call_handler {
    ($fun:ident, $params:ty, $output:ty) => {
        pub(super) fn $fun(
            control: &Control,
            params: $params,
        ) -> impl Future<Output = Result<$output, ApiError>> + Send {
            control.$fun(params)
        }
    };
}

macro_rules! forward {
    ($fun:ident, $params:ty, $output:ty) => {
        fn $fun(&self, params: $params) -> impl Future<Output = Result<$output, ApiError>> + Send {
            handlers::$fun(self, params)
        }
    };
}

/// Every method of the registry forwards to the handler of the same name in a child module.
/// The handler is called from `handlers`, where `ControlService` is not in scope: inside the
/// impl a missing handler would resolve to the trait method itself.
macro_rules! control_service {
    ($({ kind: $kind:ident, fun: $fun:ident, name: $name:literal, exec: $exec:ident, params: $params:ty, result: $result:ty, event: $event:ty, policy: $policy:ident, cap: $cap:ident })*) => {
        mod handlers {
            use std::future::Future;

            use concord_proto::ApiError;

            use super::Control;
            use crate::stream::Subscription;

            $( method!(call_handler, $kind, $fun, $params, $result, $event); )*
        }

        impl crate::service::ControlService for Control {
            fn info(&self) -> ServiceInfo {
                Control::info(self)
            }

            $( method!(forward, $kind, $fun, $params, $result, $event); )*
        }
    };
}

concord_proto::with_methods!(control_service);
