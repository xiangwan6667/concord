use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use concord_platform::HomeDir;
use concord_tls::TrustStore;
use concord_tunnel::{ConnTable, Tunnel};
use serde_json::Value;

use crate::error::Failure;

/// Stands in for the MITM engine in a build without the `mitm` feature. The API
/// refuses MITM methods before reaching it, because `core.hello` reports no `mitm`.
pub struct MitmService {
    pressure: AtomicI32,
}

impl MitmService {
    pub(crate) const ENABLED: bool = false;

    pub(crate) fn new(_table: Arc<ConnTable>) -> Self {
        MitmService {
            pressure: AtomicI32::new(0),
        }
    }

    pub(crate) fn is_started(&self) -> bool {
        false
    }

    pub(crate) fn start(&self, _home: &Arc<HomeDir>, _tunnel: &Tunnel, _running: bool) {}

    pub fn certificate(&self) -> Result<Option<Value>, Failure> {
        Err(unavailable())
    }

    pub fn generate_certificate(&self) -> Result<Value, Failure> {
        Err(unavailable())
    }

    pub fn issue_certificate(&self, _host: &str) -> Result<String, Failure> {
        Err(unavailable())
    }

    pub fn validate(&self, _raw: Value) -> Result<Value, Failure> {
        Err(unavailable())
    }

    pub async fn run_script(&self, _name: &str) -> Result<Value, Failure> {
        Err(unavailable())
    }

    pub fn exchanges(&self, _id: &str) -> Result<Value, Failure> {
        Err(unavailable())
    }

    pub fn exchange(&self, _id: i64) -> Result<Value, Failure> {
        Err(unavailable())
    }

    pub fn body(&self, _id: i64, _response: bool) -> Result<Value, Failure> {
        Err(unavailable())
    }

    pub(crate) fn apply(&self, section: &concord_config::MitmDef, _trust: Arc<TrustStore>) {
        if section.enable {
            tracing::warn!("[MITM] this build has no MITM; the section is ignored");
        }
    }

    pub(crate) fn set_running(&self, _running: bool) {}

    pub fn set_pressure(&self, level: i32) {
        self.pressure.store(level.clamp(0, 3), Ordering::Relaxed);
    }

    pub fn pressure(&self) -> i32 {
        self.pressure.load(Ordering::Relaxed)
    }

    pub(crate) fn set_capture(&self, _on: bool) {}

    pub(crate) fn network_changed(&self) {}

    pub(crate) fn shutdown(&self) {}
}

fn unavailable() -> Failure {
    Failure::core("this build has no MITM")
}
