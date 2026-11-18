use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use arc_swap::ArcSwapOption;
use concord_config::MitmDef;
use concord_mitm::{
    CaError, EVENT_NETWORK_CHANGED, LocalClock, Mitm, MitmEnv, RawConfig as MitmConfig,
};
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use concord_tunnel::{ConnTable, Tunnel};
use serde_json::Value;

use super::NOT_INITIALIZED;
use crate::error::Failure;

/// The MITM engine and the host settings that outlive it.
pub struct MitmService {
    pressure: AtomicI32,
    capture: AtomicBool,
    current: ArcSwapOption<Mitm>,
    table: Arc<ConnTable>,
}

impl MitmService {
    pub(crate) const ENABLED: bool = true;

    pub(crate) fn new(table: Arc<ConnTable>) -> Self {
        MitmService {
            pressure: AtomicI32::new(0),
            capture: AtomicBool::new(false),
            current: ArcSwapOption::empty(),
            table,
        }
    }

    pub(crate) fn is_started(&self) -> bool {
        self.current.load().is_some()
    }

    pub(crate) fn start(&self, home: &Arc<HomeDir>, tunnel: &Tunnel, running: bool) {
        let mitm = Arc::new(Mitm::new(MitmEnv {
            home: home.clone(),
            trust: TrustStore::from_parts(Vec::new(), &[], Vec::new()),
            dialer: tunnel.upstream_dialer(),
            clock: Arc::new(DeviceClock),
            runtime: None,
        }));
        mitm.set_capture(self.capture.load(Ordering::Relaxed));
        mitm.set_pressure(u8::try_from(self.pressure()).unwrap_or(0));
        mitm.set_running(running);
        tunnel.set_interceptor(mitm.interceptor());
        if let Some(previous) = self.current.swap(Some(mitm)) {
            previous.apply(None);
        }
    }

    fn started(&self) -> Result<Arc<Mitm>, Failure> {
        self.current
            .load_full()
            .ok_or_else(|| Failure::core(NOT_INITIALIZED))
    }

    pub fn certificate(&self) -> Result<Option<Value>, Failure> {
        let certificate = self.started()?.certificate().map_err(ca_failure)?;
        Ok(certificate.map(|info| serde_json::to_value(info).unwrap_or(Value::Null)))
    }

    pub fn generate_certificate(&self) -> Result<Value, Failure> {
        let info = self.started()?.generate_certificate().map_err(ca_failure)?;
        Ok(serde_json::to_value(info).unwrap_or(Value::Null))
    }

    pub fn issue_certificate(&self, host: &str) -> Result<String, Failure> {
        if host.is_empty() {
            return Err(Failure::new("invalid_arguments", "missing host"));
        }
        self.started()?.issue_certificate(host).map_err(ca_failure)
    }

    pub fn validate(&self, raw: Value) -> Result<Value, Failure> {
        let raw: MitmConfig = serde_json::from_value(raw)
            .map_err(|err| Failure::new("invalid_arguments", err.to_string()))?;
        let validation = self.started()?.validate(&raw);
        Ok(serde_json::to_value(validation).unwrap_or(Value::Null))
    }

    pub async fn run_script(&self, name: &str) -> Result<Value, Failure> {
        let output = self
            .started()?
            .run_script(name)
            .await
            .map_err(|err| Failure::core(err.to_string()))?;
        Ok(serde_json::to_value(output).unwrap_or(Value::Null))
    }

    /// Closed is read first, so a closed connection's list already holds every request
    /// it carried.
    pub fn exchanges(&self, id: &str) -> Result<Value, Failure> {
        let closed = !self.table.is_open(id);
        let list = self.started()?.exchanges(id);
        let mut value = serde_json::to_value(list).unwrap_or(Value::Null);
        if let Value::Object(map) = &mut value {
            map.insert("closed".into(), Value::Bool(closed));
        }
        Ok(value)
    }

    pub fn exchange(&self, id: i64) -> Result<Value, Failure> {
        let exchange = self.started()?.exchange(id);
        Ok(serde_json::to_value(exchange).unwrap_or(Value::Null))
    }

    pub fn body(&self, id: i64, response: bool) -> Result<Value, Failure> {
        let body = self.started()?.body(id, response);
        Ok(serde_json::to_value(body).unwrap_or(Value::Null))
    }

    /// `tunnel.UpdateMITM`. The section outlives a rejected config only as "off".
    pub(crate) fn apply(&self, section: &MitmDef, trust: Arc<TrustStore>) {
        let Some(mitm) = self.current.load_full() else {
            return;
        };
        mitm.set_trust(trust);
        for line in mitm.apply_section(Some(section.clone())) {
            tracing::warn!("[MITM] {line}");
        }
        self.table.set_closed_capacity(mitm.capture_entries());
    }

    /// `setMITMRunning`, on every start and stop: scripts run only while started.
    pub(crate) fn set_running(&self, running: bool) {
        if let Some(mitm) = self.current.load_full() {
            mitm.set_running(running);
        }
    }

    /// `mitm.SetPressure`: 0 (none) to 3 (relay), set by the Android service under memory pressure.
    pub fn set_pressure(&self, level: i32) {
        let level = level.clamp(0, 3);
        self.pressure.store(level, Ordering::Relaxed);
        if let Some(mitm) = self.current.load_full() {
            mitm.set_pressure(u8::try_from(level).unwrap_or(0));
        }
    }

    pub fn pressure(&self) -> i32 {
        self.pressure.load(Ordering::Relaxed)
    }

    pub(crate) fn set_capture(&self, on: bool) {
        self.capture.store(on, Ordering::Relaxed);
        if let Some(mitm) = self.current.load_full() {
            mitm.set_capture(on);
        }
    }

    pub(crate) fn network_changed(&self) {
        if let Some(mitm) = self.current.load_full() {
            mitm.notify(EVENT_NETWORK_CHANGED);
        }
    }

    pub(crate) fn shutdown(&self) {
        if let Some(mitm) = self.current.load_full() {
            mitm.apply(None);
            mitm.flush_scripts();
        }
    }
}

struct DeviceClock;

impl LocalClock for DeviceClock {
    fn offset_at(&self, unix: i64) -> i32 {
        concord_platform::local_utc_offset(unix)
    }
}

fn ca_failure(err: CaError) -> Failure {
    Failure::core(err.to_string())
}
