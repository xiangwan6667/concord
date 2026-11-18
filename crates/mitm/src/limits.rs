use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use concord_common::sync::lock;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const DEFAULT_MAX_BODY_SIZE: i64 = 4 << 20;
const DEFAULT_BODY_BUFFER: i64 = 32 << 20;
pub(crate) const DEFAULT_CERTIFICATE_CACHE: i64 = 1024;
const DEFAULT_SCRIPT_CONCURRENCY: i64 = 4;
const DEFAULT_SCRIPT_MEMORY: i64 = 256 << 20;
pub(crate) const DEFAULT_CAPTURE_ENTRIES: i64 = 2000;
pub(crate) const DEFAULT_CAPTURE_BYTES: i64 = 64 << 20;

const PRESSURE_HOLD: Duration = Duration::from_secs(60);

pub(crate) const BODY_WAIT: Duration = Duration::from_secs(5);

pub use concord_config::mitm::MitmLimits as RawLimits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_body_size: i64,
    pub body_buffer: i64,
    pub certificate_cache: usize,
    pub max_sessions: usize,
    pub script_concurrency: usize,
    pub script_memory: u64,
    pub capture_entries: usize,
    pub capture_bytes: i64,
}

/// The limits in force for those written, each default standing in for one left out.
pub trait Resolve {
    fn resolve(self) -> Limits;
}

impl Resolve for RawLimits {
    fn resolve(self) -> Limits {
        let positive = |value: i64, default: i64| if value <= 0 { default } else { value };
        let max_body_size = positive(self.max_body_size, DEFAULT_MAX_BODY_SIZE);
        let body_buffer = positive(self.body_buffer, DEFAULT_BODY_BUFFER).max(max_body_size);
        Limits {
            max_body_size,
            body_buffer: body_buffer.min(i64::try_from(Semaphore::MAX_PERMITS).unwrap_or(i64::MAX)),
            certificate_cache: positive(self.certificate_cache, DEFAULT_CERTIFICATE_CACHE) as usize,
            max_sessions: self.max_sessions.max(0) as usize,
            script_concurrency: positive(self.script_concurrency, DEFAULT_SCRIPT_CONCURRENCY)
                as usize,
            script_memory: positive(self.script_memory, DEFAULT_SCRIPT_MEMORY) as u64,
            capture_entries: positive(self.capture_entries, DEFAULT_CAPTURE_ENTRIES) as usize,
            capture_bytes: positive(self.capture_bytes, DEFAULT_CAPTURE_BYTES),
        }
    }
}

pub const PRESSURE_NONE: u8 = 0;
pub const PRESSURE_NO_SCRIPTS: u8 = 1;
pub const PRESSURE_NO_BODIES: u8 = 2;
pub const PRESSURE_RELAY: u8 = 3;

/// Levels of memory pressure, each shedding what the one below still does. A
/// platform signals memory running short but seldom that it is back, so a level
/// holds this long after its last signal and then lifts.
pub struct Pressure {
    level: AtomicU8,
    until: Mutex<Option<Instant>>,
    hold: Duration,
}

impl Default for Pressure {
    fn default() -> Self {
        Pressure::with_hold(PRESSURE_HOLD)
    }
}

impl Pressure {
    pub fn with_hold(hold: Duration) -> Pressure {
        Pressure {
            level: AtomicU8::new(PRESSURE_NONE),
            until: Mutex::new(None),
            hold,
        }
    }

    pub fn set(&self, level: u8) -> bool {
        let level = level.min(PRESSURE_RELAY);
        let current = self.level();
        if level == PRESSURE_NONE || level < current {
            return false;
        }
        {
            let mut until = lock(&self.until);
            *until = Some(Instant::now() + self.hold);
        }
        if level > current {
            tracing::warn!("[MITM] memory is short, pressure level {level}");
            self.level.store(level, Ordering::Relaxed);
        }
        level >= PRESSURE_NO_BODIES && current < PRESSURE_NO_BODIES
    }

    pub fn level(&self) -> u8 {
        let level = self.level.load(Ordering::Relaxed);
        if level == PRESSURE_NONE {
            return level;
        }
        let expired = lock(&self.until).is_some_and(|at| Instant::now() >= at);
        if expired && self.level.swap(PRESSURE_NONE, Ordering::Relaxed) != PRESSURE_NONE {
            tracing::info!("[MITM] memory pressure eased");
            return PRESSURE_NONE;
        }
        level
    }
}

pub(crate) struct ScriptGate {
    slots: Arc<Semaphore>,
}

impl ScriptGate {
    pub fn new(concurrency: usize) -> ScriptGate {
        ScriptGate {
            slots: Arc::new(Semaphore::new(concurrency.max(1))),
        }
    }

    pub async fn enter(&self, wait: Duration) -> Option<OwnedSemaphorePermit> {
        tokio::time::timeout(wait, self.slots.clone().acquire_owned())
            .await
            .ok()?
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_limits_take_the_defaults() {
        let limits = RawLimits::default().resolve();
        assert_eq!(limits.max_body_size, 4 << 20);
        assert_eq!(limits.body_buffer, 32 << 20);
        assert_eq!(limits.certificate_cache, 1024);
        assert_eq!(limits.script_concurrency, 4);
        assert_eq!(limits.capture_entries, 2000);
        assert_eq!(limits.max_sessions, 0);
    }

    #[test]
    fn the_body_buffer_is_never_smaller_than_one_body() {
        let limits = RawLimits {
            max_body_size: 64 << 20,
            body_buffer: 1 << 20,
            ..RawLimits::default()
        }
        .resolve();
        assert_eq!(limits.body_buffer, 64 << 20);
    }

    #[test]
    fn pressure_rises_holds_and_lifts() {
        let pressure = Pressure::with_hold(Duration::from_millis(60));
        assert!(!pressure.set(PRESSURE_NO_SCRIPTS));
        assert!(pressure.set(PRESSURE_RELAY));
        assert!(!pressure.set(PRESSURE_NO_BODIES));
        assert_eq!(pressure.level(), PRESSURE_RELAY);
        assert!(!pressure.set(PRESSURE_NONE));
        assert_eq!(pressure.level(), PRESSURE_RELAY);
        std::thread::sleep(Duration::from_millis(90));
        assert_eq!(pressure.level(), PRESSURE_NONE);
    }

    #[tokio::test]
    async fn the_gate_queues_past_its_concurrency() {
        let gate = ScriptGate::new(1);
        let first = gate.enter(Duration::from_millis(50)).await;
        assert!(first.is_some());
        let started = std::time::Instant::now();
        assert!(gate.enter(Duration::from_millis(30)).await.is_none());
        assert!(
            started.elapsed() >= Duration::from_millis(30),
            "gave up after {:?}",
            started.elapsed()
        );
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(first);
        });
        assert!(
            gate.enter(Duration::from_secs(1)).await.is_some(),
            "the slot freed while waiting was not taken"
        );
    }
}
