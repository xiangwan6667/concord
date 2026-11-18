use std::sync::Mutex;

use concord_common::Tasks;
use concord_common::sync::lock;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// The proxy layer's share of the engine's tracker, and the stop its tasks watch. Shutdown stops
/// them; the configs built after it get a fresh stop.
pub(crate) struct ProxyTasks {
    tracker: TaskTracker,
    handle: Handle,
    stop: Mutex<CancellationToken>,
}

impl ProxyTasks {
    pub(crate) fn new(tracker: TaskTracker, handle: Handle) -> Self {
        ProxyTasks {
            tracker,
            handle,
            stop: Mutex::new(CancellationToken::new()),
        }
    }

    pub(crate) fn tasks(&self) -> Tasks {
        Tasks::new(
            self.tracker.clone(),
            lock(&self.stop).clone(),
            self.handle.clone(),
        )
    }

    pub(crate) fn stop(&self) {
        let stopped = std::mem::take(&mut *lock(&self.stop));
        stopped.cancel();
    }
}
