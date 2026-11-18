//! Background tasks of the proxy layer, owned by the engine: every one is registered with the
//! engine's tracker, so shutdown can stop them and wait until they are gone.

use std::future::Future;

use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use tokio_util::task::TaskTracker;

#[derive(Clone, Default)]
pub struct Tasks {
    tracker: TaskTracker,
    stop: CancellationToken,
    handle: Option<Handle>,
}

impl std::fmt::Debug for Tasks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tasks")
            .field("running", &self.tracker.len())
            .finish_non_exhaustive()
    }
}

impl Tasks {
    /// Tasks spawned through this run on `handle`, also when spawned from a `Drop` outside it.
    pub fn new(tracker: TaskTracker, stop: CancellationToken, handle: Handle) -> Self {
        Tasks {
            tracker,
            stop,
            handle: Some(handle),
        }
    }

    /// Runs `task` until it ends or the owner stops. Panics outside a runtime, like
    /// `tokio::spawn`.
    pub fn spawn<F>(&self, task: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let handle = self.handle.clone().unwrap_or_else(Handle::current);
        self.tracker.spawn_on(self.until_stopped(task), &handle)
    }

    /// A teardown nothing waits for, started where there may be no runtime (a `Drop`); without
    /// one it is skipped. It ends when the owner stops, like `spawn`.
    pub fn spawn_detached<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if let Some(handle) = self.runtime() {
            self.tracker.spawn_on(self.until_stopped(task), &handle);
        }
    }

    /// Runs `task` to its end even after the owner stops. Only for a teardown whose end a
    /// protocol or library bounds: a QUIC connection draining after its close, a device that
    /// aborts and joins its own tasks.
    pub fn spawn_to_end<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if let Some(handle) = self.runtime() {
            self.tracker.spawn_on(task, &handle);
        }
    }

    pub fn stopped(&self) -> WaitForCancellationFuture<'_> {
        self.stop.cancelled()
    }

    pub fn child_token(&self) -> CancellationToken {
        self.stop.child_token()
    }

    fn runtime(&self) -> Option<Handle> {
        self.handle.clone().or_else(|| Handle::try_current().ok())
    }

    fn until_stopped<F>(&self, task: F) -> impl Future<Output = ()> + Send + 'static
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let stop = self.stop.clone();
        async move {
            let _ = stop.run_until_cancelled_owned(task).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn tasks() -> (Tasks, TaskTracker, CancellationToken) {
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let tasks = Tasks::new(tracker.clone(), stop.clone(), Handle::current());
        (tasks, tracker, stop)
    }

    #[tokio::test]
    async fn stopping_ends_spawned_and_detached_tasks_but_not_one_run_to_its_end() {
        let (tasks, tracker, stop) = tasks();
        let (finish, finished) = tokio::sync::oneshot::channel::<()>();
        let ended = Arc::new(AtomicBool::new(false));
        tasks.spawn(std::future::pending());
        tasks.spawn_detached(std::future::pending());
        tasks.spawn_to_end({
            let ended = ended.clone();
            async move {
                let _ = finished.await;
                ended.store(true, Ordering::SeqCst);
            }
        });
        assert_eq!(tracker.len(), 3);
        stop.cancel();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(tracker.len(), 1);
        finish.send(()).unwrap();
        tracker.close();
        tracker.wait().await;
        assert!(ended.load(Ordering::SeqCst));
    }

    #[test]
    fn a_detached_teardown_without_a_runtime_is_skipped() {
        let tasks = Tasks::default();
        tasks.spawn_detached(async {});
        tasks.spawn_to_end(async {});
        assert!(tasks.tracker.is_empty());
    }
}
