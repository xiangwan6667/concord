use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use concord_common::Tasks;
use tokio::task::JoinHandle;

use super::session::Session;
use crate::session_slot::{Resets, Ticket};
use crate::util::lock;

/// Idle sessions and every live one. Sessions report back here when they end
/// or when a stream they carried finishes.
pub(super) struct Pool {
    idle: Mutex<Vec<Arc<Session>>>,
    all: Mutex<Live>,
    disable_reuse: bool,
    min_idle: usize,
    cleaner: Mutex<Option<JoinHandle<()>>>,
    pub(super) tasks: Tasks,
}

#[derive(Default)]
struct Live {
    resets: Resets,
    sessions: HashMap<u64, Arc<Session>>,
}

impl Drop for Pool {
    fn drop(&mut self) {
        if let Some(task) = lock(&self.cleaner).take() {
            task.abort();
        }
        self.close_all();
    }
}

impl Pool {
    pub(super) fn new(disable_reuse: bool, min_idle: usize, tasks: Tasks) -> Arc<Pool> {
        Arc::new(Pool {
            idle: Mutex::new(Vec::new()),
            all: Mutex::new(Live::default()),
            disable_reuse,
            min_idle,
            cleaner: Mutex::new(None),
            tasks,
        })
    }

    pub(super) fn disable_reuse(&self) -> bool {
        self.disable_reuse
    }

    /// The newest idle session.
    pub(super) fn take_idle(&self) -> Option<Arc<Session>> {
        let mut idle = lock(&self.idle);
        let newest = idle
            .iter()
            .enumerate()
            .max_by_key(|(_, session)| session.seq)
            .map(|(index, _)| index)?;
        Some(idle.swap_remove(newest))
    }

    pub(super) fn ticket(&self) -> Ticket {
        lock(&self.all).resets.ticket()
    }

    /// Takes in a session dialled under `ticket`. On false a reset ran since, and the caller
    /// closes the session.
    pub(super) fn register(&self, session: Arc<Session>, ticket: Ticket) -> bool {
        let mut all = lock(&self.all);
        if !all.resets.none_since(ticket) {
            return false;
        }
        all.sessions.insert(session.seq, session);
        true
    }

    pub(super) fn release(&self, session: &Arc<Session>) {
        if session.is_closed() {
            return;
        }
        if self.disable_reuse {
            session.close();
            return;
        }
        *lock(&session.idle_since) = Instant::now();
        lock(&self.idle).push(session.clone());
    }

    pub(super) fn gone(&self, seq: u64) {
        lock(&self.idle).retain(|session| session.seq != seq);
        lock(&self.all).sessions.remove(&seq);
    }

    pub(super) fn close_all(&self) {
        let sessions: Vec<_> = {
            let mut all = lock(&self.all);
            all.resets.bump();
            all.sessions.drain().map(|(_, session)| session).collect()
        };
        lock(&self.idle).clear();
        for session in sessions {
            session.close();
        }
    }

    pub(super) fn start_cleaner(self: &Arc<Self>, interval: Duration, timeout: Duration) {
        if self.disable_reuse {
            return;
        }
        let mut cleaner = lock(&self.cleaner);
        if cleaner.is_some() {
            return;
        }
        let pool = Arc::downgrade(self);
        *cleaner = Some(self.tasks.spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let Some(pool) = pool.upgrade() else {
                    return;
                };
                pool.clean(timeout);
            }
        }));
    }

    fn clean(&self, timeout: Duration) {
        let now = Instant::now();
        let mut expired = Vec::new();
        {
            let mut idle = lock(&self.idle);
            idle.sort_by_key(|session| std::cmp::Reverse(session.seq));
            let mut active = 0;
            idle.retain(|session| {
                let mut since = lock(&session.idle_since);
                if now.duration_since(*since) <= timeout {
                    active += 1;
                    return true;
                }
                if active < self.min_idle {
                    *since = now;
                    active += 1;
                    return true;
                }
                expired.push(session.clone());
                false
            });
        }
        for session in expired {
            session.close();
        }
    }
}
