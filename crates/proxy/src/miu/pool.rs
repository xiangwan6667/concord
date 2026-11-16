use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
#[cfg(test)]
use concord_common::BoxStream;
use concord_common::sync::lock;
use concord_common::{DialCx, DialEnv, Initiator};
use concord_tls::TlsConn;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::anytls::padding::Padding;
use crate::node::Link;

use super::dial_lane;
use super::transport::LaneIo;

pub(super) struct IdleLane {
    pub(super) io: LaneIo,
    pub(super) peer_idle: Option<Duration>,
    pub(super) peer_raw: bool,
    since: Instant,
}

impl IdleLane {
    #[cfg(test)]
    pub(super) fn new(io: BoxStream, peer_idle: Option<Duration>) -> Self {
        Self::reused(LaneIo::Plain(io), peer_idle, false)
    }

    pub(super) fn tls(io: TlsConn) -> Self {
        Self::reused(LaneIo::Tls(Box::new(io)), None, false)
    }

    pub(super) fn reused(io: LaneIo, peer_idle: Option<Duration>, peer_raw: bool) -> Self {
        Self {
            io,
            peer_idle,
            peer_raw,
            since: Instant::now(),
        }
    }
}

#[derive(Default)]
struct State {
    generation: u64,
    idle: Vec<IdleLane>,
    pending: usize,
    last_open: Option<Instant>,
}

impl State {
    fn push(&mut self, lane: IdleLane) {
        if self.idle.len() == 32 {
            self.idle.remove(0);
        }
        self.idle.push(lane);
    }
}

pub(super) struct Pool {
    idle: Mutex<State>,
    timeout: Duration,
    cleaner: Mutex<Option<JoinHandle<()>>>,
    warmers: Mutex<Vec<JoinHandle<()>>>,
    changed: Arc<Notify>,
    pub(super) padding: ArcSwap<Padding>,
}

impl Pool {
    pub(super) fn new(timeout: u64, padding: Padding) -> Arc<Self> {
        Arc::new(Self {
            idle: Mutex::new(State::default()),
            timeout: Duration::from_secs(if timeout == 0 { 30 } else { timeout }),
            cleaner: Mutex::new(None),
            warmers: Mutex::new(Vec::new()),
            changed: Arc::new(Notify::new()),
            padding: ArcSwap::from_pointee(padding),
        })
    }

    fn ttl(&self, lane: &IdleLane, rank: usize) -> Duration {
        let ttl = if rank < 4 {
            self.timeout.max(Duration::from_secs(120))
        } else {
            self.timeout
        };
        match lane
            .peer_idle
            .filter(|peer| *peer > Duration::from_secs(10))
        {
            Some(peer) => ttl.min(peer - Duration::from_secs(5)),
            None => ttl,
        }
    }

    pub(super) fn take(&self) -> (u64, Option<IdleLane>) {
        let mut state = lock(&self.idle);
        while let Some(lane) = state.idle.pop() {
            if lane.since.elapsed() < self.ttl(&lane, 0) {
                return (state.generation, Some(lane));
            }
        }
        (state.generation, None)
    }

    #[cfg(test)]
    pub(super) async fn available(&self) -> IdleLane {
        loop {
            let changed = self.changed.notified();
            if let (_, Some(lane)) = self.take() {
                return lane;
            }
            changed.await;
        }
    }

    pub(super) fn put(self: &Arc<Self>, generation: u64, lane: IdleLane) {
        {
            let mut state = lock(&self.idle);
            if state.generation != generation {
                return;
            }
            state.push(lane);
        }
        self.start_cleaner();
        self.changed.notify_one();
    }

    pub(super) fn clear(&self) -> u64 {
        let mut warmers = lock(&self.warmers);
        let mut state = lock(&self.idle);
        state.generation = state.generation.wrapping_add(1);
        state.idle.clear();
        state.pending = 0;
        state.last_open = None;
        for task in warmers.drain(..) {
            task.abort();
        }
        self.changed.notify_one();
        state.generation
    }

    fn reserve_warm(&self, minimum: usize) -> (u64, usize) {
        let mut state = lock(&self.idle);
        let now = Instant::now();
        let burst = state
            .last_open
            .is_some_and(|last| now - last <= Duration::from_secs(10));
        state.last_open = Some(now);
        let count = if burst {
            minimum
                .min(32)
                .saturating_sub(state.idle.len() + state.pending)
        } else {
            0
        };
        state.pending += count;
        (state.generation, count)
    }

    fn finish_warm(self: &Arc<Self>, generation: u64, lane: Option<IdleLane>) {
        let received = lane.is_some();
        {
            let mut state = lock(&self.idle);
            if state.generation != generation {
                return;
            }
            state.pending = state.pending.saturating_sub(1);
            if let Some(lane) = lane {
                state.push(lane);
            }
        }
        if received {
            self.start_cleaner();
            self.changed.notify_one();
        }
    }

    pub(super) fn prewarm(
        self: &Arc<Self>,
        link: &Arc<Link>,
        token: [u8; 32],
        env: &DialEnv,
        minimum: usize,
    ) {
        let mut warmers = lock(&self.warmers);
        warmers.retain(|task| !task.is_finished());
        let (generation, count) = self.reserve_warm(minimum);
        for _ in 0..count {
            let weak = Arc::downgrade(self);
            let link = link.clone();
            let env = env.clone();
            let padding = self.padding.load_full();
            warmers.push(tokio::spawn(async move {
                let timeout = Duration::from_secs(10);
                let cx = DialCx::new(&env, Initiator::Proxy, Some(Instant::now() + timeout));
                let lane = tokio::time::timeout(timeout, dial_lane(&link, &token, &padding, &cx))
                    .await
                    .ok()
                    .and_then(Result::ok);
                if let Some(pool) = weak.upgrade() {
                    pool.finish_warm(generation, lane);
                }
            }));
        }
    }

    fn next_expiry(&self) -> Option<Instant> {
        let mut state = lock(&self.idle);
        let count = state.idle.len();
        let mut rank = count;
        state.idle.retain(|lane| {
            rank -= 1;
            lane.since.elapsed() < self.ttl(lane, rank)
        });
        state
            .idle
            .iter()
            .rev()
            .enumerate()
            .map(|(rank, lane)| lane.since + self.ttl(lane, rank))
            .min()
    }

    fn start_cleaner(self: &Arc<Self>) {
        let mut cleaner = lock(&self.cleaner);
        if cleaner.is_some() {
            return;
        }
        let weak = Arc::downgrade(self);
        let changed = self.changed.clone();
        *cleaner = Some(tokio::spawn(async move {
            loop {
                let next = match weak.upgrade() {
                    Some(pool) => pool.next_expiry(),
                    None => return,
                };
                match next {
                    Some(deadline) => tokio::select! {
                        () = tokio::time::sleep_until(deadline) => {},
                        () = changed.notified() => {},
                    },
                    None => changed.notified().await,
                }
            }
        }));
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        if let Some(cleaner) = lock(&self.cleaner).take() {
            cleaner.abort();
        }
        for task in lock(&self.warmers).drain(..) {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> Arc<Pool> {
        Pool::new(30, crate::miu::padding::derive(&[7; 32]).unwrap())
    }

    #[tokio::test(start_paused = true)]
    async fn prewarming_reserves_only_the_missing_lanes_during_a_burst() {
        let pool = pool();
        assert_eq!(pool.reserve_warm(2), (0, 0));
        assert_eq!(pool.reserve_warm(2), (0, 2));
        assert_eq!(pool.reserve_warm(2), (0, 0));
        pool.finish_warm(0, None);
        assert_eq!(pool.reserve_warm(2), (0, 1));
        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(pool.reserve_warm(32), (0, 0));
        assert_eq!(pool.reserve_warm(99), (0, 30));
    }

    #[tokio::test]
    async fn a_reset_ignores_older_prewarming_results() {
        let pool = pool();
        pool.reserve_warm(2);
        pool.reserve_warm(2);
        pool.clear();
        assert_eq!(pool.reserve_warm(2), (1, 0));
        assert_eq!(pool.reserve_warm(2), (1, 2));
        let (client, _peer) = tokio::io::duplex(64);
        pool.finish_warm(0, Some(IdleLane::new(Box::new(client), None)));
        let state = lock(&pool.idle);
        assert!(state.idle.is_empty());
        assert_eq!(state.pending, 2);
    }
}
