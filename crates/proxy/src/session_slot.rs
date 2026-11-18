use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};

use crate::util::lock;

/// Counts the resets of a node's shared connections, so that a dial can tell whether one ran
/// while it was under way: what it made then went out on the network the reset left.
#[derive(Default)]
pub(crate) struct Resets(u64);

/// The resets a dial started after.
#[derive(Clone, Copy)]
pub(crate) struct Ticket(u64);

impl Resets {
    pub(crate) fn ticket(&self) -> Ticket {
        Ticket(self.0)
    }

    pub(crate) fn bump(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }

    pub(crate) fn none_since(&self, ticket: Ticket) -> bool {
        self.0 == ticket.0
    }
}

/// What a dial that a reset overtook fails with, as sing-quic fails the callers waiting on a
/// handshake its reset discards.
pub(crate) fn overtaken() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the network changed while connecting",
    )
}

/// A node's one shared connection.
pub(crate) struct SessionSlot<T> {
    held: Mutex<Held<T>>,
}

struct Held<T> {
    resets: Resets,
    conn: Option<Arc<T>>,
}

impl<T> Default for SessionSlot<T> {
    fn default() -> Self {
        SessionSlot {
            held: Mutex::new(Held {
                resets: Resets::default(),
                conn: None,
            }),
        }
    }
}

impl<T> SessionSlot<T> {
    /// The held connection if `usable` says it still is, and the ticket a dial for a new one
    /// starts with.
    pub(crate) fn get(&self, usable: impl Fn(&T) -> bool) -> (Option<Arc<T>>, Ticket) {
        let held = lock(&self.held);
        let conn = held.conn.as_ref().filter(|conn| usable(conn)).cloned();
        (conn, held.resets.ticket())
    }

    /// Holds `conn` unless a reset ran since `ticket`. On false the caller tears `conn` down.
    pub(crate) fn keep(&self, ticket: Ticket, conn: &Arc<T>) -> bool {
        let mut held = lock(&self.held);
        if !held.resets.none_since(ticket) {
            return false;
        }
        held.conn = Some(conn.clone());
        true
    }

    /// `offer`'s last step, for a dial that runs outside it, such as a handshake its callers
    /// share from a task of its own.
    pub(crate) fn adopt(
        &self,
        ticket: Ticket,
        conn: Arc<T>,
        discard: impl FnOnce(Arc<T>),
    ) -> io::Result<Arc<T>> {
        if !self.keep(ticket, &conn) {
            discard(conn);
            return Err(overtaken());
        }
        Ok(conn)
    }

    /// The held connection if `usable` says it still is, or the one `establish` makes. `dialing`
    /// lets one dial run at a time, so the callers that wait for it take what it made.
    pub(crate) async fn offer<F>(
        &self,
        dialing: &tokio::sync::Mutex<()>,
        usable: impl Fn(&T) -> bool,
        establish: impl FnOnce() -> F,
        discard: impl FnOnce(Arc<T>),
    ) -> io::Result<Arc<T>>
    where
        F: Future<Output = io::Result<Arc<T>>>,
    {
        if let (Some(conn), _) = self.get(&usable) {
            return Ok(conn);
        }
        let _turn = dialing.lock().await;
        let (held, ticket) = self.get(&usable);
        if let Some(conn) = held {
            return Ok(conn);
        }
        self.adopt(ticket, establish().await?, discard)
    }

    pub(crate) fn reset(&self) -> Option<Arc<T>> {
        let mut held = lock(&self.held);
        held.resets.bump();
        held.conn.take()
    }

    pub(crate) fn forget(&self, conn: &Arc<T>) {
        let mut held = lock(&self.held);
        if held
            .conn
            .as_ref()
            .is_some_and(|kept| Arc::ptr_eq(kept, conn))
        {
            held.conn = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_dialled_before_a_reset_is_not_kept() {
        let slot = SessionSlot::default();
        let (_, before) = slot.get(|_: &u8| true);
        assert!(slot.reset().is_none());
        assert!(!slot.keep(before, &Arc::new(1)));
        assert!(slot.get(|_| true).0.is_none());
        let (_, after) = slot.get(|_| true);
        assert!(slot.keep(after, &Arc::new(2)));
        assert_eq!(slot.get(|_| true).0.as_deref(), Some(&2));
        assert!(slot.get(|value| *value != 2).0.is_none());
    }

    #[test]
    fn forgetting_takes_out_only_the_connection_named() {
        let slot = SessionSlot::default();
        let (first, second) = (Arc::new(1u8), Arc::new(1u8));
        assert!(slot.keep(slot.get(|_| true).1, &first));
        slot.forget(&second);
        assert!(slot.get(|_| true).0.is_some());
        slot.forget(&first);
        assert!(slot.get(|_| true).0.is_none());
    }

    #[tokio::test]
    async fn callers_that_wait_take_what_the_one_dial_made() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (slot, dialing) = (SessionSlot::default(), tokio::sync::Mutex::new(()));
        let dials = AtomicUsize::new(0);
        let dial = || async {
            dials.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(Arc::new(7u8))
        };
        let (first, second) = tokio::join!(
            slot.offer(&dialing, |_| true, dial, |_| {}),
            slot.offer(&dialing, |_| true, dial, |_| {}),
        );
        assert!(Arc::ptr_eq(&first.unwrap(), &second.unwrap()));
        assert_eq!(dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_dial_a_reset_overtook_is_discarded() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (slot, dialing) = (SessionSlot::default(), tokio::sync::Mutex::new(()));
        let discarded = AtomicBool::new(false);
        let dial = || async {
            slot.reset();
            Ok(Arc::new(1u8))
        };
        let discard = |_| discarded.store(true, Ordering::SeqCst);
        let err = slot
            .offer(&dialing, |_| true, dial, discard)
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(discarded.load(Ordering::SeqCst));
        assert!(slot.get(|_| true).0.is_none());
    }
}
