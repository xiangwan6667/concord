use std::future::Future;
use std::io;

use tokio::sync::watch;

/// Counts a client's network resets, so that a connection dialled or in use
/// across one is not kept: it went out on the network the reset left.
pub(crate) struct Resets(watch::Sender<u64>);

/// The resets a connection was taken or dialled after.
#[derive(Clone, Copy)]
pub(crate) struct Ticket(u64);

impl Resets {
    pub(crate) fn new() -> Self {
        Resets(watch::Sender::new(0))
    }

    pub(crate) fn ticket(&self) -> Ticket {
        Ticket(*self.0.borrow())
    }

    pub(crate) fn bump(&self) {
        self.0
            .send_modify(|resets| *resets = resets.wrapping_add(1));
    }

    pub(crate) fn none_since(&self, ticket: Ticket) -> bool {
        *self.0.borrow() == ticket.0
    }

    /// `dial`, dropped once a reset runs, as sing-box's DNS `ConnPool.Reset`
    /// cancels the dials it overtakes.
    pub(crate) async fn dial<T>(
        &self,
        ticket: Ticket,
        dial: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        let mut resets = self.0.subscribe();
        tokio::select! {
            biased;
            _ = resets.wait_for(|resets| *resets != ticket.0) => Err(overtaken()),
            dialled = dial => dialled,
        }
    }
}

pub(crate) fn overtaken() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the network changed while connecting",
    )
}
