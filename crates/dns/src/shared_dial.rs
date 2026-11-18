use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};

use concord_common::sync::lock;
use tokio::sync::watch;

use crate::resets::overtaken;

#[derive(Clone)]
enum Outcome {
    Pending,
    Done(Result<(), Arc<io::Error>>),
    /// A reset ran while the dial was under way: what it makes went out on
    /// the network the reset left, so the waiters join a dial on the new one.
    Overtaken,
}

type Flight = watch::Sender<Outcome>;

/// One upstream session shared by concurrent queries: a live cached session is
/// handed out, and a caller that misses it joins the dial already in progress
/// instead of starting another.
pub(crate) struct SharedDial<T> {
    state: Mutex<State<T>>,
}

struct State<T> {
    cached: Option<T>,
    connecting: Option<Arc<Flight>>,
}

pub(crate) struct Got<T> {
    pub(crate) value: T,
    /// The session was cached before this caller asked, so a failure on it may
    /// only mean the server dropped an idle connection.
    pub(crate) reused: bool,
}

enum Join<'a, T> {
    Ready(Got<T>),
    Dial(Turn<'a, T>),
}

/// The caller's turn to dial. Waiters are released by `publish` or
/// `fail`; dropping the turn unfinished fails them as cancelled.
struct Turn<'a, T> {
    slot: &'a SharedDial<T>,
    flight: Arc<Flight>,
}

impl<T> SharedDial<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                cached: None,
                connecting: None,
            }),
        }
    }

    pub(crate) fn take(&self) -> Option<T> {
        lock(&self.state).cached.take()
    }

    /// `take` after a network change, which also overtakes the dial in
    /// progress, as sing-box's DNS `ConnPool.Reset` cancels it.
    pub(crate) fn reset(&self) -> Option<T> {
        let mut state = lock(&self.state);
        if let Some(flight) = state.connecting.take() {
            flight.send_replace(Outcome::Overtaken);
        }
        state.cached.take()
    }
}

impl<T: Clone> SharedDial<T> {
    pub(crate) async fn get(
        &self,
        live: impl Fn(&T) -> bool,
        dial: impl Future<Output = io::Result<T>>,
    ) -> io::Result<Got<T>> {
        let turn = match self.join(live).await? {
            Join::Ready(got) => return Ok(got),
            Join::Dial(turn) => turn,
        };
        let mut reset = turn.flight.subscribe();
        tokio::select! {
            biased;
            _ = reset.wait_for(|outcome| matches!(outcome, Outcome::Overtaken)) => Err(overtaken()),
            dialled = dial => match dialled {
                Ok(value) => {
                    if turn.publish(value.clone()) {
                        Ok(Got {
                            value,
                            reused: false,
                        })
                    } else {
                        Err(overtaken())
                    }
                }
                Err(err) => Err(turn.fail(err)),
            },
        }
    }

    async fn join(&self, live: impl Fn(&T) -> bool) -> io::Result<Join<'_, T>> {
        let mut reused = true;
        loop {
            let mut outcome = {
                let mut state = lock(&self.state);
                state.cached.take_if(|session| !live(session));
                if let Some(session) = &state.cached {
                    return Ok(Join::Ready(Got {
                        value: session.clone(),
                        reused,
                    }));
                }
                reused = false;
                match &state.connecting {
                    Some(flight) => flight.subscribe(),
                    None => {
                        let flight = Arc::new(watch::Sender::new(Outcome::Pending));
                        state.connecting = Some(Arc::clone(&flight));
                        return Ok(Join::Dial(Turn { slot: self, flight }));
                    }
                }
            };
            let result = outcome
                .wait_for(|outcome| !matches!(outcome, Outcome::Pending))
                .await
                .map_err(io::Error::other)?
                .clone();
            if let Outcome::Done(Err(err)) = result {
                return Err(shared(err));
            }
        }
    }
}

impl<T> Turn<'_, T> {
    /// Caches `session`, or returns false when a reset overtook this dial.
    fn publish(self, session: T) -> bool {
        self.finish(Some(session), Ok(()))
    }

    fn fail(self, err: io::Error) -> io::Error {
        let err = Arc::new(err);
        self.finish(None, Err(Arc::clone(&err)));
        shared(err)
    }

    fn finish(&self, session: Option<T>, result: Result<(), Arc<io::Error>>) -> bool {
        let mut state = lock(&self.slot.state);
        if !self.current(&state) {
            return false;
        }
        if let Some(session) = session {
            state.cached = Some(session);
        }
        state.connecting = None;
        self.flight.send_replace(Outcome::Done(result));
        true
    }

    fn current(&self, state: &State<T>) -> bool {
        state
            .connecting
            .as_ref()
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
    }
}

impl<T> Drop for Turn<'_, T> {
    fn drop(&mut self) {
        let mut state = lock(&self.slot.state);
        if self.current(&state) {
            state.connecting = None;
            self.flight
                .send_replace(Outcome::Done(Err(Arc::new(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "DNS session dial cancelled",
                )))));
        }
    }
}

fn shared(err: Arc<io::Error>) -> io::Error {
    io::Error::new(err.kind(), err)
}
