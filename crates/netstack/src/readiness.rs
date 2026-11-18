use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use concord_common::sync::lock;
use concord_platform::SocketObserver;
use futures_util::task::AtomicWaker;

const READ: u64 = 1;
const WRITE: u64 = 2;
const FLAGS: u64 = READ | WRITE;

#[derive(Default)]
pub struct SocketReady {
    native: std::sync::Mutex<Option<SocketObserver>>,
    state: AtomicU64,
    reader: AtomicWaker,
    writer: AtomicWaker,
}

impl SocketReady {
    pub fn set_native(&self, native: Option<SocketObserver>) {
        *lock(&self.native) = native;
        // A waiter parked with the old observer hears nothing from the new one until it polls
        // again, and its connection may have no other event coming.
        self.reader.wake();
        self.writer.wake();
    }

    pub fn set(&self, readable: bool, writable: bool) {
        let flags = (u64::from(readable) * READ) | (u64::from(writable) * WRITE);
        if flags == 0 {
            return;
        }
        let _ = self
            .state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                Some((state.wrapping_add(FLAGS + 1) & !FLAGS) | (state & FLAGS) | flags)
            });
        if readable {
            self.reader.wake();
        }
        if writable {
            self.writer.wake();
        }
    }

    fn poll_ready(
        &self,
        cx: &mut Context<'_>,
        flag: u64,
        waker: &AtomicWaker,
    ) -> Poll<io::Result<()>> {
        let budget = ready!(tokio::task::coop::poll_proceed(cx));
        if self.state.load(Ordering::Acquire) & flag != 0 {
            budget.made_progress();
            return Poll::Ready(Ok(()));
        }
        waker.register(cx.waker());
        if self.state.load(Ordering::Acquire) & flag != 0 {
            budget.made_progress();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    pub fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if SocketObserver::AVAILABLE
            && let Some(native) = lock(&self.native).as_ref()
        {
            self.reader.register(cx.waker());
            return native.poll_read_ready(cx);
        }
        self.poll_ready(cx, READ, &self.reader)
    }

    pub fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if SocketObserver::AVAILABLE
            && let Some(native) = lock(&self.native).as_ref()
        {
            self.writer.register(cx.waker());
            return native.poll_write_ready(cx);
        }
        self.poll_ready(cx, WRITE, &self.writer)
    }

    fn try_io<T>(&self, flag: u64, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        if SocketObserver::AVAILABLE
            && let Some(native) = lock(&self.native).as_ref()
        {
            let interest = if flag == READ {
                tokio::io::Interest::READABLE
            } else {
                tokio::io::Interest::WRITABLE
            };
            return native.try_io(interest, operation);
        }
        let state = self.state.load(Ordering::Acquire);
        let result = operation();
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        {
            // An event arriving during the syscall must survive clearing the old readiness.
            let _ = self.state.compare_exchange(
                state,
                state & !flag,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        result
    }

    pub fn try_read<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.try_io(READ, operation)
    }

    pub fn try_write<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.try_io(WRITE, operation)
    }
}

/// Registers once per connection; readiness and I/O remain concrete on the hot path.
pub trait SocketOwner: Send + Sync {
    fn register(
        &self,
        socket: Arc<TcpStream>,
        ready: Arc<SocketReady>,
    ) -> io::Result<Box<dyn Send + Sync>>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use super::*;

    #[test]
    fn clearing_a_read_does_not_clear_a_concurrent_event() {
        let ready = SocketReady::default();
        ready.set(true, true);
        let result: io::Result<()> = ready.try_read(|| {
            ready.set(true, false);
            Err(io::ErrorKind::WouldBlock.into())
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_ne!(ready.state.load(Ordering::Acquire) & READ, 0);
        ready
            .try_read(|| Err::<(), _>(io::ErrorKind::WouldBlock.into()))
            .unwrap_err();
        assert_eq!(ready.state.load(Ordering::Acquire) & FLAGS, WRITE);
    }
}
