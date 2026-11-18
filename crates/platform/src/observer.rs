use std::io;
use std::task::{Context, Poll};

use tokio::io::Interest;

/// Tokio's reactor watching a socket that another reactor owns, which Linux and Android's TUN
/// queues hand their sockets to while idle. No other platform hands sockets between reactors,
/// so there [`AVAILABLE`](Self::AVAILABLE) is false and none is ever made.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct SocketObserver(tokio::io::unix::AsyncFd<Source>);

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub struct SocketObserver(std::convert::Infallible);

#[cfg(any(target_os = "linux", target_os = "android"))]
struct Source(std::sync::Arc<dyn std::os::fd::AsRawFd + Send + Sync>);

#[cfg(any(target_os = "linux", target_os = "android"))]
impl std::os::fd::AsRawFd for Source {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl SocketObserver {
    pub const AVAILABLE: bool = true;

    /// Registers `source` with the current runtime's reactor.
    pub fn register(
        source: std::sync::Arc<dyn std::os::fd::AsRawFd + Send + Sync>,
        interest: Interest,
    ) -> io::Result<Self> {
        // SAFETY: the source Arc keeps the descriptor open and stable until deregistration.
        unsafe { tokio::io::unix::AsyncFd::register_with_interest(Source(source), interest) }
            .map(Self)
            .map_err(|error| error.into_parts().1)
    }

    pub fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_read_ready(cx).map(|result| result.map(|_| ()))
    }

    pub fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_write_ready(cx).map(|result| result.map(|_| ()))
    }

    pub fn try_io<T>(
        &self,
        interest: Interest,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        self.0.try_io(interest, |_| operation())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl SocketObserver {
    pub const AVAILABLE: bool = false;

    pub fn poll_read_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0 {}
    }

    pub fn poll_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0 {}
    }

    pub fn try_io<T>(
        &self,
        _interest: Interest,
        _operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        match self.0 {}
    }
}
