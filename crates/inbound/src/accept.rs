use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use concord_platform::is_lost_connection;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

const MIN_BACKOFF: Duration = Duration::from_millis(5);
const MAX_BACKOFF: Duration = Duration::from_secs(1);

pub(crate) fn next_backoff(previous: Duration) -> Duration {
    (previous * 2).clamp(MIN_BACKOFF, MAX_BACKOFF)
}

/// `EMFILE`/`ENFILE` on Unix and `WSAEMFILE` on Windows. A match only changes
/// the log line: every error that is not a lost connection backs off.
pub(crate) fn is_fd_exhaustion(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(23 | 24 | 10024))
}

pub(crate) async fn accept_loop(
    listener: TcpListener,
    cancel: CancellationToken,
    mut on_accept: impl FnMut(TcpStream, SocketAddr),
) {
    let mut delay = Duration::ZERO;
    loop {
        let accepted = tokio::select! {
            () = cancel.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, from)) => {
                delay = Duration::ZERO;
                on_accept(stream, from);
            }
            Err(err) if is_lost_connection(&err) => {}
            Err(err) => {
                if delay.is_zero() {
                    if is_fd_exhaustion(&err) {
                        tracing::warn!("accept: out of file descriptors, backing off");
                    } else {
                        tracing::warn!("accept failed: {err}");
                    }
                }
                delay = next_backoff(delay);
                tokio::select! {
                    () = cancel.cancelled() => return,
                    () = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_five_milliseconds_to_one_second() {
        let mut delay = Duration::ZERO;
        let mut seen = Vec::new();
        for _ in 0..10 {
            delay = next_backoff(delay);
            seen.push(delay.as_millis());
        }
        assert_eq!(seen, [5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000]);
    }

    #[test]
    fn descriptor_exhaustion_is_recognised() {
        assert!(is_fd_exhaustion(&io::Error::from_raw_os_error(24)));
        assert!(is_fd_exhaustion(&io::Error::from_raw_os_error(23)));
        assert!(!is_fd_exhaustion(&io::Error::from_raw_os_error(98)));
        assert!(!is_fd_exhaustion(&io::Error::other("x")));
    }

    #[tokio::test]
    async fn a_cancelled_loop_returns_and_releases_the_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(accept_loop(listener, cancel.clone(), |_, _| {}));
        cancel.cancel();
        task.await.unwrap();
        TcpListener::bind(addr).await.unwrap();
    }
}
