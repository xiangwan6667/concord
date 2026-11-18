use std::io;
use std::time::Duration;

/// Keeps the operation's error and uses the caller's message only if its deadline expires.
pub async fn with_timeout<T>(
    duration: Duration,
    work: impl Future<Output = io::Result<T>>,
    message: &'static str,
) -> io::Result<T> {
    tokio::time::timeout(duration, work)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, message))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn deadlines_only_replace_an_unfinished_operation() {
        let limit = Duration::from_secs(5);
        assert_eq!(
            with_timeout(limit, async { Ok(42) }, "late").await.unwrap(),
            42
        );
        let err = with_timeout::<()>(
            limit,
            async { Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")) },
            "late",
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), "denied");
        let start = tokio::time::Instant::now();
        let err = with_timeout::<()>(limit, std::future::pending(), "late")
            .await
            .unwrap_err();
        assert_eq!(start.elapsed(), limit);
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(err.to_string(), "late");
    }
}
