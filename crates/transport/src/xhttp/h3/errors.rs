use std::error::Error;
use std::io;

use ::h3::error::{ConnectionError, StreamError};
use ::h3::quic::ConnectionErrorIncoming;

type AnyError = dyn Error + Send + Sync + 'static;

pub(super) fn error(err: impl Into<Box<AnyError>>) -> io::Error {
    let err = err.into();
    match err.downcast::<io::Error>() {
        Ok(err) => *err,
        Err(err) => io::Error::new(kind(err.as_ref()), err),
    }
}

fn kind(err: &AnyError) -> io::ErrorKind {
    use io::ErrorKind::*;
    if let Some(err) = err.downcast_ref::<io::Error>() {
        return err.kind();
    }
    if let Some(err) = err.downcast_ref::<quinn::ConnectionError>() {
        return io::Error::from(err.clone()).kind();
    }
    if let Some(err) = err.downcast_ref::<quinn::ReadError>() {
        return io::Error::from(err.clone()).kind();
    }
    if let Some(err) = err.downcast_ref::<quinn::WriteError>() {
        return io::Error::from(err.clone()).kind();
    }
    if let Some(err) = err.downcast_ref::<StreamError>() {
        return match err {
            StreamError::ConnectionError { 0: err, .. } => kind(err),
            StreamError::Undefined { 0: err, .. } => kind(err.as_ref()),
            StreamError::RemoteClosing { .. } | StreamError::RemoteTerminate { .. } => {
                ConnectionReset
            }
            StreamError::HeaderTooBig { .. } | StreamError::StreamError { .. } => InvalidData,
            _ => Other,
        };
    }
    if let Some(err) = err.downcast_ref::<ConnectionError>() {
        return match err {
            ConnectionError::Timeout { .. } => TimedOut,
            ConnectionError::Remote {
                0: ConnectionErrorIncoming::Timeout,
                ..
            } => TimedOut,
            ConnectionError::Remote {
                0: ConnectionErrorIncoming::Undefined(err),
                ..
            } => kind(err.as_ref()),
            _ => ConnectionReset,
        };
    }
    Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xhttp_h3_keeps_error_kinds() {
        assert_eq!(
            error(io::Error::from(io::ErrorKind::BrokenPipe)).kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            error(quinn::ConnectionError::TimedOut).kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            error(quinn::ConnectionError::Reset).kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            error(quinn::ReadError::ClosedStream).kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            error(quinn::WriteError::ClosedStream).kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            error(quinn::ReadError::ZeroRttRejected).kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            error(quinn::WriteError::ZeroRttRejected).kind(),
            io::ErrorKind::ConnectionReset
        );
    }
}
