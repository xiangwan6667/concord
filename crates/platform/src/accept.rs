use std::io;

/// Errors accept(2) says to retry like `EAGAIN`: they belong to the dequeued connection.
pub fn is_lost_connection(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable => true,
        // WSAENETDOWN means the whole network subsystem failed.
        #[cfg(unix)]
        io::ErrorKind::NetworkDown => true,
        _ => is_pending_errno(err),
    }
}

/// By errno, as `EOPNOTSUPP` shares the `Unsupported` kind with `ENOSYS`, which keeps backing off.
#[cfg(unix)]
fn is_pending_errno(err: &io::Error) -> bool {
    match err.raw_os_error() {
        Some(libc::EPROTO | libc::ENOPROTOOPT | libc::EHOSTDOWN | libc::EOPNOTSUPP) => true,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Some(libc::ENONET) => true,
        _ => false,
    }
}

#[cfg(not(unix))]
fn is_pending_errno(_: &io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_of_one_connection_do_not_back_off() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
        ] {
            assert!(is_lost_connection(&io::Error::from(kind)), "{kind:?}");
        }
        assert!(!is_lost_connection(&io::Error::other("x")));
        assert!(!is_lost_connection(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }

    #[cfg(unix)]
    #[test]
    fn pending_errnos_retry_and_persistent_ones_back_off() {
        let raw = io::Error::from_raw_os_error;
        let pending = [
            libc::EPROTO,
            libc::ENOPROTOOPT,
            libc::EHOSTDOWN,
            libc::EOPNOTSUPP,
            libc::ENETDOWN,
        ];
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert!(is_lost_connection(&raw(libc::ENONET)));
        for errno in pending {
            assert!(is_lost_connection(&raw(errno)), "errno {errno}");
        }
        for errno in [
            libc::ENOSYS,
            libc::EPERM,
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOBUFS,
        ] {
            assert!(!is_lost_connection(&raw(errno)), "errno {errno}");
        }
    }
}
