use std::io;
use std::net::IpAddr;

use concord_common::RawSocket;
use socket2::{Protocol, Socket};

/// Whether a vectored TCP write goes through [`send_tcp_vectored`] instead of the stream's
/// own: on Linux std's vectored TCP write uses writev, unlike its signal-safe scalar send.
pub const SEND_TCP_VECTORED: bool = cfg!(any(target_os = "linux", target_os = "android"));

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn send_tcp_vectored(
    stream: &tokio::net::TcpStream,
    buffers: &[io::IoSlice<'_>],
) -> io::Result<usize> {
    socket2::SockRef::from(stream).send_vectored_with_flags(buffers, libc::MSG_NOSIGNAL)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn send_tcp_vectored(
    _stream: &tokio::net::TcpStream,
    _buffers: &[io::IoSlice<'_>],
) -> io::Result<usize> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(unix)]
pub fn raw_socket_of<T: std::os::fd::AsRawFd>(socket: &T) -> RawSocket {
    RawSocket(i64::from(socket.as_raw_fd()))
}

#[cfg(windows)]
pub fn raw_socket_of<T: std::os::windows::io::AsRawSocket>(socket: &T) -> RawSocket {
    RawSocket(socket.as_raw_socket() as i64)
}

/// Bytes a TCP socket's send buffer can still take. The kernel counts its bookkeeping
/// against the same limit, so this is an upper bound.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn send_space(stream: &impl std::os::fd::AsFd) -> Option<usize> {
    use std::os::fd::AsRawFd;
    let capacity = socket2::SockRef::from(stream).send_buffer_size().ok()?;
    let mut queued: libc::c_int = 0;
    // SAFETY: the descriptor is borrowed from a live socket, and `TIOCOUTQ` writes one `c_int`
    // through the pointer it is given.
    let rc = unsafe { libc::ioctl(stream.as_fd().as_raw_fd(), libc::TIOCOUTQ, &mut queued) };
    (rc == 0).then(|| capacity.saturating_sub(usize::try_from(queued).unwrap_or(0)))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn send_space<T: ?Sized>(_stream: &T) -> Option<usize> {
    None
}

/// Whether TCP keep-alive may be turned on; mihomo keeps it off on Android whatever the profile
/// says (`component/keepalive/tcp_keepalive.go::SetDisableKeepAlive`).
pub const KEEP_ALIVE: bool = !cfg!(target_os = "android");

/// Whether a nonblocking TCP write goes through [`try_send_vectored`] instead of the stream's own.
pub const TRY_SEND_VECTORED: bool = cfg!(target_os = "linux");

/// Attempts a nonblocking TCP write even before its new reactor reports readiness.
#[cfg(target_os = "linux")]
pub fn try_send_vectored(
    stream: &impl std::os::fd::AsFd,
    bufs: &[io::IoSlice<'_>],
) -> io::Result<usize> {
    socket2::SockRef::from(stream)
        .send_vectored_with_flags(bufs, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
}

#[cfg(not(target_os = "linux"))]
pub fn try_send_vectored<T: ?Sized>(_stream: &T, _bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn bind_to_interface(socket: &Socket, _name: &str, index: u32, is_v6: bool) -> io::Result<()> {
    let index = std::num::NonZeroU32::new(index);
    if is_v6 {
        socket.bind_device_by_index_v6(index)
    } else {
        socket.bind_device_by_index_v4(index)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind_to_interface(socket: &Socket, name: &str, _index: u32, _is_v6: bool) -> io::Result<()> {
    socket.bind_device(Some(name.as_bytes()))
}

#[cfg(windows)]
pub fn bind_to_interface(socket: &Socket, _name: &str, index: u32, is_v6: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, setsockopt,
    };

    // IP_UNICAST_IF wants the IPv4 index in network byte order, IPV6_UNICAST_IF does not.
    let (level, name, value) = if is_v6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    };
    // SAFETY: pointer and length describe `value`; the handle belongs to `socket`.
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    windows
)))]
pub fn bind_to_interface(
    _socket: &Socket,
    _name: &str,
    _index: u32,
    _is_v6: bool,
) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_routing_mark(socket: &Socket, mark: u32) -> io::Result<()> {
    socket.set_mark(mark)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn set_routing_mark(_socket: &Socket, _mark: u32) -> io::Result<()> {
    Ok(())
}

/// macOS and Windows need `connectx`/`ConnectEx` to carry data, which tokio cannot issue.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn enable_tfo(socket: &Socket) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let value: libc::c_int = 1;
    // SAFETY: pointer and length describe `value`; the descriptor belongs to `socket`.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN_CONNECT,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn enable_tfo(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn mptcp_protocol() -> Option<Protocol> {
    Some(Protocol::MPTCP)
}

#[cfg(not(target_os = "linux"))]
pub fn mptcp_protocol() -> Option<Protocol> {
    None
}

/// Without this Windows fails `recvfrom` on an ICMP port-unreachable or TTL-expired message
/// for any peer, as Go's `net` also turns off for every UDP socket.
#[cfg(windows)]
pub fn prepare_udp_socket(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SIO_UDP_CONNRESET, SIO_UDP_NETRESET, SOCKET_ERROR, WSAIoctl,
    };

    for control in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
        let enable: u32 = 0;
        let mut returned: u32 = 0;
        // SAFETY: buffers match the sizes passed and no overlapped I/O is requested.
        let rc = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as usize,
                control,
                std::ptr::from_ref(&enable).cast(),
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if rc == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn prepare_udp_socket(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_routable_destinations_are_global_unicast() {
        for text in [
            "8.8.8.8",
            "192.168.1.1",
            "10.0.0.1",
            "2001:db8::1",
            "fd00::1",
        ] {
            assert!(is_global_unicast(text.parse().unwrap()), "{text}");
        }
        for text in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!is_global_unicast(text.parse().unwrap()), "{text}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn raw_socket_of_returns_the_descriptor() {
        use std::os::fd::AsRawFd;

        let socket = Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        assert_eq!(raw_socket_of(&socket).0, i64::from(socket.as_raw_fd()));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn binding_to_the_loopback_interface_succeeds() {
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let index = crate::interface_by_name(name).map_or(1, |info| info.index);
        let socket = Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        match bind_to_interface(&socket, name, index, false) {
            Ok(()) => {}
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}"),
        }
    }
}
