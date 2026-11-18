use std::io;

use socket2::{Domain, Protocol, Socket, Type};

/// A socket that sends ICMP echo requests, and whether a reply carries the request's own
/// identifier.
pub struct IcmpSocket {
    pub socket: Socket,
    pub keeps_identifier: bool,
}

/// Linux gives a datagram ICMP socket its own identifier and rewrites the request's; a
/// refused datagram socket falls back to a raw one.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn icmp_echo_socket(domain: Domain, protocol: Protocol) -> io::Result<IcmpSocket> {
    match Socket::new(domain, Type::DGRAM, Some(protocol)) {
        Ok(socket) => Ok(IcmpSocket {
            socket,
            keeps_identifier: false,
        }),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Ok(IcmpSocket {
            socket: Socket::new(domain, Type::RAW, Some(protocol))?,
            keeps_identifier: true,
        }),
        Err(err) => Err(err),
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
pub fn icmp_echo_socket(domain: Domain, protocol: Protocol) -> io::Result<IcmpSocket> {
    Ok(IcmpSocket {
        socket: Socket::new(domain, Type::DGRAM, Some(protocol))?,
        keeps_identifier: true,
    })
}

/// Windows has no datagram ICMP socket; a raw one needs the privilege the TUN device needs.
#[cfg(windows)]
pub fn icmp_echo_socket(domain: Domain, protocol: Protocol) -> io::Result<IcmpSocket> {
    Ok(IcmpSocket {
        socket: Socket::new(domain, Type::RAW, Some(protocol))?,
        keeps_identifier: true,
    })
}

#[cfg(not(any(unix, windows)))]
pub fn icmp_echo_socket(_domain: Domain, _protocol: Protocol) -> io::Result<IcmpSocket> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}
