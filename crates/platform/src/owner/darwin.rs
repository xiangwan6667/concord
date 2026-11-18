use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use concord_common::{Network, ProcessInfo};

const XSO_SOCKET: u32 = 0x1;
const XSO_INPCB: u32 = 0x10;
const INP_IPV4: u8 = 0x1;
const INP_IPV6: u8 = 0x2;
const MIN_INPCB: usize = 80;
const MIN_SOCKET: usize = 88;
const SS_NOFDREF: u16 = 0x1;
const SOF_MP_SUBFLOW: u32 = 0x0100_0000;
const PATH_MAX: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub struct Pcb {
    pub local: SocketAddr,
    pub v4: bool,
    pub pid: u32,
}

fn word(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

/// `pcblist_n` is a stream of `{len, kind, ..}` records per socket after an `xinpgen`
/// header, each padded to 8 bytes, so the walk does not depend on per-release struct sizes.
pub fn parse_pcblist(buf: &[u8]) -> Vec<Pcb> {
    let mut sockets = Vec::new();
    let mut pending: Option<(SocketAddr, bool)> = None;
    let mut at = word(buf, 0).unwrap_or(0) as usize;
    while let (Some(len), Some(kind)) = (word(buf, at), word(buf, at + 4)) {
        let len = len as usize;
        let Some(record) = buf.get(at..at + len).filter(|_| len >= 8) else {
            break;
        };
        at += len.next_multiple_of(8);
        if kind == XSO_INPCB && len >= MIN_INPCB {
            pending = parse_inpcb(record);
        } else if kind == XSO_SOCKET
            && len >= MIN_SOCKET
            && let (Some((local, v4)), Some(pid)) = (pending.take(), word(record, 68))
            && has_descriptor(record)
        {
            sockets.push(Pcb { local, v4, pid });
        }
    }
    sockets
}

/// A closed socket lingering on a live socket's address keeps its last pid. MPTCP subflows never
/// have a descriptor; xnu's `soreceive` exempts them the same way. `pack(4)` puts `so_flags` at 84.
fn has_descriptor(socket: &[u8]) -> bool {
    let state = socket
        .get(26..28)
        .map_or(0, |b| u16::from_ne_bytes([b[0], b[1]]));
    let flags = word(socket, 84).unwrap_or(0);
    state & SS_NOFDREF == 0 || flags & SOF_MP_SUBFLOW != 0
}

fn parse_inpcb(record: &[u8]) -> Option<(SocketAddr, bool)> {
    let port = u16::from_be_bytes(record.get(18..20)?.try_into().ok()?);
    let flags = *record.get(44)?;
    if flags & INP_IPV4 != 0 {
        let octets: [u8; 4] = record.get(76..80)?.try_into().ok()?;
        Some((
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port),
            true,
        ))
    } else if flags & INP_IPV6 != 0 {
        let octets: [u8; 16] = record.get(64..80)?.try_into().ok()?;
        let ip = Ipv6Addr::from(octets);
        let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
        Some((SocketAddr::new(ip, port), false))
    } else {
        None
    }
}

pub fn select(sockets: &[Pcb], network: Network, src: SocketAddr) -> Option<u32> {
    let same_port = || sockets.iter().filter(|pcb| pcb.local.port() == src.port());
    let exact = same_port().find(|pcb| pcb.v4 == src.is_ipv4() && pcb.local.ip() == src.ip());
    let wildcard =
        || same_port().find(|pcb| pcb.v4 == src.is_ipv4() && pcb.local.ip().is_unspecified());
    let found = match network {
        Network::Tcp => exact,
        Network::Udp => exact.or_else(wildcard),
    };
    found.map(|pcb| pcb.pid)
}

fn read_pcblist(network: Network) -> Option<Vec<u8>> {
    let name = match network {
        Network::Tcp => c"net.inet.tcp.pcblist_n",
        Network::Udp => c"net.inet.udp.pcblist_n",
    };
    for _ in 0..4 {
        let mut len = 0usize;
        // SAFETY: a null buffer only asks for the size.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let mut buf = vec![0u8; len + len / 4 + 8192];
        let mut size = buf.len();
        // SAFETY: `buf` is writable for `size` bytes, which the call updates to the bytes written.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buf.truncate(size);
            return Some(buf);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

fn path_of(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; PATH_MAX];
    // SAFETY: `buf` is writable for the PATH_MAX bytes passed.
    let written =
        unsafe { libc::proc_pidpath(pid as libc::c_int, buf.as_mut_ptr().cast(), PATH_MAX as u32) };
    let written = usize::try_from(written).ok().filter(|len| *len > 0)?;
    buf.truncate(written);
    String::from_utf8(buf).ok()
}

pub fn find(network: Network, src: SocketAddr) -> Option<ProcessInfo> {
    let pid = select(&parse_pcblist(&read_pcblist(network)?), network, src)?;
    let path = path_of(pid)?;
    let name = Path::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    Some(ProcessInfo {
        uid: None,
        name,
        path,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream, UdpSocket};

    use socket2::{Domain, Socket, Type};

    use super::*;

    #[allow(
        clippy::disallowed_methods,
        reason = "tests bind loopback sockets directly"
    )]
    fn bind_udp() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "tests connect to a loopback listener directly"
    )]
    fn connect_tcp(addr: SocketAddr) -> TcpStream {
        TcpStream::connect(addr).unwrap()
    }

    fn record(kind: u32, len: usize, fill: &[(usize, &[u8])]) -> Vec<u8> {
        let mut bytes = vec![0u8; len.next_multiple_of(8)];
        bytes[..4].copy_from_slice(&(len as u32).to_ne_bytes());
        bytes[4..8].copy_from_slice(&kind.to_ne_bytes());
        for (at, value) in fill {
            bytes[*at..*at + value.len()].copy_from_slice(value);
        }
        bytes
    }

    #[test]
    fn records_pair_a_pcb_with_the_following_socket() {
        let header = record(0, 24, &[]);
        let inpcb = record(
            XSO_INPCB,
            104,
            &[
                (18, &8080u16.to_be_bytes()),
                (44, &[INP_IPV4]),
                (76, &[10, 0, 0, 7]),
            ],
        );
        let socket = record(XSO_SOCKET, 120, &[(68, &4321u32.to_ne_bytes())]);
        let ignored = record(0x20, 204, &[]);
        let trailer = record(0x10, 24, &[]);

        let dump = [header, inpcb, socket, ignored, trailer].concat();
        let sockets = parse_pcblist(&dump);
        assert_eq!(
            sockets,
            vec![Pcb {
                local: "10.0.0.7:8080".parse().unwrap(),
                v4: true,
                pid: 4321
            }]
        );
        assert_eq!(
            select(&sockets, Network::Tcp, "10.0.0.7:8080".parse().unwrap()),
            Some(4321)
        );
        assert_eq!(
            select(&sockets, Network::Tcp, "10.0.0.8:8080".parse().unwrap()),
            None
        );
    }

    #[test]
    fn udp_falls_back_to_the_wildcard_socket() {
        let sockets = vec![Pcb {
            local: "0.0.0.0:5353".parse().unwrap(),
            v4: true,
            pid: 9,
        }];
        let src: SocketAddr = "192.168.1.5:5353".parse().unwrap();
        assert_eq!(select(&sockets, Network::Udp, src), Some(9));
        assert_eq!(select(&sockets, Network::Tcp, src), None);
    }

    #[test]
    fn this_process_owns_its_sockets() {
        let exe = std::env::current_exe().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = connect_tcp(listener.local_addr().unwrap());
        let udp = bind_udp();

        for (network, addr) in [
            (Network::Tcp, listener.local_addr().unwrap()),
            (Network::Tcp, client.local_addr().unwrap()),
            (Network::Udp, udp.local_addr().unwrap()),
        ] {
            let info =
                find(network, addr).unwrap_or_else(|| panic!("no owner for {network} {addr}"));
            assert_eq!(Path::new(&info.path).file_name(), exe.file_name());
            assert_eq!(info.name, exe.file_name().unwrap().to_string_lossy());
        }
    }

    #[test]
    fn a_socket_without_a_descriptor_is_skipped_unless_it_is_a_subflow() {
        let inpcb = record(
            XSO_INPCB,
            104,
            &[
                (18, &8080u16.to_be_bytes()),
                (44, &[INP_IPV4]),
                (76, &[127, 0, 0, 1]),
            ],
        );
        let socket = |pid: u32, state: u16, flags: u32| {
            record(
                XSO_SOCKET,
                104,
                &[
                    (26, &state.to_ne_bytes()),
                    (68, &pid.to_ne_bytes()),
                    (84, &flags.to_ne_bytes()),
                ],
            )
        };
        let dump = [
            record(0, 24, &[]),
            inpcb.clone(),
            socket(1, SS_NOFDREF, 0),
            inpcb.clone(),
            socket(2, SS_NOFDREF, SOF_MP_SUBFLOW),
            inpcb,
            socket(3, 0, 0),
        ]
        .concat();
        let pids: Vec<u32> = parse_pcblist(&dump).iter().map(|pcb| pcb.pid).collect();
        assert_eq!(pids, [2, 3]);
    }

    #[test]
    fn a_closed_socket_on_the_same_port_is_not_listed() {
        // Newer than the live socket, the closed one comes first in the list until its peer closes.
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let reusable = || {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
            socket.set_reuse_address(true).unwrap();
            socket
        };
        let live = reusable();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        live.bind(&any.into()).unwrap();
        live.connect(&second.local_addr().unwrap().into()).unwrap();
        let src = live.local_addr().unwrap().as_socket().unwrap();
        let closed = reusable();
        closed.bind(&src.into()).unwrap();
        closed.connect(&first.local_addr().unwrap().into()).unwrap();
        let _peer = first.accept().unwrap();
        drop(closed);

        let sockets = parse_pcblist(&read_pcblist(Network::Tcp).unwrap());
        let listed = sockets.iter().filter(|pcb| pcb.local == src).count();
        assert_eq!(listed, 1);
    }

    #[test]
    fn an_unused_port_has_no_owner() {
        let unused = bind_udp();
        let addr = unused.local_addr().unwrap();
        drop(unused);
        assert!(find(Network::Udp, addr).is_none());
    }
}
