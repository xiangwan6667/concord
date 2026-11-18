use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::time::Duration;

use concord_common::Network;
#[cfg(target_os = "linux")]
use concord_common::ProcessInfo;
use socket2::{Domain, Protocol, Socket, Type};

use super::procnet::{self, Match};

const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST_DUMP: u16 = 0x1 | 0x300;
const HEADER: usize = 16;
const DIAG_MSG: usize = 72;

fn request(family: u8, protocol: u8, port: u16) -> Vec<u8> {
    let mut message = Vec::with_capacity(HEADER + 56);
    message.extend_from_slice(&((HEADER + 56) as u32).to_ne_bytes());
    message.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    message.extend_from_slice(&NLM_F_REQUEST_DUMP.to_ne_bytes());
    message.extend_from_slice(&[0; 8]);
    message.extend_from_slice(&[family, protocol, 0, 0]);
    message.extend_from_slice(&u32::MAX.to_ne_bytes());
    message.extend_from_slice(&port.to_be_bytes());
    message.extend_from_slice(&[0; 38]);
    message.extend_from_slice(&[0xff; 8]);
    message
}

#[derive(Debug, PartialEq, Eq)]
struct Diag {
    local: SocketAddr,
    uid: u32,
    inode: u32,
}

fn parse_diag(data: &[u8]) -> Option<Diag> {
    let data = data.get(..DIAG_MSG)?;
    let port = u16::from_be_bytes(data.get(4..6)?.try_into().ok()?);
    let ip = match *data.first()? {
        2 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data.get(8..12)?).ok()?)),
        10 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data.get(8..24)?).ok()?)),
        _ => return None,
    };
    Some(Diag {
        local: SocketAddr::new(ip, port),
        uid: u32::from_ne_bytes(data.get(64..68)?.try_into().ok()?),
        inode: u32::from_ne_bytes(data.get(68..72)?.try_into().ok()?),
    })
}

fn dump(protocol: u8, family: u8, port: u16) -> Option<Vec<Diag>> {
    let socket = Socket::new(
        Domain::from(libc::AF_NETLINK),
        Type::RAW,
        Some(Protocol::from(NETLINK_SOCK_DIAG)),
    )
    .ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    (&socket).write_all(&request(family, protocol, port)).ok()?;

    let mut found = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = (&socket).read(&mut buf).ok()?;
        let mut rest = buf.get(..read)?;
        while rest.len() >= HEADER {
            let length = u32::from_ne_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let kind = u16::from_ne_bytes(rest.get(4..6)?.try_into().ok()?);
            if length < HEADER || length > rest.len() {
                break;
            }
            match kind {
                NLMSG_DONE => return Some(found),
                NLMSG_ERROR => return None,
                SOCK_DIAG_BY_FAMILY => {
                    found.extend(rest.get(HEADER..length).and_then(parse_diag));
                }
                _ => {}
            }
            rest = rest.get(length.next_multiple_of(4).min(rest.len())..)?;
        }
        if read == 0 {
            return Some(found);
        }
    }
}

fn sock_diag(network: Network, src: SocketAddr) -> Option<Diag> {
    let protocol = match network {
        Network::Tcp => libc::IPPROTO_TCP as u8,
        Network::Udp => libc::IPPROTO_UDP as u8,
    };
    let families: &[u8] = if src.is_ipv4() { &[2, 10] } else { &[10] };
    let wanted = src.ip();
    let mut wildcard = None;
    for &family in families {
        for diag in dump(protocol, family, src.port()).unwrap_or_default() {
            // A socket no process holds any more (TIME_WAIT, or closed and still finishing
            // its handshake) reports inode 0 and may share its port with a live connection.
            if diag.local.port() != src.port() || diag.inode == 0 {
                continue;
            }
            let ip = diag.local.ip();
            let same = match (ip, wanted) {
                (IpAddr::V6(v6), IpAddr::V4(v4)) => v6.to_ipv4_mapped() == Some(v4),
                _ => ip == wanted,
            };
            if same {
                return Some(diag);
            }
            if ip.is_unspecified() && wildcard.is_none() {
                wildcard = Some(diag);
            }
        }
    }
    wildcard
}

pub fn find_uid(network: Network, src: SocketAddr) -> Option<u32> {
    match sock_diag(network, src) {
        Some(diag) => Some(diag.uid),
        None => procnet::lookup(network, src, Match::Exact).map(|entry| entry.uid),
    }
}

#[cfg(target_os = "linux")]
fn socket_holder(inode: u64, uid: u32) -> Option<String> {
    let needle = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|text| text.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        if entry.metadata().map(|meta| meta.uid()).ok() != Some(uid) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let holds = fds
            .flatten()
            .filter_map(|fd| std::fs::read_link(fd.path()).ok())
            .any(|target| target.as_os_str().as_encoded_bytes() == needle.as_bytes());
        if holds {
            return std::fs::read_link(entry.path().join("exe"))
                .ok()
                .map(|exe| exe.to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub fn find(network: Network, src: SocketAddr) -> Option<ProcessInfo> {
    let (uid, inode) = match sock_diag(network, src) {
        Some(diag) => (diag.uid, u64::from(diag.inode)),
        None => {
            let entry = procnet::lookup(network, src, Match::Exact)?;
            (entry.uid, entry.inode)
        }
    };
    let path = socket_holder(inode, uid)?;
    let name = Path::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    Some(ProcessInfo {
        uid: Some(uid),
        name,
        path,
    })
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn the_request_is_a_dump_of_one_family() {
        let message = request(2, 6, 8080);
        assert_eq!(message.len(), 72);
        assert_eq!(u32::from_ne_bytes(message[..4].try_into().unwrap()), 72);
        assert_eq!(&message[16..20], &[2, 6, 0, 0]);
        assert_eq!(&message[24..26], &8080u16.to_be_bytes());
    }

    #[test]
    fn a_diag_message_is_decoded() {
        let mut data = vec![0u8; DIAG_MSG];
        data[0] = 2;
        data[4..6].copy_from_slice(&8080u16.to_be_bytes());
        data[8..12].copy_from_slice(&[10, 1, 2, 3]);
        data[64..68].copy_from_slice(&1000u32.to_ne_bytes());
        data[68..72].copy_from_slice(&4242u32.to_ne_bytes());
        assert_eq!(
            parse_diag(&data),
            Some(Diag {
                local: "10.1.2.3:8080".parse().unwrap(),
                uid: 1000,
                inode: 4242
            })
        );
        assert_eq!(parse_diag(&data[..40]), None);
    }

    #[test]
    fn a_listening_socket_belongs_to_this_uid() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let uid = std::fs::metadata("/proc/self").map(|meta| {
            use std::os::unix::fs::MetadataExt;
            meta.uid()
        });
        assert_eq!(
            find_uid(Network::Tcp, listener.local_addr().unwrap()),
            uid.ok()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn this_process_owns_its_listening_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let info = find(Network::Tcp, listener.local_addr().unwrap()).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(Path::new(&info.path).file_name(), exe.file_name());
        assert_eq!(info.name, exe.file_name().unwrap().to_string_lossy());
        assert_eq!(
            info.uid,
            Some(std::fs::metadata("/proc/self").unwrap().uid())
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_closed_socket_on_the_same_port_is_not_the_owner() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let reusable = || {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
            socket.set_reuse_address(true).unwrap();
            socket
        };
        let closed = reusable();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        closed.bind(&any.into()).unwrap();
        closed.connect(&first.local_addr().unwrap().into()).unwrap();
        let src = closed.local_addr().unwrap().as_socket().unwrap();
        let _peer = first.accept().unwrap();
        drop(closed);

        let live = reusable();
        live.bind(&src.into()).unwrap();
        live.connect(&second.local_addr().unwrap().into()).unwrap();

        let info = find(Network::Tcp, src).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(Path::new(&info.path).file_name(), exe.file_name());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn an_unresolvable_holder_leaves_no_owner() {
        assert_eq!(socket_holder(u64::MAX, u32::MAX), None);
    }
}
