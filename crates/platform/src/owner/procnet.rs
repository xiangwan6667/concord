use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use concord_common::Network;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcNetEntry {
    pub local: SocketAddr,
    pub uid: u32,
    pub inode: u64,
}

/// `Loose` also accepts a socket that merely shares the port, which is what an
/// Android VPN needs when the flow's source is not the socket's own address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    Exact,
    Loose,
}

fn parse_v4(hex: &str) -> Option<IpAddr> {
    if hex.len() != 8 {
        return None;
    }
    let word = u32::from_str_radix(hex, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes())))
}

fn parse_v6(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (chunk, word_hex) in octets.chunks_mut(4).zip(hex.as_bytes().chunks(8)) {
        let word = u32::from_str_radix(std::str::from_utf8(word_hex).ok()?, 16).ok()?;
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

/// The kernel prints addresses as native-endian words, so the column positions
/// of `local_address`, `uid` and `inode` are fixed for the tcp and udp tables.
pub fn parse_table(text: &str, ipv6: bool) -> Vec<ProcNetEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (local, uid, inode) = (fields.get(1)?, fields.get(7)?, fields.get(9)?);
            let (addr, port) = local.split_once(':')?;
            let ip = if ipv6 {
                parse_v6(addr)?
            } else {
                parse_v4(addr)?
            };
            Some(ProcNetEntry {
                local: SocketAddr::new(ip, u16::from_str_radix(port, 16).ok()?),
                uid: uid.parse().ok()?,
                inode: inode.parse().ok()?,
            })
        })
        .collect()
}

fn mapped_or_equal(found: IpAddr, wanted: IpAddr) -> bool {
    match (found, wanted) {
        (IpAddr::V6(v6), IpAddr::V4(v4)) => v6.to_ipv4_mapped() == Some(v4),
        _ => found == wanted,
    }
}

pub fn select(entries: &[ProcNetEntry], src: SocketAddr, how: Match) -> Option<ProcNetEntry> {
    // A TIME_WAIT row carries neither an inode nor a uid and may share its port with a live
    // connection.
    let same_port = entries
        .iter()
        .filter(|entry| entry.local.port() == src.port() && (entry.inode != 0 || entry.uid != 0));
    let exact = same_port
        .clone()
        .find(|entry| mapped_or_equal(entry.local.ip(), src.ip()));
    let wildcard = || {
        same_port
            .clone()
            .find(|entry| entry.local.ip().is_unspecified())
    };
    let loose = || {
        let candidates = same_port.clone().filter(|entry| entry.inode != 0);
        candidates
            .clone()
            .find(|entry| entry.uid != 0)
            .or_else(|| candidates.clone().next())
    };
    match how {
        Match::Exact => exact.or_else(wildcard),
        Match::Loose => exact.or_else(wildcard).or_else(loose),
    }
    .copied()
}

pub fn lookup(network: Network, src: SocketAddr, how: Match) -> Option<ProcNetEntry> {
    let proto = network.as_str();
    let tables: &[(&str, bool)] = if src.is_ipv4() {
        &[("", false), ("6", true)]
    } else {
        &[("6", true)]
    };
    let mut best = None;
    for (suffix, ipv6) in tables {
        let Ok(text) = std::fs::read_to_string(format!("/proc/net/{proto}{suffix}")) else {
            continue;
        };
        let entries = parse_table(&text, *ipv6);
        if let Some(found) = select(&entries, src, Match::Exact) {
            return Some(found);
        }
        if best.is_none() && how == Match::Loose {
            best = select(&entries, src, Match::Loose);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
        0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0 100 0\n\
        1: 0201A8C0:C350 0101A8C0:01BB 01 00000000:00000000 02:000A7F10 00000000     0        0 22222 2 0 20 4\n\
        2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000   123        0 33333 1 0 100 0\n\
        bad line\n";

    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
        0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 44444 1 0 100 0\n\
        1: 0000000000000000FFFF00000100007F:2710 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1002        0 55555 1 0 100 0\n";

    #[test]
    fn ipv4_rows_decode_in_native_order() {
        let entries = parse_table(TCP, false);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].local, "127.0.0.1:8080".parse().unwrap());
        assert_eq!((entries[0].uid, entries[0].inode), (1000, 11111));
        assert_eq!(entries[1].local, "192.168.1.2:50000".parse().unwrap());
    }

    #[test]
    fn ipv6_rows_decode_and_mapped_addresses_match_ipv4() {
        let entries = parse_table(TCP6, true);
        assert_eq!(entries[0].local, "[::1]:8080".parse().unwrap());
        let v4: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        assert_eq!(
            select(&entries, v4, Match::Exact).map(|e| e.uid),
            Some(1002)
        );
    }

    #[test]
    fn exact_beats_wildcard_and_loose_adds_port_only_matches() {
        let entries = parse_table(TCP, false);
        let exact: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            select(&entries, exact, Match::Exact).map(|e| e.uid),
            Some(1000)
        );

        let wildcard: SocketAddr = "10.9.9.9:80".parse().unwrap();
        assert_eq!(
            select(&entries, wildcard, Match::Exact).map(|e| e.uid),
            Some(123)
        );

        let other_ip: SocketAddr = "10.9.9.9:8080".parse().unwrap();
        assert_eq!(select(&entries, other_ip, Match::Exact), None);
        assert_eq!(
            select(&entries, other_ip, Match::Loose).map(|e| e.uid),
            Some(1000)
        );
    }

    #[test]
    fn a_time_wait_row_on_the_same_address_is_skipped() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
            0: 0100007F:C350 0200007F:1F90 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0\n\
            1: 0100007F:C350 0300007F:1F91 01 00000000:00000000 00:00000000 00000000  1000        0 77777 1 0 20 4\n";
        let entries = parse_table(table, false);
        let src: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        assert_eq!(
            select(&entries, src, Match::Exact).map(|e| (e.uid, e.inode)),
            Some((1000, 77777))
        );
    }
}
