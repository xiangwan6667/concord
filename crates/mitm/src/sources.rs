//! Surge's `client-source-address`: the clients whose connections are decrypted.

use std::net::IpAddr;

use concord_config::mitm::SourceEntryDef;
use ipnetwork::IpNetwork;

use crate::view::SourceEntryView;

/// Every client while it names none, as Surge leaves MITM on for all clients without the key;
/// an entry with `-` leaves its clients out whatever else names them.
#[derive(Debug, Default)]
pub(crate) struct SourceList {
    include: Vec<IpNetwork>,
    exclude: Vec<IpNetwork>,
}

impl SourceList {
    pub(crate) fn add(&mut self, entries: &[SourceEntryDef]) -> Vec<SourceEntryView> {
        entries
            .iter()
            .map(|entry| {
                let list = if entry.exclude {
                    &mut self.exclude
                } else {
                    &mut self.include
                };
                list.push(entry.network);
                SourceEntryView {
                    network: entry.network.to_string(),
                    exclude: entry.exclude,
                }
            })
            .collect()
    }

    /// The entries before a bad one stay added, and come back with its error.
    #[cfg(test)]
    pub(crate) fn add_line(
        &mut self,
        line: &str,
    ) -> (
        Vec<SourceEntryView>,
        Result<(), concord_config::mitm::LineError>,
    ) {
        let (entries, error) = concord_config::mitm::parse_source_line(line);
        (self.add(&entries), error.map_or(Ok(()), Err))
    }

    pub(crate) fn allows(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        !self.exclude.iter().any(|net| net.contains(ip))
            && (self.include.is_empty() || self.include.iter().any(|net| net.contains(ip)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(lines: &[&str]) -> SourceList {
        let mut list = SourceList::default();
        for line in lines {
            list.add_line(line).1.unwrap();
        }
        list
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn follows_surge_semantics() {
        assert!(list(&[]).allows(ip("10.0.0.1")));
        let surge = list(&["-192.168.1.2, 0.0.0.0/0"]);
        assert!(surge.allows(ip("192.168.1.3")));
        assert!(!surge.allows(ip("192.168.1.2")));
        assert!(!surge.allows(ip("::ffff:192.168.1.2")));
        assert!(!surge.allows(ip("2001:db8::1")), "only IPv4 is named");
        let skipped = list(&["-192.168.4.50", "-192.168.4.51"]);
        assert!(skipped.allows(ip("192.168.4.52")));
        assert!(!skipped.allows(ip("192.168.4.51")));
        let mut bad = SourceList::default();
        assert!(bad.add_line("192.168.1.0/24, lan").1.is_err());
    }
}
