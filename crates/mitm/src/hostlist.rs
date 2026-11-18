use concord_config::mitm::{HostEntryDef, LineError};

use crate::view::{HostEntryView, HostsView, LineView};

const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;

/// Surge's `[MITM] hostname`: entries match in order, so an exclusion has to
/// come before the wider entry it carves out of.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostList(Vec<HostEntryDef>);

impl HostList {
    pub fn parse(lines: &[String]) -> (HostList, Vec<String>) {
        let mut list = HostList::default();
        let mut errors = Vec::new();
        for line in lines {
            let (entries, line_errors) = parse_host_line(line);
            list.0.extend(entries.0);
            errors.extend(line_errors.into_iter().map(|err| format!("hostname {err}")));
        }
        (list, errors)
    }

    /// A bare entry covers 443, and 80, which Surge's HTTP engine rewrites without an entry.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.find(host, port, false)
    }

    /// Widens a bare entry to any port, as Surge does for a connection whose server
    /// name was read from its first bytes.
    pub fn matches_sniffed(&self, host: &str, port: u16) -> bool {
        self.find(host, port, true)
    }

    /// Whether the first entry that covers `host` on `port` carves it out.
    pub fn excludes(&self, host: &str, port: u16) -> bool {
        self.first(host, port, false)
            .is_some_and(|entry| entry.exclude)
    }

    pub fn includes_any(&self) -> bool {
        self.0.iter().any(|entry| !entry.exclude)
    }

    fn find(&self, host: &str, port: u16, sniffed: bool) -> bool {
        self.first(host, port, sniffed)
            .is_some_and(|entry| !entry.exclude)
    }

    fn first(&self, host: &str, port: u16, sniffed: bool) -> Option<&HostEntryDef> {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        self.0
            .iter()
            .find(|entry| covers(entry, port, sniffed) && glob(&entry.pattern, &host))
    }

    /// `None` while the list has no entry, as a line none of whose items could be read.
    pub(crate) fn view(&self) -> Option<LineView> {
        (!self.0.is_empty()).then(|| {
            LineView::Hosts(HostsView {
                entries: self
                    .0
                    .iter()
                    .map(|entry| HostEntryView {
                        host: entry.pattern.clone(),
                        port: (!entry.bare).then_some(entry.port),
                        exclude: entry.exclude,
                    })
                    .collect(),
            })
        })
    }

    pub(crate) fn extend(&mut self, other: HostList) {
        self.0.extend(other.0);
    }
}

fn covers(entry: &HostEntryDef, port: u16, sniffed: bool) -> bool {
    if entry.bare {
        return entry.exclude || sniffed || port == HTTPS_PORT || port == HTTP_PORT;
    }
    entry.port == 0 || entry.port == port
}

/// One error per bad item, naming it; the entries of the good items apply all the same.
pub(crate) fn parse_host_line(line: &str) -> (HostList, Vec<LineError>) {
    let (entries, errors) = concord_config::mitm::parse_host_line(line);
    (HostList(entries), errors)
}

impl From<Vec<HostEntryDef>> for HostList {
    fn from(entries: Vec<HostEntryDef>) -> HostList {
        HostList(entries)
    }
}

/// `*` and `?` over bytes; the name is already lower-case.
pub(crate) fn glob(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    let (mut p, mut n) = (0, 0);
    let mut star: Option<usize> = None;
    let mut mark = 0;
    while n < name.len() {
        match pattern.get(p) {
            Some(b'?') => {
                p += 1;
                n += 1;
            }
            Some(b'*') => {
                star = Some(p);
                mark = n;
                p += 1;
            }
            Some(&c) if c == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match star {
                Some(at) => {
                    p = at + 1;
                    mark += 1;
                    n = mark;
                }
                None => return false,
            },
        }
    }
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn follows_surge_semantics() {
        let (list, errors) = HostList::parse(&lines(&[
            "-skip.example.com",
            "*.example.com, api.other.com:8443",
            "all.ports.com:0",
            "[2001:db8::1]:443",
            "10.0.0.?",
        ]));
        assert!(errors.is_empty(), "{errors:?}");
        let cases = [
            ("a.example.com", 443, true),
            ("A.Example.COM.", 443, true),
            ("a.b.example.com", 443, true),
            ("example.com", 443, false),
            ("a.example.com", 80, true),
            ("a.example.com", 8443, false),
            ("skip.example.com", 443, false),
            ("skip.example.com", 80, false),
            ("api.other.com", 8443, true),
            ("api.other.com", 443, false),
            ("all.ports.com", 22, true),
            ("2001:db8::1", 443, true),
            ("10.0.0.7", 443, true),
            ("10.0.0.17", 443, false),
            ("", 443, false),
        ];
        for (host, port, want) in cases {
            assert_eq!(list.matches(host, port), want, "{host}:{port}");
        }
    }

    #[test]
    fn order_decides() {
        let (list, _) = HostList::parse(&lines(&["*", "-a.com"]));
        assert!(list.matches("a.com", 443));
    }

    #[test]
    fn sniffed_widens_bare_entries() {
        let (list, _) = HostList::parse(&lines(&["a.com"]));
        assert!(!list.matches("a.com", 8080));
        assert!(list.matches_sniffed("a.com", 8080));
    }

    #[test]
    fn reports_bad_entries() {
        let (list, errors) = HostList::parse(&lines(&[
            "good.com",
            "bad host.com",
            "x.com:99999",
            "<ip-address>",
            "[::1",
        ]));
        assert_eq!(errors.len(), 4, "{errors:?}");
        assert!(list.matches("good.com", 443));
        assert_eq!(
            errors.first().map(String::as_str),
            Some("hostname \"bad host.com\": unsupported character ' '")
        );
    }

    #[test]
    fn glob_cases() {
        let cases = [
            ("*", "anything.at.all", true),
            ("*.a.com", "x.a.com", true),
            ("*.a.com", "a.com", false),
            ("a*c", "abbbc", true),
            ("a*c", "abbbd", false),
            ("?.a.com", "x.a.com", true),
            ("?.a.com", "xy.a.com", false),
            ("*x*y*", "1x2y3", true),
        ];
        for (pattern, name, want) in cases {
            assert_eq!(glob(pattern, name), want, "{pattern} {name}");
        }
    }
}
