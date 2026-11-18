//! The payload text a connection record shows for a rule.

use concord_config::rule::{Cond, NetworkKind, RuleDef, UidRange};

use crate::kind::RuleKind;

const COMMA_IN_PAYLOAD: &[&str] = &[
    "NOT",
    "OR",
    "AND",
    "SUB-RULE",
    "DOMAIN-REGEX",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH-REGEX",
];

/// The payload field of a rule line, split the way mihomo splits it.
pub(crate) fn raw_payload(text: &str) -> String {
    let items: Vec<&str> = text.split(',').map(|part| part.trim_matches(' ')).collect();
    let Some(first) = items.first() else {
        return String::new();
    };
    let kind = first.to_uppercase();
    if items.len() < 2 || kind == "MATCH" {
        return String::new();
    }
    if COMMA_IN_PAYLOAD.contains(&kind.as_str()) {
        let end = items.len() - 1;
        return items.get(1..end).unwrap_or_default().join(",");
    }
    items.get(1).copied().unwrap_or_default().to_string()
}

fn uids(list: &[UidRange]) -> String {
    list.iter()
        .map(|r| {
            if r.start == r.end {
                r.start.to_string()
            } else {
                format!("{}-{}", r.start, r.end)
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn part(cond: &Cond) -> String {
    format!(
        "({},{})",
        RuleKind::of(cond, false).name(),
        cond_payload(cond)
    )
}

/// The payload of a condition that has no rule line of its own: a child of a
/// logic rule.
pub(crate) fn cond_payload(cond: &Cond) -> String {
    match cond {
        Cond::Domain(p)
        | Cond::DomainSuffix(p)
        | Cond::DomainKeyword(p)
        | Cond::GeoIp(p)
        | Cond::SrcGeoIp(p) => p.to_lowercase(),
        Cond::DomainRegex(p)
        | Cond::DomainWildcard(p)
        | Cond::GeoSite(p)
        | Cond::IpAsn(p)
        | Cond::SrcIpAsn(p)
        | Cond::ProcessName(p)
        | Cond::ProcessPath(p)
        | Cond::ProcessNameRegex(p)
        | Cond::ProcessPathRegex(p)
        | Cond::ProcessNameWildcard(p)
        | Cond::ProcessPathWildcard(p)
        | Cond::RuleSet(p) => p.clone(),
        Cond::IpCidr(c)
        | Cond::IpCidr6(c)
        | Cond::SrcIpCidr(c)
        | Cond::IpSuffix(c)
        | Cond::SrcIpSuffix(c) => c.to_string(),
        Cond::SrcPort(r) | Cond::DstPort(r) | Cond::InPort(r) | Cond::Dscp(r) => r.text.clone(),
        Cond::Network(NetworkKind::Tcp) => "tcp".to_string(),
        Cond::Network(NetworkKind::Udp) => "udp".to_string(),
        Cond::Uid(r) => uids(r),
        Cond::InType(list) | Cond::InUser(list) | Cond::InName(list) | Cond::RematchName(list) => {
            list.join("/")
        }
        Cond::And(children) => logic(children, " && "),
        Cond::Or(children) => logic(children, " || "),
        Cond::Not(child) => format!("(!{})", part(child)),
        Cond::SubRule(child) => part(child),
        Cond::Match => String::new(),
        Cond::Flagged { cond, .. } => cond_payload(cond),
    }
}

fn logic(children: &[Cond], separator: &str) -> String {
    let parts: Vec<String> = children.iter().map(part).collect();
    format!("({})", parts.join(separator))
}

/// What `Payload()` returns for a top-level rule.
pub(crate) fn rule_payload(def: &RuleDef) -> String {
    let raw = raw_payload(&def.text);
    match &def.cond {
        Cond::Domain(_) | Cond::DomainSuffix(_) | Cond::DomainKeyword(_) => raw.to_lowercase(),
        Cond::GeoIp(_) | Cond::SrcGeoIp(_) => raw.to_lowercase(),
        Cond::InType(_) => raw.to_uppercase(),
        Cond::DomainWildcard(p) => p.clone(),
        Cond::IpCidr(c) | Cond::IpCidr6(c) | Cond::SrcIpCidr(c) => c.to_string(),
        Cond::Network(_) | Cond::And(_) | Cond::Or(_) | Cond::Not(_) | Cond::Match => {
            cond_payload(&def.cond)
        }
        _ if raw.is_empty() => cond_payload(&def.cond),
        _ => raw,
    }
}

#[cfg(test)]
mod tests {
    use concord_config::rule::parse_rule;

    use super::*;

    fn payload(line: &str) -> String {
        rule_payload(&parse_rule(line).unwrap())
    }

    #[test]
    fn leaf_payloads_follow_mihomo() {
        assert_eq!(payload("DOMAIN,Example.COM,PROXY"), "example.com");
        assert_eq!(payload("GEOIP,CN,DIRECT,no-resolve"), "cn");
        assert_eq!(payload("GEOSITE,Category-Ads,REJECT"), "Category-Ads");
        assert_eq!(payload("IP-CIDR,192.168.1.5/24,DIRECT"), "192.168.1.5/24");
        assert_eq!(payload("IP-SUFFIX,0.0.0.1/8,DIRECT"), "0.0.0.1/8");
        assert_eq!(payload("DST-PORT,80/443,PROXY"), "80/443");
        assert_eq!(payload("NETWORK,UDP,DIRECT"), "udp");
        assert_eq!(payload("IN-TYPE,http/socks,DIRECT"), "HTTP/SOCKS");
        assert_eq!(
            payload("DOMAIN-REGEX,^a{1,3}\\.com$,DIRECT"),
            "^a{1,3}\\.com$"
        );
        assert_eq!(payload("RULE-SET,ads,REJECT"), "ads");
        assert_eq!(payload("MATCH,PROXY"), "");
        assert_eq!(payload("PROCESS-NAME,Curl,DIRECT"), "Curl");
    }

    #[test]
    fn logic_payloads_nest() {
        assert_eq!(
            payload("AND,((DOMAIN,baidu.com),(NETWORK,UDP)),DIRECT"),
            "((Domain,baidu.com) && (Network,udp))"
        );
        assert_eq!(
            payload("OR,((DOMAIN,a.com),(AND,((DOMAIN-KEYWORD,b),(NOT,((GEOIP,CN)))))),PROXY"),
            "((Domain,a.com) || (AND,((DomainKeyword,b) && (NOT,(!(GeoIP,cn))))))"
        );
        assert_eq!(payload("NOT,((DOMAIN,x.com)),REJECT"), "(!(Domain,x.com))");
    }

    #[test]
    fn sub_rule_keeps_its_condition_text() {
        assert_eq!(payload("SUB-RULE,(NETWORK,tcp),inner"), "(NETWORK,tcp)");
    }
}
