use super::ranges::{auto_route_ranges, excluded_uids};
use super::{Family, IfaceInfo, Plan, RouteSpec, RuleAction, RuleSpec, Step};
use crate::options::{Prefix, TunOptions};

/// Policy-routing plan of sing-tun on Linux: default routes in a private table, selected by
/// rules that keep loopback, the interface itself, excluded uids, ports and interfaces out.
pub fn plan_linux(options: &TunOptions, iface: &IfaceInfo) -> Plan {
    plan(options, iface, false)
}

/// The same plan for a device a privileged process opens on Android. There is no resolvectl: DNS
/// reaches the device by route like any other traffic.
pub fn plan_android(options: &TunOptions, iface: &IfaceInfo) -> Plan {
    plan(options, iface, true)
}

fn plan(options: &TunOptions, iface: &IfaceInfo, android: bool) -> Plan {
    let start = options.iproute2_rule_index;
    let mut plan = Plan {
        stale_rule_priorities: Some((start, start + 10)),
        ..Plan::default()
    };
    if !options.auto_route {
        plan.steps.extend(
            rules(options, &iface.name, android)
                .into_iter()
                .map(Step::Rule),
        );
        return plan;
    }
    plan.steps.push(Step::RpFilter {
        ifname: iface.name.clone(),
    });
    // sing-tun's `Inet4GatewayAddr`/`Inet6GatewayAddr` give no gateway on Android, where netd's tables
    // cannot resolve one for table 2022.
    let gateway = |addresses: &[Prefix]| {
        (!android)
            .then(|| addresses.first().and_then(Prefix::next_host))
            .flatten()
    };
    for dest in auto_route_ranges(options, false) {
        let gateway = if dest.is_ipv4() {
            gateway(&options.inet4_address)
        } else {
            gateway(&options.inet6_address)
        };
        plan.steps.push(Step::Route(RouteSpec {
            dest,
            gateway,
            if_index: iface.index,
            table: Some(options.iproute2_table_index),
        }));
    }
    let p4 = !options.inet4_address.is_empty();
    if android && (p4 || !options.inet6_address.is_empty()) {
        let defaults = ["0.0.0.0/0", "::/0"]
            .into_iter()
            .filter(|dest| p4 || dest.contains(':'))
            .filter_map(Prefix::parse);
        for dest in defaults {
            plan.steps.push(Step::Route(RouteSpec {
                dest,
                gateway: None,
                if_index: iface.index,
                table: Some(dns_table(options)),
            }));
        }
    }
    plan.steps.extend(
        rules(options, &iface.name, android)
            .into_iter()
            .map(Step::Rule),
    );
    let servers: Vec<_> = [&options.inet4_address, &options.inet6_address]
        .into_iter()
        .filter_map(|addresses| addresses.first().and_then(Prefix::next_host))
        .collect();
    if !servers.is_empty() && !android {
        plan.steps.push(Step::Dns {
            ifname: iface.name.clone(),
            servers,
        });
    }
    if options.strict_route
        && (options.inet4_address.is_empty() || options.inet6_address.is_empty())
    {
        plan.warnings.push(
            "strict-route blocks the family without a tun address with unreachable rules".into(),
        );
    }
    plan
}

struct Cursor {
    p4: bool,
    p6: bool,
    v4: u32,
    v6: u32,
    nop: u32,
    rules: Vec<RuleSpec>,
}

impl Cursor {
    fn push(&mut self, family: Family, action: RuleAction, build: impl FnOnce(&mut RuleSpec)) {
        let priority = if family == Family::V4 {
            self.v4
        } else {
            self.v6
        };
        let mut rule = RuleSpec::new(family, priority, action);
        build(&mut rule);
        self.rules.push(rule);
    }

    fn both(&mut self, action: RuleAction, build: impl Fn(&mut RuleSpec)) {
        if self.p4 {
            self.push(Family::V4, action, &build);
        }
        if self.p6 {
            self.push(Family::V6, action, &build);
        }
    }

    fn next(&mut self) {
        if self.p4 {
            self.v4 += 1;
        }
        if self.p6 {
            self.v6 += 1;
        }
    }
}

/// Android's system resolver usually sits on the LAN, which a route address that leaves private
/// ranges out keeps off the private table: queries leave the device unhijacked and come back with
/// addresses the core never handed out. sing-tun keeps DNS off `main` with the rule this chain
/// skips; here port 53 gets a table of its own that only holds the device, in both families
/// even when the device has no IPv6 address, as a `VpnService` takes every system query.
pub(crate) fn dns_table(options: &TunOptions) -> u32 {
    options.iproute2_table_index + 1
}

/// The routing tables a privileged Android device fills.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn android_tables(options: &TunOptions) -> [u32; 2] {
    [options.iproute2_table_index, dns_table(options)]
}

pub fn rules_for(options: &TunOptions, name: &str) -> Vec<RuleSpec> {
    rules(options, name, false)
}

/// sing-tun's chain under `runtime.GOOS == "android"`: without the rules ahead of the loopback ones,
/// since Android routes through netd's per-network tables and leaves `main` nearly empty, and with
/// an IPv6 rule for the unspecified source like the IPv4 one.
pub fn rules_for_android(options: &TunOptions, name: &str) -> Vec<RuleSpec> {
    rules(options, name, true)
}

fn rules(options: &TunOptions, name: &str, android: bool) -> Vec<RuleSpec> {
    let table = options.iproute2_table_index;
    let (p4, p6) = (
        !options.inet4_address.is_empty(),
        !options.inet6_address.is_empty(),
    );
    if !options.auto_route {
        if !p6 {
            return Vec::new();
        }
        let mut rule = RuleSpec::new(
            Family::V6,
            options.iproute2_rule_index,
            RuleAction::Table(table),
        );
        rule.oif = Some(name.to_owned());
        return vec![rule];
    }
    if !p4 && !p6 {
        return Vec::new();
    }
    let dns6 = android && !p6;
    let start = options.iproute2_rule_index;
    let mut cur = Cursor {
        p4,
        p6: p6 || dns6,
        v4: start,
        v6: start,
        nop: start + 10,
        rules: Vec::new(),
    };
    let nop = cur.nop;

    let uids = excluded_uids(&options.include_uid, &options.exclude_uid);
    let mut grouped = false;
    for range in &uids {
        cur.both(RuleAction::Goto(nop), |rule| {
            rule.uid_range = Some((range.start, range.end));
        });
        grouped = true;
    }
    for range in &options.exclude_src_port {
        cur.both(RuleAction::Goto(nop), |rule| {
            rule.sport = Some((range.start as u16, range.end as u16));
        });
        grouped = true;
    }
    for range in &options.exclude_dst_port {
        cur.both(RuleAction::Goto(nop), |rule| {
            rule.dport = Some((range.start as u16, range.end as u16));
        });
        grouped = true;
    }
    if grouped {
        cur.next();
    }

    if !options.include_interface.is_empty() {
        let (match4, match6) = (cur.v4 + 2, cur.v6 + 2);
        for iface in &options.include_interface {
            if p4 {
                cur.push(Family::V4, RuleAction::Goto(match4), |rule| {
                    rule.iif = Some(iface.clone());
                });
            }
            if p6 {
                cur.push(Family::V6, RuleAction::Goto(match6), |rule| {
                    rule.iif = Some(iface.clone());
                });
            }
        }
        cur.next();
        if p4 {
            cur.push(Family::V4, RuleAction::Goto(nop), |_| {});
            cur.v4 += 1;
            cur.push(Family::V4, RuleAction::Nop, |_| {});
            cur.v4 += 1;
        }
        if p6 {
            cur.push(Family::V6, RuleAction::Goto(nop), |_| {});
            cur.v6 += 1;
            cur.push(Family::V6, RuleAction::Nop, |_| {});
            cur.v6 += 1;
        }
    } else if !options.exclude_interface.is_empty() {
        for iface in &options.exclude_interface {
            cur.both(RuleAction::Goto(nop), |rule| rule.iif = Some(iface.clone()));
        }
        cur.next();
    }

    if options.strict_route {
        if !p4 {
            cur.push(Family::V4, RuleAction::Unreachable, |_| {});
            cur.v4 += 1;
        }
        if !p6 {
            cur.push(Family::V6, RuleAction::Unreachable, |_| {});
            cur.v6 += 1;
        }
    }

    if !android {
        main_table_rules(&mut cur, options, table);
    }

    let loopback = |rule: &mut RuleSpec| rule.iif = Some("lo".to_owned());
    let dns = |rule: &mut RuleSpec| {
        loopback(rule);
        rule.dport = Some((53, 53));
    };
    if p4 {
        cur.push(Family::V4, RuleAction::Goto(nop), |rule| {
            rule.iif = Some(name.to_owned());
        });
        cur.v4 += 1;
        if android {
            cur.push(Family::V4, RuleAction::Table(dns_table(options)), dns);
        }
        cur.push(Family::V4, RuleAction::Table(table), |rule| {
            rule.invert = true;
            loopback(rule);
        });
        cur.push(Family::V4, RuleAction::Table(table), |rule| {
            loopback(rule);
            rule.src = Prefix::parse("0.0.0.0/32");
        });
        for address in &options.inet4_address {
            cur.push(Family::V4, RuleAction::Table(table), |rule| {
                loopback(rule);
                rule.src = Some(address.masked());
            });
        }
    }
    if p6 {
        cur.push(Family::V6, RuleAction::Goto(nop), |rule| {
            rule.iif = Some(name.to_owned());
        });
        cur.v6 += 1;
        if android {
            cur.push(Family::V6, RuleAction::Table(dns_table(options)), dns);
        }
        for address in &options.inet6_address {
            cur.push(Family::V6, RuleAction::Table(table), |rule| {
                loopback(rule);
                rule.src = Some(address.masked());
            });
        }
        // sing-tun relies on the skipped suppress rule for an unbound socket's lookup, which on
        // Android would let every local IPv6 connection fall past the halves below to netd.
        if android {
            cur.push(Family::V6, RuleAction::Table(table), |rule| {
                loopback(rule);
                rule.src = Prefix::parse("::/128");
            });
        }
        cur.v6 += 1;
        for half in ["::/1", "8000::/1"] {
            cur.push(Family::V6, RuleAction::Goto(nop), |rule| {
                loopback(rule);
                rule.src = Prefix::parse(half);
            });
        }
        cur.v6 += 1;
        cur.push(Family::V6, RuleAction::Table(table), |_| {});
    } else if dns6 {
        cur.push(Family::V6, RuleAction::Goto(nop), |rule| {
            rule.iif = Some(name.to_owned());
        });
        cur.v6 += 1;
        cur.push(Family::V6, RuleAction::Table(dns_table(options)), dns);
    }
    if p4 {
        cur.rules
            .push(RuleSpec::new(Family::V4, nop, RuleAction::Nop));
    }
    if p6 || dns6 {
        cur.rules
            .push(RuleSpec::new(Family::V6, nop, RuleAction::Nop));
    }
    cur.rules
}

fn main_table_rules(cur: &mut Cursor, options: &TunOptions, table: u32) {
    if cur.p4 {
        for address in &options.inet4_address {
            cur.push(Family::V4, RuleAction::Table(table), |rule| {
                rule.dst = Some(address.masked());
            });
        }
        cur.v4 += 1;
        cur.push(Family::V4, RuleAction::Table(table), |rule| {
            rule.suppress_prefixlen = Some(0);
        });
        cur.v4 += 1;
    }
    if cur.p6 {
        cur.push(Family::V6, RuleAction::Table(table), |rule| {
            rule.suppress_prefixlen = Some(0);
        });
        cur.v6 += 1;
    }
    cur.both(RuleAction::Table(254), |rule| {
        rule.invert = true;
        rule.dport = Some((53, 53));
        rule.suppress_prefixlen = Some(0);
    });
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use netlink::NetlinkBackend;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod netlink {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use async_trait::async_trait;
    use futures_util::TryStreamExt;
    use rtnetlink::packet_route::AddressFamily;
    use rtnetlink::packet_route::route::{RouteAttribute, RouteMessage};
    use rtnetlink::packet_route::rule::{
        RuleAction as NlAction, RuleAttribute, RuleFlags, RuleMessage, RulePortRange, RuleUidRange,
    };
    use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};
    use tokio::task::JoinHandle;

    use super::super::{Family, Op, RouteBackend, RouteSpec, RuleAction, RuleSpec, Step};

    pub struct NetlinkBackend {
        handle: Handle,
        connection: JoinHandle<()>,
    }

    impl NetlinkBackend {
        pub fn connect() -> io::Result<Self> {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            Ok(NetlinkBackend {
                handle,
                connection: tokio::spawn(connection),
            })
        }
    }

    impl NetlinkBackend {
        /// Gives a device its MTU and addresses and brings it up, as sing-tun's `configure`.
        pub async fn bring_up(
            &self,
            index: u32,
            mtu: u32,
            addresses: &[(IpAddr, u8)],
        ) -> io::Result<()> {
            let link = || rtnetlink::LinkUnspec::new_with_index(index);
            self.handle
                .link()
                .set(link().mtu(mtu).build())
                .execute()
                .await
                .map_err(nl_error)?;
            for &(address, length) in addresses {
                match self
                    .handle
                    .address()
                    .add(index, address, length)
                    .execute()
                    .await
                {
                    Err(rtnetlink::Error::NetlinkError(message))
                        if message.raw_code().abs() == libc::EEXIST => {}
                    other => other.map_err(nl_error)?,
                }
            }
            self.handle
                .link()
                .set(link().up().build())
                .execute()
                .await
                .map_err(nl_error)
        }

        /// Deletes every route in `tables`, in both families; the count of deleted routes.
        pub async fn flush_tables(&self, tables: &[u32]) -> io::Result<usize> {
            let mut removed = 0;
            let dumps = [
                RouteMessageBuilder::<Ipv4Addr>::new().build(),
                RouteMessageBuilder::<Ipv6Addr>::new().build(),
            ];
            for dump in dumps {
                let routes: Vec<RouteMessage> = self
                    .handle
                    .route()
                    .get(dump)
                    .execute()
                    .try_collect()
                    .await
                    .map_err(nl_error)?;
                for route in routes {
                    let table = route
                        .attributes
                        .iter()
                        .find_map(|attribute| match attribute {
                            RouteAttribute::Table(table) => Some(*table),
                            _ => None,
                        })
                        .unwrap_or_else(|| u32::from(route.header.table));
                    if tables.contains(&table)
                        && self.handle.route().del(route).execute().await.is_ok()
                    {
                        removed += 1;
                    }
                }
            }
            Ok(removed)
        }

        pub async fn delete_link(&self, index: u32) -> io::Result<()> {
            self.handle
                .link()
                .del(index)
                .execute()
                .await
                .map_err(nl_error)
        }
    }

    impl Drop for NetlinkBackend {
        fn drop(&mut self) {
            self.connection.abort();
        }
    }

    fn nl_error(err: rtnetlink::Error) -> io::Error {
        match err {
            rtnetlink::Error::NetlinkError(message) => {
                io::Error::from_raw_os_error(message.raw_code().abs())
            }
            other => io::Error::other(other),
        }
    }

    pub(super) fn rule_message(rule: &RuleSpec) -> RuleMessage {
        let mut message = RuleMessage::default();
        message.header.family = match rule.family {
            Family::V4 => AddressFamily::Inet,
            Family::V6 => AddressFamily::Inet6,
        };
        message.header.action = match rule.action {
            RuleAction::Table(_) => NlAction::ToTable,
            RuleAction::Goto(_) => NlAction::Goto,
            RuleAction::Nop => NlAction::Nop,
            RuleAction::Unreachable => NlAction::Unreachable,
        };
        if rule.invert {
            message.header.flags |= RuleFlags::Invert;
        }
        if let Some(dst) = rule.dst {
            message.header.dst_len = dst.len();
            message
                .attributes
                .push(RuleAttribute::Destination(dst.addr()));
        }
        if let Some(src) = rule.src {
            message.header.src_len = src.len();
            message.attributes.push(RuleAttribute::Source(src.addr()));
        }
        let attributes = &mut message.attributes;
        attributes.push(RuleAttribute::Priority(rule.priority));
        match rule.action {
            RuleAction::Table(table) => {
                if table < 256 {
                    message.header.table = table as u8;
                }
                attributes.push(RuleAttribute::Table(table));
                if let Some(length) = rule.suppress_prefixlen {
                    attributes.push(RuleAttribute::SuppressPrefixLen(length));
                }
            }
            RuleAction::Goto(target) => attributes.push(RuleAttribute::Goto(target)),
            RuleAction::Nop | RuleAction::Unreachable => {}
        }
        if let Some(name) = &rule.iif {
            attributes.push(RuleAttribute::Iifname(name.clone()));
        }
        if let Some(name) = &rule.oif {
            attributes.push(RuleAttribute::Oifname(name.clone()));
        }
        if let Some((start, end)) = rule.dport {
            attributes.push(RuleAttribute::DestinationPortRange(RulePortRange {
                start,
                end,
            }));
        }
        if let Some((start, end)) = rule.sport {
            attributes.push(RuleAttribute::SourcePortRange(RulePortRange { start, end }));
        }
        if let Some((start, end)) = rule.uid_range {
            attributes.push(RuleAttribute::UidRange(RuleUidRange { start, end }));
        }
        message
    }

    fn route_message(spec: &RouteSpec) -> RouteMessage {
        let prefix = spec.dest;
        match prefix.addr() {
            IpAddr::V4(dest) => {
                let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(dest, prefix.len())
                    .output_interface(spec.if_index);
                if let Some(IpAddr::V4(gateway)) = spec.gateway {
                    builder = builder.gateway(gateway);
                }
                if let Some(table) = spec.table {
                    builder = builder.table_id(table);
                }
                builder.build()
            }
            IpAddr::V6(dest) => {
                let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(dest, prefix.len())
                    .output_interface(spec.if_index);
                if let Some(IpAddr::V6(gateway)) = spec.gateway {
                    builder = builder.gateway(gateway);
                }
                if let Some(table) = spec.table {
                    builder = builder.table_id(table);
                }
                builder.build()
            }
        }
    }

    async fn run(program: &str, args: &[&str]) -> io::Result<()> {
        let status = tokio::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await?;
        status.success().then_some(()).ok_or_else(|| {
            io::Error::other(format!("{program} {} failed: {status}", args.join(" ")))
        })
    }

    fn resolvectl_present() -> bool {
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|dir| dir.join("resolvectl").is_file())
        })
    }

    async fn dns(op: Op, ifname: &str, servers: &[IpAddr]) -> io::Result<()> {
        if !resolvectl_present() {
            return Ok(());
        }
        match op {
            Op::Add => {
                run("resolvectl", &["domain", ifname, "~."]).await?;
                run("resolvectl", &["default-route", ifname, "true"]).await?;
                let mut args = vec!["dns".to_owned(), ifname.to_owned()];
                args.extend(servers.iter().map(ToString::to_string));
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                run("resolvectl", &refs).await
            }
            Op::Delete => run("resolvectl", &["revert", ifname]).await,
        }
    }

    fn rp_filter(ifname: &str) -> io::Result<()> {
        let read = |path: String| -> Option<i32> {
            std::fs::read_to_string(path).ok()?.trim().parse().ok()
        };
        let effective = read("/proc/sys/net/ipv4/conf/all/rp_filter".into())
            .into_iter()
            .chain(read(format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter")))
            .max()
            .unwrap_or(0);
        if effective == 1 {
            std::fs::write(format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"), "2")?;
        }
        Ok(())
    }

    #[async_trait]
    impl RouteBackend for NetlinkBackend {
        async fn apply(&mut self, op: Op, step: &Step) -> io::Result<()> {
            match (op, step) {
                (Op::Add, Step::Route(route)) => self
                    .handle
                    .route()
                    .add(route_message(route))
                    .replace()
                    .execute()
                    .await
                    .map_err(nl_error),
                (Op::Delete, Step::Route(route)) => self
                    .handle
                    .route()
                    .del(route_message(route))
                    .execute()
                    .await
                    .map_err(nl_error),
                (Op::Add, Step::Rule(rule)) => {
                    let mut request = self.handle.rule().add();
                    *request.message_mut() = rule_message(rule);
                    request.execute().await.map_err(nl_error)
                }
                (Op::Delete, Step::Rule(rule)) => self
                    .handle
                    .rule()
                    .del(rule_message(rule))
                    .execute()
                    .await
                    .map_err(nl_error),
                (op, Step::Dns { ifname, servers }) => dns(op, ifname, servers).await,
                (Op::Add, Step::RpFilter { ifname }) => rp_filter(ifname),
                (Op::Delete, Step::RpFilter { .. }) | (_, Step::StrictRoute(_)) => Ok(()),
            }
        }

        async fn clean_stale(&mut self, priorities: (u32, u32)) -> io::Result<usize> {
            let mut removed = 0;
            for version in [IpVersion::V4, IpVersion::V6] {
                let rules: Vec<RuleMessage> = self
                    .handle
                    .rule()
                    .get(version)
                    .execute()
                    .try_collect()
                    .await
                    .map_err(nl_error)?;
                for rule in rules {
                    let priority = rule
                        .attributes
                        .iter()
                        .find_map(|attribute| match attribute {
                            RuleAttribute::Priority(value) => Some(*value),
                            _ => None,
                        });
                    if priority.is_some_and(|value| (priorities.0..=priorities.1).contains(&value))
                        && self.handle.rule().del(rule).execute().await.is_ok()
                    {
                        removed += 1;
                    }
                }
            }
            Ok(removed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::IdRange;

    fn p(text: &str) -> Prefix {
        Prefix::parse(text).unwrap()
    }

    fn options() -> TunOptions {
        TunOptions {
            auto_route: true,
            inet4_address: vec![p("198.18.0.1/30")],
            inet6_address: vec![p("fdfe:dcba:9876::1/126")],
            ..TunOptions::default()
        }
    }

    fn iface() -> IfaceInfo {
        IfaceInfo {
            name: "tun0".into(),
            index: 7,
        }
    }

    fn of(rules: &[RuleSpec], family: Family) -> Vec<&RuleSpec> {
        rules.iter().filter(|rule| rule.family == family).collect()
    }

    #[test]
    fn default_plan_routes_both_families_through_the_private_table() {
        let plan = plan_linux(&options(), &iface());
        assert_eq!(plan.stale_rule_priorities, Some((9000, 9010)));
        let routes: Vec<_> = plan
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Route(route) => Some(route),
                _ => None,
            })
            .collect();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].dest, p("0.0.0.0/0"));
        assert_eq!(routes[0].gateway, Some("198.18.0.2".parse().unwrap()));
        assert_eq!(routes[0].table, Some(2022));
        assert_eq!(
            routes[1].gateway,
            Some("fdfe:dcba:9876::2".parse().unwrap())
        );
        assert!(matches!(plan.steps.first(), Some(Step::RpFilter { .. })));
        assert!(matches!(plan.steps.last(), Some(Step::Dns { servers, .. }) if servers.len() == 2));
    }

    #[test]
    fn without_auto_route_only_the_stale_cleanup_is_planned() {
        let mut o = options();
        o.auto_route = false;
        o.inet6_address.clear();
        let plan = plan_linux(&o, &iface());
        assert!(plan.steps.is_empty());
        assert_eq!(plan.stale_rule_priorities, Some((9000, 9010)));
    }

    #[test]
    fn without_auto_route_an_ipv6_tun_still_gets_its_output_rule() {
        let mut o = options();
        o.auto_route = false;
        let plan = plan_linux(&o, &iface());
        let [Step::Rule(rule)] = plan.steps.as_slice() else {
            panic!("expected one rule, got {:?}", plan.steps);
        };
        assert_eq!(rule.oif.as_deref(), Some("tun0"));
        assert_eq!((rule.family, rule.priority), (Family::V6, 9000));
    }

    #[test]
    fn ipv4_rule_chain_matches_sing_tun() {
        let rules = rules_for(&options(), "tun0");
        let v4 = of(&rules, Family::V4);
        let summary: Vec<_> = v4
            .iter()
            .map(|rule| (rule.priority, rule.action, rule.invert))
            .collect();
        assert_eq!(
            summary,
            [
                (9000, RuleAction::Table(2022), false),
                (9001, RuleAction::Table(2022), false),
                (9002, RuleAction::Table(254), true),
                (9002, RuleAction::Goto(9010), false),
                (9003, RuleAction::Table(2022), true),
                (9003, RuleAction::Table(2022), false),
                (9003, RuleAction::Table(2022), false),
                (9010, RuleAction::Nop, false),
            ]
        );
        assert_eq!(v4[0].dst, Some(p("198.18.0.0/30")));
        assert_eq!(v4[1].suppress_prefixlen, Some(0));
        assert_eq!(v4[2].dport, Some((53, 53)));
        assert_eq!(v4[3].iif.as_deref(), Some("tun0"));
        assert_eq!(v4[4].iif.as_deref(), Some("lo"));
        assert_eq!(v4[5].src, Some(p("0.0.0.0/32")));
        assert_eq!(v4[6].src, Some(p("198.18.0.0/30")));
    }

    #[test]
    fn ipv6_rule_chain_matches_sing_tun() {
        let rules = rules_for(&options(), "tun0");
        let v6 = of(&rules, Family::V6);
        let summary: Vec<_> = v6.iter().map(|rule| (rule.priority, rule.action)).collect();
        assert_eq!(
            summary,
            [
                (9000, RuleAction::Table(2022)),
                (9001, RuleAction::Table(254)),
                (9001, RuleAction::Goto(9010)),
                (9002, RuleAction::Table(2022)),
                (9003, RuleAction::Goto(9010)),
                (9003, RuleAction::Goto(9010)),
                (9004, RuleAction::Table(2022)),
                (9010, RuleAction::Nop),
            ]
        );
        assert_eq!(v6[4].src, Some(p("::/1")));
        assert_eq!(v6[5].src, Some(p("8000::/1")));
    }

    #[test]
    fn android_chain_matches_sing_tun_without_the_main_table_rules() {
        let rules = rules_for_android(&options(), "tun0");
        let summary = |family| -> Vec<_> {
            of(&rules, family)
                .iter()
                .map(|rule| (rule.priority, rule.action, rule.invert))
                .collect()
        };
        assert_eq!(
            summary(Family::V4),
            [
                (9000, RuleAction::Goto(9010), false),
                (9001, RuleAction::Table(2023), false),
                (9001, RuleAction::Table(2022), true),
                (9001, RuleAction::Table(2022), false),
                (9001, RuleAction::Table(2022), false),
                (9010, RuleAction::Nop, false),
            ]
        );
        assert_eq!(
            summary(Family::V6),
            [
                (9000, RuleAction::Goto(9010), false),
                (9001, RuleAction::Table(2023), false),
                (9001, RuleAction::Table(2022), false),
                (9001, RuleAction::Table(2022), false),
                (9002, RuleAction::Goto(9010), false),
                (9002, RuleAction::Goto(9010), false),
                (9003, RuleAction::Table(2022), false),
                (9010, RuleAction::Nop, false),
            ]
        );
        assert_eq!(of(&rules, Family::V6)[3].src, Some(p("::/128")));
        assert!(rules.iter().all(|rule| rule.suppress_prefixlen.is_none()
            && rule.dst.is_none()
            && (rule.dport.is_none() || rule.action == RuleAction::Table(2023))));
    }

    #[test]
    fn android_without_ipv6_still_takes_ipv6_dns_past_the_excluded_uids() {
        let mut o = options();
        o.inet6_address.clear();
        o.exclude_uid = vec![IdRange::single(10_123)];
        let plan = plan_android(&o, &iface());
        let rules: Vec<_> = plan
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Rule(rule) if rule.family == Family::V6 => Some(rule),
                _ => None,
            })
            .collect();
        let summary: Vec<_> = rules
            .iter()
            .map(|rule| (rule.priority, rule.action, rule.dport, rule.uid_range))
            .collect();
        assert_eq!(
            summary,
            [
                (9000, RuleAction::Goto(9010), None, Some((10_123, 10_123))),
                (9001, RuleAction::Goto(9010), None, None),
                (9002, RuleAction::Table(2023), Some((53, 53)), None),
                (9010, RuleAction::Nop, None, None),
            ]
        );
        assert!(plan.steps.iter().any(|step| matches!(
            step,
            Step::Route(route) if route.table == Some(2023) && route.dest == p("::/0")
        )));
        assert!(
            !plan
                .steps
                .iter()
                .any(|step| matches!(step, Step::Route(route) if route.table == Some(2022) && !route.dest.is_ipv4()))
        );
    }

    #[test]
    fn android_sends_local_dns_to_a_table_of_the_device_alone() {
        let mut o = options();
        o.exclude_uid = vec![IdRange::single(10_123)];
        o.route_address = vec![p("1.0.0.0/8"), p("2000::/3")];
        let plan = plan_android(&o, &iface());
        let dns_rules: Vec<_> = plan
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Rule(rule) if rule.dport.is_some() => Some(rule),
                _ => None,
            })
            .collect();
        assert_eq!(dns_rules.len(), 2);
        for rule in &dns_rules {
            assert_eq!(rule.dport, Some((53, 53)));
            assert_eq!(rule.iif.as_deref(), Some("lo"));
            assert_eq!(rule.action, RuleAction::Table(2023));
            assert!(rule.priority > 9000, "after the excluded uids");
        }
        let dns_routes: Vec<_> = plan
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Route(route) if route.table == Some(2023) => Some(route.dest),
                _ => None,
            })
            .collect();
        assert_eq!(dns_routes, [p("0.0.0.0/0"), p("::/0")]);
        assert!(
            rules_for(&o, "tun0")
                .iter()
                .all(|rule| rule.action != RuleAction::Table(2023))
        );
    }

    #[test]
    fn only_strict_route_with_a_missing_family_leaves_a_terminal_rule() {
        let terminal = |o: &TunOptions| -> Vec<Family> {
            rules_for_android(o, "tun0")
                .into_iter()
                .filter(|rule| rule.action == RuleAction::Unreachable)
                .map(|rule| rule.family)
                .collect()
        };
        let mut o = options();
        o.exclude_uid = vec![IdRange::single(10_123)];
        assert!(terminal(&o).is_empty());
        o.inet6_address.clear();
        assert!(terminal(&o).is_empty());
        o.strict_route = true;
        assert_eq!(terminal(&o), [Family::V6]);
    }

    #[test]
    fn android_plan_routes_the_private_table_without_a_resolver_step() {
        let mut o = options();
        o.exclude_uid = vec![IdRange::single(10_123)];
        let plan = plan_android(&o, &iface());
        assert_eq!(plan.stale_rule_priorities, Some((9000, 9010)));
        assert!(matches!(plan.steps.first(), Some(Step::RpFilter { .. })));
        assert!(
            !plan
                .steps
                .iter()
                .any(|step| matches!(step, Step::Dns { .. }))
        );
        let first_rule = plan.steps.iter().find_map(|step| match step {
            Step::Rule(rule) => Some(rule),
            _ => None,
        });
        assert_eq!(
            first_rule.and_then(|rule| rule.uid_range),
            Some((10_123, 10_123))
        );
        assert_eq!(
            plan.steps
                .iter()
                .filter(
                    |step| matches!(step, Step::Route(route) if route.table == Some(2022)
                    && route.gateway.is_none())
                )
                .count(),
            2
        );
    }

    #[test]
    fn excluded_uids_ports_and_interfaces_jump_past_the_tunnel() {
        let mut o = options();
        o.inet6_address.clear();
        o.exclude_uid = vec![IdRange {
            start: 1000,
            end: 1999,
        }];
        o.exclude_dst_port = vec![IdRange { start: 22, end: 22 }];
        o.exclude_interface = vec!["docker0".into()];
        let rules = rules_for(&o, "tun0");
        assert_eq!(rules[0].uid_range, Some((1000, 1999)));
        assert_eq!(rules[0].action, RuleAction::Goto(9010));
        assert_eq!(rules[0].priority, 9000);
        assert_eq!(rules[1].dport, Some((22, 22)));
        assert_eq!(rules[1].priority, 9000);
        assert_eq!(rules[2].iif.as_deref(), Some("docker0"));
        assert_eq!(rules[2].priority, 9001);
        assert_eq!(rules[3].priority, 9002);
        assert!(rules.iter().all(|rule| rule.family == Family::V4));
    }

    #[test]
    fn include_interface_sends_only_those_into_the_tunnel() {
        let mut o = options();
        o.inet6_address.clear();
        o.include_interface = vec!["wlan0".into()];
        let rules = rules_for(&o, "tun0");
        assert_eq!(rules[0].iif.as_deref(), Some("wlan0"));
        assert_eq!(rules[0].action, RuleAction::Goto(9002));
        assert_eq!(rules[1].action, RuleAction::Goto(9010));
        assert_eq!(rules[1].priority, 9001);
        assert_eq!(
            (rules[2].priority, rules[2].action),
            (9002, RuleAction::Nop)
        );
    }

    #[test]
    fn strict_route_blocks_the_family_the_tunnel_does_not_carry() {
        let mut o = options();
        o.inet6_address.clear();
        o.strict_route = true;
        let rules = rules_for(&o, "tun0");
        let unreachable: Vec<_> = rules
            .iter()
            .filter(|rule| rule.action == RuleAction::Unreachable)
            .collect();
        assert_eq!(unreachable.len(), 1);
        assert_eq!(unreachable[0].family, Family::V6);
    }

    #[test]
    fn custom_table_and_rule_indexes_move_the_chain() {
        let mut o = options();
        o.iproute2_table_index = 100;
        o.iproute2_rule_index = 500;
        let rules = rules_for(&o, "tun0");
        assert!(
            rules
                .iter()
                .any(|rule| rule.action == RuleAction::Table(100))
        );
        assert_eq!(rules.iter().map(|rule| rule.priority).min(), Some(500));
        assert_eq!(rules.iter().map(|rule| rule.priority).max(), Some(510));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rule_messages_carry_the_selectors() {
        use rtnetlink::packet_route::rule::RuleAttribute;
        let mut rule = RuleSpec::new(Family::V4, 9002, RuleAction::Table(2022));
        rule.invert = true;
        rule.iif = Some("lo".into());
        rule.dport = Some((53, 53));
        let message = super::netlink::rule_message(&rule);
        assert!(
            message
                .header
                .flags
                .contains(rtnetlink::packet_route::rule::RuleFlags::Invert)
        );
        assert!(message.attributes.contains(&RuleAttribute::Priority(9002)));
        assert!(message.attributes.contains(&RuleAttribute::Table(2022)));
        assert!(
            message
                .attributes
                .contains(&RuleAttribute::Iifname("lo".into()))
        );
    }
}
