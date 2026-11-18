use crate::Map;
use crate::error::{ConfigError, Result};
use crate::lenient::Fields;
use crate::net::{IpCidr, parse_cidr};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TunConfig {
    pub enable: bool,
    pub device: String,
    pub stack_name: String,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub dns_hijack: Vec<String>,
    pub route_address: Vec<IpCidr>,
    pub route_exclude_address: Vec<IpCidr>,
    pub strict_route: bool,
    pub mtu: u32,
    pub congestion_controller: String,
    pub udp_timeout: i64,
    pub disable_icmp_forwarding: bool,
    /// `None` when the profile does not say.
    pub gso: Option<bool>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<u32>,
    pub exclude_uid: Vec<u32>,
    pub exclude_src_port: Vec<u16>,
    pub exclude_dst_port: Vec<u16>,
}

fn cidrs(f: &mut Fields<'_>, key: &str) -> Result<Vec<IpCidr>> {
    f.strings(key)?
        .iter()
        .enumerate()
        .map(|(index, text)| {
            parse_cidr(text).map_err(|err| err.prefixed(&format!("tun.{key}[{index}]: ")))
        })
        .collect()
}

/// mihomo still appends the old per-family keys to the merged lists (`listener/sing_tun/server.go`).
fn routes(f: &mut Fields<'_>, key: &str, inet4: &str, inet6: &str) -> Result<Vec<IpCidr>> {
    let mut out = cidrs(f, key)?;
    out.extend(cidrs(f, inet4)?);
    out.extend(cidrs(f, inet6)?);
    Ok(out)
}

fn narrow<T: TryFrom<i128>>(values: Vec<i128>) -> Vec<T> {
    values
        .into_iter()
        .filter_map(|n| T::try_from(n).ok())
        .collect()
}

impl TunConfig {
    pub fn from_map(map: &Map) -> Result<TunConfig> {
        let mut f = Fields::new(map, "tun", false);
        let stack_name = f.string("stack")?;
        if !matches!(
            stack_name.to_ascii_lowercase().as_str(),
            "" | "gvisor" | "mips" | "mixed" | "system"
        ) {
            return Err(ConfigError::new("invalid tun stack"));
        }
        Ok(TunConfig {
            enable: f.boolean("enable")?,
            device: f.string("device")?,
            stack_name,
            auto_route: f.boolean("auto-route")?,
            auto_detect_interface: f.boolean("auto-detect-interface")?,
            dns_hijack: f.strings("dns-hijack")?,
            route_address: routes(
                &mut f,
                "route-address",
                "inet4-route-address",
                "inet6-route-address",
            )?,
            route_exclude_address: routes(
                &mut f,
                "route-exclude-address",
                "inet4-route-exclude-address",
                "inet6-route-exclude-address",
            )?,
            strict_route: f.boolean("strict-route")?,
            mtu: f.u32("mtu")?,
            congestion_controller: f.string("congestion-controller")?,
            udp_timeout: f.i64("udp-timeout")?,
            disable_icmp_forwarding: f.boolean("disable-icmp-forwarding")?,
            gso: f.opt_bool("gso")?,
            include_interface: f.strings("include-interface")?,
            exclude_interface: f.strings("exclude-interface")?,
            include_uid: narrow(f.ints("include-uid", 0, i128::from(u32::MAX))?),
            exclude_uid: narrow(f.ints("exclude-uid", 0, i128::from(u32::MAX))?),
            exclude_src_port: narrow(f.ints("exclude-src-port", 0, i128::from(u16::MAX))?),
            exclude_dst_port: narrow(f.ints("exclude-dst-port", 0, i128::from(u16::MAX))?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::tun_defaults;
    use serde_json::json;

    #[test]
    fn defaults_and_stack_names() {
        let tun = TunConfig::from_map(&tun_defaults()).unwrap();
        assert!(!tun.enable && tun.auto_route && tun.auto_detect_interface);
        assert_eq!(tun.dns_hijack, ["0.0.0.0:53"]);
        let mut map = tun_defaults();
        map.insert("stack".into(), json!("System"));
        assert_eq!(TunConfig::from_map(&map).unwrap().stack_name, "System");
        map.insert("stack".into(), json!("bogus"));
        assert!(TunConfig::from_map(&map).is_err());
    }

    #[test]
    fn route_lists_are_validated() {
        let mut map = tun_defaults();
        map.insert("route-address".into(), json!(["10.0.0.0/8", "::/0"]));
        map.insert("exclude-dst-port".into(), json!([53, "853"]));
        map.insert("mtu".into(), json!(1500));
        let tun = TunConfig::from_map(&map).unwrap();
        assert_eq!(tun.route_address.len(), 2);
        assert_eq!(tun.exclude_dst_port, [53, 853]);
        assert_eq!(tun.mtu, 1500);
        map.insert("route-address".into(), json!(["10.0.0.0"]));
        assert!(TunConfig::from_map(&map).is_err());
    }

    #[test]
    fn the_old_per_family_route_keys_add_to_the_merged_lists() {
        let mut map = tun_defaults();
        map.insert("route-address".into(), json!(["10.0.0.0/8"]));
        map.insert("inet4-route-address".into(), json!(["0.0.0.0/1"]));
        map.insert("inet6-route-address".into(), json!(["::/1"]));
        map.insert(
            "inet4-route-exclude-address".into(),
            json!(["192.168.0.0/16"]),
        );
        let tun = TunConfig::from_map(&map).unwrap();
        let text = |list: &[IpCidr]| list.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(
            text(&tun.route_address),
            ["10.0.0.0/8", "0.0.0.0/1", "::/1"]
        );
        assert_eq!(text(&tun.route_exclude_address), ["192.168.0.0/16"]);
    }
}
