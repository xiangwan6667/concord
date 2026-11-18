use crate::Map;
use crate::error::Result;
use crate::keys::{default_number, ntp_defaults};
use crate::lenient::{Fields, Ignored};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtpConfig {
    pub enable: bool,
    pub server: String,
    pub port: u16,
    pub interval: u32,
    pub dialer_proxy: String,
    pub write_to_system: bool,
}

impl NtpConfig {
    pub fn from_map(map: &Map) -> Result<NtpConfig> {
        Ok(NtpConfig::read(map)?.0)
    }

    /// A number out of range takes its default, returned as a note.
    pub fn read(map: &Map) -> Result<(NtpConfig, Vec<Ignored>)> {
        let defaults = ntp_defaults();
        let mut f = Fields::new(map, "ntp", false);
        let ntp = NtpConfig {
            enable: f.boolean("enable")?,
            server: f.string("server")?,
            port: f.loose("port", default_number(&defaults, "port"))?,
            interval: f.loose("interval", default_number(&defaults, "interval"))?,
            dialer_proxy: f.string("dialer-proxy")?,
            write_to_system: f.boolean("write-to-system")?,
        };
        Ok((ntp, f.take_ignored()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ntp_defaults;

    #[test]
    fn defaults() {
        let ntp = NtpConfig::from_map(&ntp_defaults()).unwrap();
        assert_eq!(
            (ntp.server.as_str(), ntp.port, ntp.interval),
            ("time.apple.com", 123, 30)
        );
        assert!(!ntp.enable && !ntp.write_to_system);
    }
}
