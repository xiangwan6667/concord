use super::super::types::MasqueOpts;
use super::{Fail, R};
use crate::error::ConfigError;
use crate::lenient::Fields;

pub(super) fn parse(f: &mut Fields<'_>) -> R<MasqueOpts> {
    let handshake_timeout = f.i64("handshake-timeout")?;
    if handshake_timeout < 0 {
        return Err(Fail::Hard(ConfigError::new(
            "masque handshake timeout must be non-negative",
        )));
    }
    let mut out = MasqueOpts {
        server: f.req_string("server")?,
        port: f.req_u16("port")?,
        private_key: f.req_string("private-key")?,
        public_key: f.req_string("public-key")?,
        ip: f.string("ip")?,
        ipv6: f.string("ipv6")?,
        uri: f.string("uri")?,
        sni: f.string("sni")?,
        mtu: f.u32("mtu")?,
        handshake_timeout: handshake_timeout as u64,
        skip_cert_verify: f.boolean("skip-cert-verify")?,
        network: f.string("network")?,
        congestion_controller: f.string("congestion-controller")?,
        cwnd: f.u32("cwnd")?,
        bbr_profile: f.string("bbr-profile")?,
        remote_dns_resolve: f.boolean("remote-dns-resolve")?,
        dns: f.strings("dns")?,
        ..MasqueOpts::default()
    };
    // mihomo accepts this placeholder but pins the endpoint key instead of its name.
    f.string("name-cert-verify")?;
    if let Some(mut stack) = f.sub("ip-stack")? {
        out.ip_stack_mode = stack.string("mode")?;
        out.ip_stack_congestion_controller = stack.string("congestion-controller")?;
    }
    Ok(out)
}
