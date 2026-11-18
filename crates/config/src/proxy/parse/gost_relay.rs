use super::*;

pub(super) fn gost_relay_opts(f: &mut Fields<'_>) -> R<GostRelayOpts> {
    let (server, port) = server_port(f)?;
    if server.is_empty() || port == 0 {
        return Err(Fail::Hard(ConfigError::new(
            "gost-relay requires a valid server and port",
        )));
    }
    let tls = TlsOpts {
        enabled: f.boolean("tls")?,
        server_name: f.string("sni")?,
        skip_cert_verify: f.boolean("skip-cert-verify")?,
        fingerprint: f.string("fingerprint")?,
        certificate: f.string("certificate")?,
        private_key: f.string("private-key")?,
        name_cert_verify: f.string("name-cert-verify")?,
        client_fingerprint: f.string("client-fingerprint")?,
        ..TlsOpts::default()
    };
    Ok(GostRelayOpts {
        server,
        port,
        tls,
        forward: f.boolean("forward")?,
        mux: f.boolean("mux")?,
        username: f.string("username")?,
        password: f.string("password")?,
    })
}
