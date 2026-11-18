use super::*;

pub(super) fn parse_ss(f: &mut Fields<'_>, caps: &Capabilities) -> R<SsOpts> {
    let (server, port) = server_port(f)?;
    let password = f.req_string("password")?;
    let cipher = f.req_string("cipher")?;
    let plugin_name = f.string("plugin")?;
    let plugin_map = PluginOpts(f.object("plugin-opts")?.cloned().unwrap_or_default());
    let plugin = match plugin_name.as_str() {
        "" => None,
        name if T2_SS_PLUGINS.contains(&name) => {
            return quarantine(format!(
                "shadowsocks plugin '{name}' is not supported by this core"
            ));
        }
        name if !caps.ss_plugins.contains(&name)
            && matches!(
                name,
                "obfs" | "v2ray-plugin" | "shadow-tls" | "jls" | "gost-plugin"
            ) =>
        {
            return quarantine(format!(
                "shadowsocks plugin '{name}' is not implemented yet"
            ));
        }
        "obfs" => {
            let mut o = plugin_fields(&plugin_map);
            let mode = o.string("mode")?;
            let host = o
                .opt_string("host")?
                .unwrap_or_else(|| "bing.com".to_string());
            if mode != "tls" && mode != "http" {
                return Err(Fail::Hard(ConfigError::new(format!(
                    "ss {server}:{port} obfs mode error: {mode}"
                ))));
            }
            Some(SsPlugin::Obfs { mode, host })
        }
        "v2ray-plugin" | "gost-plugin" => {
            let mut o = plugin_fields(&plugin_map);
            let plugin = websocket_plugin(&mut o, caps, plugin_name == "gost-plugin").map_err(
                |failure| match failure {
                    Fail::Hard(error) if plugin_name == "gost-plugin" => {
                        Fail::Hard(error.prefixed(&format!(
                            "ss {server}:{port} initialize gost-plugin error: "
                        )))
                    }
                    other => other,
                },
            )?;
            if plugin.mode != "websocket" {
                return Err(Fail::Hard(ConfigError::new(format!(
                    "ss {server}:{port} obfs mode error: {}",
                    plugin.mode
                ))));
            }
            Some(if plugin_name == "gost-plugin" {
                SsPlugin::Gost(Box::new(plugin))
            } else {
                SsPlugin::V2ray(Box::new(plugin))
            })
        }
        "jls" => Some(SsPlugin::Jls(jls_plugin(plugin_fields(&plugin_map))?)),
        "shadow-tls" => Some(SsPlugin::ShadowTls(shadow_tls_opts(
            plugin_fields(&plugin_map),
            &format!("ss {server}:{port}"),
        )?)),
        other => return quarantine(format!("unknown shadowsocks plugin '{other}'")),
    };
    Ok(SsOpts {
        server,
        port,
        password,
        cipher,
        plugin,
        udp_over_tcp: f.boolean("udp-over-tcp")?,
        udp_over_tcp_version: u8::try_from(f.u32("udp-over-tcp-version")?).unwrap_or(0),
        client_fingerprint: f.string("client-fingerprint")?,
    })
}

fn websocket_plugin(o: &mut Fields<'_>, caps: &Capabilities, gost: bool) -> R<V2rayPlugin> {
    let tls = o.boolean("tls")?;
    Ok(V2rayPlugin {
        mode: o.string("mode")?,
        host: o
            .opt_string("host")?
            .unwrap_or_else(|| "bing.com".to_string()),
        path: o.string("path")?,
        tls,
        ech: if !gost || tls {
            ech_opts(o, caps)?
        } else {
            None
        },
        fingerprint: o.string("fingerprint")?,
        certificate: o.string("certificate")?,
        private_key: o.string("private-key")?,
        headers: headers(o, "headers")?,
        skip_cert_verify: o.boolean("skip-cert-verify")?,
        name_cert_verify: o.string("name-cert-verify")?,
        mux: o.opt_bool("mux")?.unwrap_or(true),
        v2ray_http_upgrade: !gost && o.boolean("v2ray-http-upgrade")?,
        v2ray_http_upgrade_fast_open: !gost && o.boolean("v2ray-http-upgrade-fast-open")?,
    })
}
