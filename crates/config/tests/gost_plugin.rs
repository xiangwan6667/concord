use concord_config::proxy::{ProxyKind, SsPlugin};
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use serde_json::json;

#[test]
fn gost_plugin_defaults_and_tls_options_are_preserved() {
    let mut value = json!({"name":"g", "type":"ss", "server":"server", "port":443,
        "cipher":"aes-128-gcm", "password":"pw", "plugin":"gost-plugin", "plugin-opts":{"mode":"websocket"}});
    let ProxyParse::Ok(def) =
        parse_proxy(value.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("quarantined")
    };
    let ProxyKind::Ss(ss) = def.kind else {
        panic!("not SS")
    };
    let Some(SsPlugin::Gost(opts)) = ss.plugin else {
        panic!("not gost")
    };
    assert_eq!(opts.host, "bing.com");
    assert!(opts.mux);
    value["plugin-opts"] = json!({"mode":"websocket", "mux":false, "tls":true,
        "headers":{"Host":"edge.example"}, "certificate":"cert", "private-key":"key",
        "name-cert-verify":"verify.example", "fingerprint":"pin", "skip-cert-verify":true});
    let ProxyParse::Ok(def) =
        parse_proxy(value.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("quarantined")
    };
    let ProxyKind::Ss(ss) = def.kind else {
        panic!("not SS")
    };
    let Some(SsPlugin::Gost(opts)) = ss.plugin else {
        panic!("not gost")
    };
    assert!(opts.tls && opts.skip_cert_verify && !opts.mux);
    assert_eq!(
        (
            opts.certificate.as_str(),
            opts.private_key.as_str(),
            opts.fingerprint.as_str()
        ),
        ("cert", "key", "pin")
    );
    assert_eq!(opts.headers["Host"], "edge.example");
    let mut caps = Capabilities::full();
    caps.ss_plugins.retain(|name| *name != "gost-plugin");
    assert!(matches!(
        parse_proxy(value.as_object().unwrap(), &caps).unwrap(),
        ProxyParse::Quarantined { .. }
    ));
    value["plugin-opts"]["mode"] = json!("tcp");
    assert!(parse_proxy(value.as_object().unwrap(), &Capabilities::full()).is_err());
}

#[test]
fn gost_plugin_ignores_ech_without_tls_and_prefixes_decode_errors() {
    let mut value = json!({"name":"g", "type":"ss", "server":"server", "port":443,
        "cipher":"aes-128-gcm", "password":"pw", "plugin":"gost-plugin",
        "plugin-opts":{"mode":"websocket", "tls":false, "ech-opts":42}});
    assert!(matches!(
        parse_proxy(value.as_object().unwrap(), &Capabilities::full()).unwrap(),
        ProxyParse::Ok(_)
    ));
    value["plugin-opts"]["tls"] = json!(true);
    let error = parse_proxy(value.as_object().unwrap(), &Capabilities::full()).unwrap_err();
    assert!(
        error.message.contains("initialize gost-plugin error"),
        "{error}"
    );
}
