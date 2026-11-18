use concord_config::proxy::ProxyKind;
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use serde_json::json;

#[test]
fn gost_relay_options_parse_and_require_a_server() {
    let mut value = json!({"name":"r", "type":"gost-relay", "server":"relay", "port":443,
        "forward":true, "mux":true, "tls":true, "sni":"sni.example", "username":"u", "password":"p",
        "certificate":"cert", "private-key":"key", "fingerprint":"pin", "client-fingerprint":"chrome", "udp":true});
    let ProxyParse::Ok(def) =
        parse_proxy(value.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("quarantined")
    };
    let ProxyKind::GostRelay(opts) = def.kind else {
        panic!("wrong type")
    };
    assert!(opts.forward && opts.mux && opts.tls.enabled && def.common.udp);
    assert_eq!(opts.tls.server_name, "sni.example");
    assert_eq!((opts.username.as_str(), opts.password.as_str()), ("u", "p"));
    assert_eq!(
        (opts.tls.certificate.as_str(), opts.tls.private_key.as_str()),
        ("cert", "key")
    );
    for port in [0, 65536] {
        value["port"] = json!(port);
        assert!(parse_proxy(value.as_object().unwrap(), &Capabilities::full()).is_err());
    }
    value["port"] = json!(443);
    value["server"] = json!("");
    assert!(parse_proxy(value.as_object().unwrap(), &Capabilities::full()).is_err());
}
