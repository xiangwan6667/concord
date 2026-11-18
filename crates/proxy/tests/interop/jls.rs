use super::{Case, Certs, Udp, case, merge};
use serde_json::json;

pub(super) fn cases(certs: &Certs) -> Vec<Case> {
    let mut cases = Vec::new();
    for fingerprint in ["", "chrome", "firefox", "safari"] {
        let extra = json!({"tls": true, "sni": "localhost", "servername": "localhost",
            "client-fingerprint": fingerprint, "jls-opts": {"username": "name", "password": "secret"}});
        let suffix = if fingerprint.is_empty() {
            "plain"
        } else {
            fingerprint
        };
        let listener = "    jls-config:\n      enable: true\n      sni: localhost\n      dest: 127.0.0.1:9\n      users:\n        - username: name\n          password: secret\n";
        cases.push(super::vmess_case(
            &format!("jls-vmess-{suffix}"),
            extra.clone(),
            Udp::OneDestination,
            0,
            listener,
        ));
        cases.push(super::vless_case(
            &format!("jls-vless-{suffix}"),
            extra.clone(),
            Udp::Many,
            "",
            listener,
        ));
        let mut trojan = super::trojan_case(
            &format!("jls-trojan-{suffix}"),
            extra.clone(),
            Udp::Many,
            listener,
            certs,
        );
        trojan.listener = trojan.listener.replace(&super::tls_lines(certs), "");
        cases.push(trojan);
        let mut anytls =
            super::anytls_case(&format!("jls-anytls-{suffix}"), extra, listener, certs);
        anytls.listener = anytls.listener.replace(&super::tls_lines(certs), "");
        cases.push(anytls);
        let plugin = json!({"host": "localhost", "username": "name", "password": "secret"});
        cases.push(super::ss_case(
            &format!("jls-ss-{suffix}"),
            "aes-128-gcm",
            "pw",
            listener,
            json!({"plugin": "jls", "plugin-opts": plugin, "client-fingerprint": fingerprint}),
            Udp::Many,
        ));
        for version in [4, 6] {
            let psk = if version == 6 {
                "snell-v6-jls-psk"
            } else {
                "snell-psk"
            };
            let body = format!("    psk: {psk}\n    version: {version}\n    udp: true\n{listener}");
            cases.push(case(
                &format!("jls-snell-v{version}-{suffix}"),
                "snell",
                "snell",
                &body,
                json!({"psk": psk, "version": version, "client-fingerprint": fingerprint,
                    "obfs-opts": merge(plugin.clone(), json!({"mode": "jls"}))}),
                Udp::Many,
            ));
        }
    }
    cases
}
