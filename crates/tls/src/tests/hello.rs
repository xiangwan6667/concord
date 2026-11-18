//! ClientHello captures: what each fingerprint value puts on the wire.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::Arc;

use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, duplex};

use super::support::Ca;
use crate::TlsOptions;
use crate::boring_backend::BoringConnector;
use crate::fingerprints::{ClientFingerprint, GREASE};
use crate::policy::CertPolicy;
use crate::reality::{HelloParams, build_client_hello};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Parsed {
    pub name: String,
    pub ciphers: Vec<String>,
    pub extensions: Vec<String>,
    pub groups: Vec<String>,
    pub sigalgs: Vec<String>,
    pub versions: Vec<String>,
    pub alpn: Vec<String>,
    pub key_shares: Vec<String>,
    pub psk_modes: Vec<String>,
    pub compress_cert: Vec<String>,
    pub alps: Vec<String>,
    pub point_formats: Vec<String>,
    pub delegated_cred: Vec<String>,
    pub record_size_limit: String,
    pub ech_payload_len: usize,
    pub padding: usize,
    pub hello_len: usize,
    pub session_id_len: usize,
    pub compression: Vec<String>,
}

fn hx(value: u16) -> String {
    let [hi, lo] = value.to_be_bytes();
    if hi == lo && hi & 0x0f == 0x0a {
        "GREASE".into()
    } else {
        format!("{value:04x}")
    }
}

fn u16s(data: &[u8], skip: usize) -> Vec<String> {
    data.get(skip..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| hx(u16::from_be_bytes(*c)))
        .collect()
}

/// `hello` is the handshake message, header included.
pub fn parse_hello(name: &str, hello: &[u8]) -> Parsed {
    let mut parsed = Parsed {
        name: name.into(),
        hello_len: hello.len(),
        ..Parsed::default()
    };
    let mut at = 4 + 2 + 32;
    let sid = usize::from(hello[at]);
    parsed.session_id_len = sid;
    at += 1 + sid;
    let ciphers = usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 2;
    parsed.ciphers = u16s(&hello[at..at + ciphers], 0);
    at += ciphers;
    let comp = usize::from(hello[at]);
    at += 1;
    parsed.compression = hello[at..at + comp]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    at += comp;
    let ext_len = usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 2;
    let mut exts = &hello[at..at + ext_len];
    assert_eq!(at + ext_len, hello.len(), "extensions run to the end");
    while exts.len() >= 4 {
        let kind = u16::from_be_bytes([exts[0], exts[1]]);
        let len = usize::from(u16::from_be_bytes([exts[2], exts[3]]));
        let data = &exts[4..4 + len];
        exts = &exts[4 + len..];
        parsed.extensions.push(hx(kind));
        match kind {
            10 => parsed.groups = u16s(data, 2),
            13 => parsed.sigalgs = u16s(data, 2),
            43 => parsed.versions = u16s(data, 1),
            16 => {
                let mut list = &data[2..];
                while !list.is_empty() {
                    let n = usize::from(list[0]);
                    parsed
                        .alpn
                        .push(String::from_utf8_lossy(&list[1..1 + n]).into_owned());
                    list = &list[1 + n..];
                }
            }
            51 => {
                let mut list = &data[2..];
                while list.len() >= 4 {
                    let group = u16::from_be_bytes([list[0], list[1]]);
                    let n = usize::from(u16::from_be_bytes([list[2], list[3]]));
                    parsed.key_shares.push(format!("{}:{n}", hx(group)));
                    list = &list[4 + n..];
                }
            }
            45 => parsed.psk_modes = data[1..].iter().map(|b| format!("{b:02x}")).collect(),
            27 => parsed.compress_cert = u16s(data, 1),
            17513 | 17613 => {
                parsed.alps = u16s(data, 2);
                parsed.alps.push(format!("ext={kind}"));
            }
            11 => parsed.point_formats = data[1..].iter().map(|b| format!("{b:02x}")).collect(),
            34 => parsed.delegated_cred = u16s(data, 2),
            28 => parsed.record_size_limit = hex::encode(data),
            0xfe0d => parsed.ech_payload_len = len,
            21 => parsed.padding = len,
            _ => {}
        }
    }
    parsed
}

fn list(items: &[String]) -> String {
    if items.is_empty() {
        return "null".into();
    }
    let quoted: Vec<String> = items.iter().map(|i| format!("{i:?}")).collect();
    format!("[{}]", quoted.join(","))
}

pub fn to_json(items: &[Parsed]) -> String {
    let mut out = String::from("[\n");
    for (i, p) in items.iter().enumerate() {
        let _ = write!(
            out,
            "{{\"name\":{:?},\"ciphers\":{},\"extensions\":{},\"groups\":{},\"sigalgs\":{},\
             \"versions\":{},\"alpn\":{},\"key_shares\":{},\"psk_modes\":{},\"compress_cert\":{},\
             \"alps\":{},\"point_formats\":{},\"delegated_cred\":{},\"record_size_limit\":{:?},\
             \"ech_payload_len\":{},\"padding\":{},\"hello_len\":{},\"session_id_len\":{},\
             \"compression\":{}}}",
            p.name,
            list(&p.ciphers),
            list(&p.extensions),
            list(&p.groups),
            list(&p.sigalgs),
            list(&p.versions),
            list(&p.alpn),
            list(&p.key_shares),
            list(&p.psk_modes),
            list(&p.compress_cert),
            list(&p.alps),
            list(&p.point_formats),
            list(&p.delegated_cred),
            p.record_size_limit,
            p.ech_payload_len,
            p.padding,
            p.hello_len,
            p.session_id_len,
            list(&p.compression),
        );
        out.push_str(if i + 1 == items.len() { "\n" } else { ",\n" });
    }
    out.push(']');
    out
}

pub fn reality_hello(fp: ClientFingerprint, mlkem: bool) -> Vec<u8> {
    let spec = fp.spec().unwrap();
    let ek = vec![0x42u8; 1184];
    build_client_hello(
        spec,
        &HelloParams {
            jls: false,
            server_name: Some("example.com"),
            alpn: None,
            random: &[7u8; 32],
            x25519_public: &[9u8; 32],
            mlkem_encapsulation_key: mlkem.then_some(ek.as_slice()),
        },
    )
    .unwrap()
}

pub async fn boring_hello(fp: ClientFingerprint, sni: &str) -> Vec<u8> {
    let ca = Ca::new();
    let (effective, _) = fp.effective();
    let spec = effective.spec().unwrap();
    let connector = BoringConnector::new(
        spec,
        Arc::new(CertPolicy::new(&TlsOptions::default(), ca.trust()).unwrap()),
        &[],
        None,
        None,
    )
    .unwrap();
    let (client, mut server) = duplex(1 << 16);
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    let attempt = tokio::spawn(async move {
        let _ = connector.connect_over(name, client).await;
    });
    let mut header = [0u8; 5];
    server.read_exact(&mut header).await.unwrap();
    let mut body = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    server.read_exact(&mut body).await.unwrap();
    drop(server);
    let _ = attempt.await;
    assert_eq!(header[0], 22);
    body
}

const ALL: [ClientFingerprint; 11] = [
    ClientFingerprint::Chrome,
    ClientFingerprint::Firefox,
    ClientFingerprint::Safari,
    ClientFingerprint::Ios,
    ClientFingerprint::Android,
    ClientFingerprint::Edge,
    ClientFingerprint::Qihoo360,
    ClientFingerprint::Qq,
    ClientFingerprint::Chrome120,
    ClientFingerprint::Firefox120,
    ClientFingerprint::Safari16,
];

#[tokio::test]
async fn dump_hellos_for_the_go_comparison() {
    let Some(dir) = std::env::var_os("CONCORD_TLS_DUMP") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let mut boring = Vec::new();
    let mut reality = Vec::new();
    for fp in ALL {
        boring.push(parse_hello(
            fp.name(),
            &boring_hello(fp, "example.com").await,
        ));
        if fp.spec().is_some_and(|spec| spec.tls13) {
            reality.push(parse_hello(fp.name(), &reality_hello(fp, true)));
        }
    }
    std::fs::write(dir.join("rust-boring.json"), to_json(&boring)).unwrap();
    std::fs::write(dir.join("rust-reality.json"), to_json(&reality)).unwrap();
}

#[test]
fn every_encoded_hello_follows_its_spec() {
    for fp in ALL {
        let spec = fp.spec().unwrap();
        if !spec.tls13 {
            continue;
        }
        for mlkem in [false, true] {
            let hello = reality_hello(fp, mlkem);
            let parsed = parse_hello(fp.name(), &hello);
            assert_eq!(hello[0], 1);
            assert_eq!(
                usize::from(hello[1]) << 16 | usize::from(hello[2]) << 8 | usize::from(hello[3]),
                hello.len() - 4,
                "{fp}"
            );
            assert_eq!(parsed.session_id_len, 32);
            assert_eq!(&hello[39..71], &[0u8; 32]);
            let want_ciphers: Vec<String> = spec.cipher_suites.iter().map(|c| hx(*c)).collect();
            assert_eq!(parsed.ciphers, want_ciphers, "{fp}");
            let offered_mlkem = spec.offers_mlkem() && mlkem;
            let want_groups: Vec<String> = spec
                .groups
                .iter()
                .filter(|g| **g != 0x11ec || offered_mlkem)
                .map(|g| hx(*g))
                .collect();
            assert_eq!(parsed.groups, want_groups, "{fp} mlkem={mlkem}");
            assert_eq!(
                parsed.key_shares.iter().any(|s| s.starts_with("11ec:1216")),
                offered_mlkem,
                "{fp}"
            );
            let want_sigalgs: Vec<String> =
                spec.signature_algorithms.iter().map(|g| hx(*g)).collect();
            assert_eq!(parsed.sigalgs, want_sigalgs, "{fp}");
            assert_eq!(parsed.alpn, ["h2", "http/1.1"], "{fp}");
            let real: Vec<&String> = parsed
                .extensions
                .iter()
                .filter(|e| *e != "GREASE")
                .collect();
            let unique: BTreeSet<_> = real.iter().collect();
            assert_eq!(real.len(), unique.len(), "{fp} repeats an extension");
        }
    }
}

#[test]
fn chrome_extension_order_is_shuffled_with_grease_pinned() {
    let mut orders = BTreeSet::new();
    for _ in 0..12 {
        let parsed = parse_hello("chrome", &reality_hello(ClientFingerprint::Chrome, true));
        assert_eq!(
            parsed.extensions.first().map(String::as_str),
            Some("GREASE")
        );
        assert_eq!(parsed.extensions.last().map(String::as_str), Some("GREASE"));
        orders.insert(parsed.extensions);
    }
    assert!(
        orders.len() > 6,
        "extension order did not vary: {}",
        orders.len()
    );
}

#[test]
fn fixed_order_fingerprints_do_not_shuffle() {
    for fp in [
        ClientFingerprint::Firefox,
        ClientFingerprint::Safari,
        ClientFingerprint::Ios,
        ClientFingerprint::Edge,
        ClientFingerprint::Qq,
    ] {
        let first = parse_hello("x", &reality_hello(fp, true)).extensions;
        for _ in 0..4 {
            assert_eq!(
                parse_hello("x", &reality_hello(fp, true)).extensions,
                first,
                "{fp}"
            );
        }
    }
}

#[test]
fn padding_brings_short_hellos_to_512() {
    for fp in [
        ClientFingerprint::Safari,
        ClientFingerprint::Ios,
        ClientFingerprint::Edge,
        ClientFingerprint::Qq,
    ] {
        let hello = reality_hello(fp, false);
        assert_eq!(hello.len(), 512, "{fp}");
    }
}

#[test]
fn grease_values_come_in_a_valid_shape() {
    let hello = reality_hello(ClientFingerprint::Chrome, true);
    let raw = u16::from_be_bytes([
        hello[4 + 2 + 32 + 1 + 32 + 2],
        hello[4 + 2 + 32 + 1 + 32 + 3],
    ]);
    let [hi, lo] = raw.to_be_bytes();
    assert_eq!(hi, lo);
    assert_eq!(hi & 0x0f, 0x0a);
    assert_ne!(raw, GREASE.wrapping_add(1));
}

#[tokio::test]
async fn boring_chrome_hello_has_the_chrome_shape() {
    let parsed = parse_hello(
        "chrome",
        &boring_hello(ClientFingerprint::Chrome, "example.com").await,
    );
    assert_eq!(parsed.ciphers.first().map(String::as_str), Some("GREASE"));
    assert_eq!(&parsed.ciphers[1..4], ["1301", "1302", "1303"]);
    assert_eq!(parsed.groups.first().map(String::as_str), Some("GREASE"));
    assert!(parsed.groups.contains(&"11ec".to_string()));
    assert!(parsed.key_shares.iter().any(|s| s.starts_with("11ec")));
    assert!(parsed.compress_cert.contains(&"0002".to_string()));
    assert_eq!(parsed.alpn, ["h2", "http/1.1"]);
    assert!(parsed.extensions.contains(&"fe0d".to_string()));
}

#[tokio::test]
async fn boring_hello_shuffles_extensions() {
    let mut orders = BTreeSet::new();
    for _ in 0..6 {
        let parsed = parse_hello(
            "chrome",
            &boring_hello(ClientFingerprint::Chrome, "example.com").await,
        );
        orders.insert(parsed.extensions);
    }
    assert!(orders.len() > 1);
}

#[tokio::test]
async fn boring_sends_no_sni_for_an_ip_target() {
    let with_name = parse_hello(
        "n",
        &boring_hello(ClientFingerprint::Chrome, "example.com").await,
    );
    let with_ip = parse_hello(
        "i",
        &boring_hello(ClientFingerprint::Chrome, "192.0.2.1").await,
    );
    assert!(with_name.extensions.contains(&"0000".to_string()));
    assert!(!with_ip.extensions.contains(&"0000".to_string()));
}
