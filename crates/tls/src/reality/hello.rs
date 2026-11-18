use aws_lc_rs::agreement::{self, ECDH_P256};
use rand::seq::SliceRandom;

use crate::TlsError;
use crate::fingerprints::{
    Ext, FingerprintSpec, GREASE, GROUP_P256, GROUP_X25519, GROUP_X25519_MLKEM768, KeyShareKind,
};

pub(crate) const SESSION_ID_OFFSET: usize = 39;
pub(crate) const SESSION_ID_LEN: usize = 32;

pub(crate) struct HelloParams<'a> {
    pub server_name: Option<&'a str>,
    pub jls: bool,
    pub alpn: Option<&'a [String]>,
    pub random: &'a [u8; 32],
    pub x25519_public: &'a [u8; 32],
    pub mlkem_encapsulation_key: Option<&'a [u8]>,
}

struct Grease {
    cipher: u16,
    group: u16,
    extension1: u16,
    extension2: u16,
    version: u16,
}

impl Grease {
    fn random() -> Self {
        let seed: [u8; 5] = rand::random();
        let value = |byte: u8| u16::from((byte & 0xf0) | 0x0a) * 0x0101;
        let [cipher, group, e1, e2, version] = seed;
        let extension1 = value(e1);
        let mut extension2 = value(e2);
        if extension2 == extension1 {
            extension2 ^= 0x1010;
        }
        Self {
            cipher: value(cipher),
            group: value(group),
            extension1,
            extension2,
            version: value(version),
        }
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_len16(out: &mut Vec<u8>, len: usize) -> Result<(), TlsError> {
    let len = u16::try_from(len).map_err(|_| TlsError::Config("tls field too long".into()))?;
    put_u16(out, len);
    Ok(())
}

fn put_u16_list(out: &mut Vec<u8>, values: &[u16], grease: u16) -> Result<(), TlsError> {
    put_len16(out, values.len() * 2)?;
    for value in values {
        put_u16(out, if *value == GREASE { grease } else { *value });
    }
    Ok(())
}

fn alpn_data(protocols: &[String]) -> Result<Vec<u8>, TlsError> {
    let mut list = Vec::new();
    for proto in protocols {
        let len = u8::try_from(proto.len())
            .ok()
            .filter(|len| *len > 0)
            .ok_or_else(|| TlsError::Config(format!("invalid ALPN protocol {proto:?}")))?;
        list.push(len);
        list.extend_from_slice(proto.as_bytes());
    }
    let mut out = Vec::with_capacity(2 + list.len());
    put_len16(&mut out, list.len())?;
    out.extend_from_slice(&list);
    Ok(out)
}

fn p256_decoy() -> Result<Vec<u8>, TlsError> {
    let key = agreement::PrivateKey::generate(&ECDH_P256)
        .and_then(|key| key.compute_public_key())
        .map_err(|_| TlsError::Handshake("p-256 key share".into()))?;
    Ok(key.as_ref().to_vec())
}

fn grease_ech(aeads: &[u16], payload_lens: &[u16]) -> Vec<u8> {
    let pick = |len: usize| rand::random_range(0..len.max(1));
    let aead = aeads.get(pick(aeads.len())).copied().unwrap_or(1);
    let payload = usize::from(
        payload_lens
            .get(pick(payload_lens.len()))
            .copied()
            .unwrap_or(144),
    );
    let mut out = Vec::with_capacity(42 + payload);
    out.push(0);
    put_u16(&mut out, 0x0001);
    put_u16(&mut out, aead);
    out.push(rand::random());
    put_u16(&mut out, 32);
    out.extend_from_slice(&rand::random::<[u8; 32]>());
    put_u16(&mut out, u16::try_from(payload).unwrap_or(144));
    let start = out.len();
    out.resize(start + payload, 0);
    if let Some(tail) = out.get_mut(start..) {
        rand::fill(tail);
    }
    out
}

fn wanted_group(group: u16, mlkem: bool) -> bool {
    mlkem || group != GROUP_X25519_MLKEM768
}

/// Encodes the ClientHello handshake message (4-byte header included) the way
/// `spec` would send it, with a zeroed 32-byte session id at
/// [`SESSION_ID_OFFSET`] for the REALITY seal. `mlkem` keeps the hybrid
/// X25519MLKEM768 group when the spec offers it.
pub(crate) fn build_client_hello(
    spec: &FingerprintSpec,
    params: &HelloParams<'_>,
) -> Result<Vec<u8>, TlsError> {
    let mlkem = params.mlkem_encapsulation_key.is_some();
    let grease = Grease::random();

    let mut order: Vec<Ext> = spec.extensions.to_vec();
    if spec.permute_extensions {
        let movable: Vec<usize> = order
            .iter()
            .enumerate()
            .filter(|(_, ext)| !ext.is_pinned())
            .map(|(index, _)| index)
            .collect();
        let mut shuffled: Vec<Ext> = movable
            .iter()
            .filter_map(|i| order.get(*i).copied())
            .collect();
        shuffled.shuffle(&mut rand::rng());
        for (slot, ext) in movable.into_iter().zip(shuffled) {
            if let Some(target) = order.get_mut(slot) {
                *target = ext;
            }
        }
    }

    let mut body = Vec::with_capacity(1024);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(params.random);
    body.push(SESSION_ID_LEN as u8);
    body.extend_from_slice(&[0u8; SESSION_ID_LEN]);
    put_u16_list(&mut body, spec.cipher_suites, grease.cipher)?;
    body.extend_from_slice(&[1, 0]);

    let protocols: Vec<String> = params.alpn.map_or_else(
        || spec.alpn.iter().map(|proto| (*proto).to_owned()).collect(),
        <[String]>::to_vec,
    );

    let mut exts = Vec::with_capacity(768);
    let mut greases_seen = 0;
    let mut padded = false;
    for ext in &order {
        let (kind, data): (u16, Vec<u8>) = match *ext {
            Ext::Grease => {
                greases_seen += 1;
                if greases_seen == 1 {
                    (grease.extension1, Vec::new())
                } else {
                    (grease.extension2, vec![0])
                }
            }
            Ext::ServerName => {
                let Some(name) = params.server_name else {
                    continue;
                };
                let mut data = Vec::with_capacity(5 + name.len());
                put_len16(&mut data, name.len() + 3)?;
                data.push(0);
                put_len16(&mut data, name.len())?;
                data.extend_from_slice(name.as_bytes());
                (0, data)
            }
            Ext::ExtendedMasterSecret => (23, Vec::new()),
            Ext::RenegotiationInfo => (0xff01, vec![0]),
            Ext::SupportedGroups => {
                let groups: Vec<u16> = spec
                    .groups
                    .iter()
                    .copied()
                    .filter(|group| wanted_group(*group, mlkem))
                    .collect();
                let mut data = Vec::new();
                put_u16_list(&mut data, &groups, grease.group)?;
                (10, data)
            }
            Ext::PointFormats => (11, vec![1, 0]),
            Ext::SessionTicket => (35, Vec::new()),
            Ext::Alpn => {
                if protocols.is_empty() {
                    continue;
                }
                (16, alpn_data(&protocols)?)
            }
            Ext::StatusRequest => (5, vec![1, 0, 0, 0, 0]),
            Ext::SignatureAlgorithms => {
                let mut data = Vec::new();
                put_u16_list(&mut data, spec.signature_algorithms, GREASE)?;
                (13, data)
            }
            Ext::SignatureAlgorithmsCert(algorithms) => {
                let mut data = Vec::new();
                put_u16_list(&mut data, algorithms, GREASE)?;
                (50, data)
            }
            Ext::Sct => (18, Vec::new()),
            Ext::KeyShare => {
                let mut shares = Vec::with_capacity(1300);
                for share in spec.key_shares {
                    match share {
                        KeyShareKind::Grease => {
                            put_u16(&mut shares, grease.group);
                            put_u16(&mut shares, 1);
                            shares.push(0);
                        }
                        KeyShareKind::X25519MlKem768 => {
                            let Some(encapsulation) = params.mlkem_encapsulation_key else {
                                continue;
                            };
                            put_u16(&mut shares, GROUP_X25519_MLKEM768);
                            put_len16(&mut shares, encapsulation.len() + 32)?;
                            shares.extend_from_slice(encapsulation);
                            shares.extend_from_slice(params.x25519_public);
                        }
                        KeyShareKind::X25519 => {
                            put_u16(&mut shares, GROUP_X25519);
                            put_u16(&mut shares, 32);
                            shares.extend_from_slice(params.x25519_public);
                        }
                        KeyShareKind::P256 => {
                            let point = p256_decoy()?;
                            put_u16(&mut shares, GROUP_P256);
                            put_len16(&mut shares, point.len())?;
                            shares.extend_from_slice(&point);
                        }
                    }
                }
                let mut data = Vec::with_capacity(2 + shares.len());
                put_len16(&mut data, shares.len())?;
                data.extend_from_slice(&shares);
                (51, data)
            }
            Ext::PskModes => (45, vec![1, 1]),
            Ext::SupportedVersions => {
                let mut data = vec![u8::try_from(spec.versions.len() * 2).unwrap_or(0)];
                for version in spec.versions {
                    put_u16(
                        &mut data,
                        if *version == GREASE {
                            grease.version
                        } else {
                            *version
                        },
                    );
                }
                (43, data)
            }
            Ext::CompressCertificate => {
                let mut data = vec![u8::try_from(spec.cert_compression.len() * 2).unwrap_or(0)];
                for algo in spec.cert_compression {
                    put_u16(&mut data, *algo);
                }
                (27, data)
            }
            Ext::Alps(codepoint) => {
                if params.jls && !protocols.iter().any(|proto| proto == "h2") {
                    continue;
                }
                let mut list = Vec::new();
                for proto in spec.alps_protocols {
                    list.push(u8::try_from(proto.len()).unwrap_or(0));
                    list.extend_from_slice(proto.as_bytes());
                }
                let mut data = Vec::new();
                put_len16(&mut data, list.len())?;
                data.extend_from_slice(&list);
                (codepoint, data)
            }
            Ext::EchGrease => {
                let Some(ech) = spec.ech_grease else {
                    continue;
                };
                (0xfe0d, grease_ech(ech.aeads, ech.payload_lens))
            }
            Ext::DelegatedCredentials => {
                let mut data = Vec::new();
                put_u16_list(&mut data, spec.delegated_credentials, GREASE)?;
                (34, data)
            }
            Ext::RecordSizeLimit => (28, spec.record_size_limit.to_be_bytes().to_vec()),
            Ext::NextProtocolNegotiation => (13172, Vec::new()),
            Ext::ChannelId => (30032, Vec::new()),
            Ext::Padding => {
                padded = true;
                continue;
            }
        };
        put_u16(&mut exts, kind);
        put_len16(&mut exts, data.len())?;
        exts.extend_from_slice(&data);
    }

    // BoringSSL pads hellos that land in 256..511 bytes up to 512.
    let unpadded = 4 + body.len() + 2 + exts.len();
    if padded && unpadded > 0xff && unpadded < 0x200 {
        let mut pad = 0x200 - unpadded;
        pad = if pad >= 5 { pad - 4 } else { 1 };
        put_u16(&mut exts, 21);
        put_len16(&mut exts, pad)?;
        exts.resize(exts.len() + pad, 0);
    }

    put_len16(&mut body, exts.len())?;
    body.extend_from_slice(&exts);

    let mut hello = Vec::with_capacity(4 + body.len());
    hello.push(1);
    let len = body.len();
    hello.extend_from_slice(&[
        u8::try_from(len >> 16).unwrap_or(0),
        u8::try_from((len >> 8) & 0xff).unwrap_or(0),
        u8::try_from(len & 0xff).unwrap_or(0),
    ]);
    hello.extend_from_slice(&body);
    Ok(hello)
}
