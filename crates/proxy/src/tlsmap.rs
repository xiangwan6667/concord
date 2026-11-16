use std::fmt;
use std::io;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;

use concord_common::Initiator;
use concord_config::proxy::{TlsOpts, deprecated_fingerprint};
use concord_tls::{ClientFingerprint, EchLookup, RealityOptions, TlsConnector, TlsOptions};

use crate::ctx::{BuildCtx, BuildError};
use crate::link::EnvSlot;

/// Asks the resolver of the environment the node was last dialed with, for the proxy-server path.
struct EnvEch {
    slot: EnvSlot,
    query_server_name: String,
}

impl fmt::Debug for EnvEch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvEch")
            .field("query_server_name", &self.query_server_name)
            .finish()
    }
}

#[async_trait]
impl EchLookup for EnvEch {
    async fn config_list(&self, server_name: &str) -> io::Result<Vec<u8>> {
        let env = self
            .slot
            .load_full()
            .ok_or_else(|| io::Error::other("no dial environment for the ECH lookup"))?;
        let name = if self.query_server_name.is_empty() {
            server_name
        } else {
            &self.query_server_name
        };
        env.resolver.resolve_ech(name, Initiator::Proxy).await
    }
}

pub(crate) struct TlsSpec {
    pub(crate) sni: String,
    pub(crate) alpn: Vec<String>,
}

/// This mihomo has dropped `global-client-fingerprint`, so only the node's own value counts;
/// an unknown name is ignored, as `GetFingerprint` does. The deprecated uTLS names are read as
/// the modern fingerprint the config warning names.
pub(crate) fn client_fingerprint(node: &str) -> Option<ClientFingerprint> {
    if node.is_empty() {
        return None;
    }
    let node = deprecated_fingerprint(node).unwrap_or(node);
    match ClientFingerprint::from_str(node) {
        Ok(fingerprint) => Some(fingerprint),
        Err(_) => {
            tracing::warn!("unknown client-fingerprint {node:?} ignored");
            None
        }
    }
}

fn non_empty(text: &str) -> Option<String> {
    Some(text).filter(|t| !t.is_empty()).map(str::to_string)
}

pub(crate) fn looks_up_ech(tls: &TlsOpts) -> bool {
    tls.ech
        .as_ref()
        .is_some_and(|ech| ech.enable && ech.config.is_empty())
}

/// `env` is where the node's dials leave their environment; without it, `ech-opts` with no
/// `config` cannot be served.
pub(crate) fn tls_options(
    tls: &TlsOpts,
    spec: TlsSpec,
    ctx: &BuildCtx,
    env: Option<&EnvSlot>,
) -> Result<TlsOptions, BuildError> {
    let (ech_config_list, ech_lookup) = match tls.ech.as_ref().filter(|ech| ech.enable) {
        None => (None, None),
        Some(ech) if ech.config.is_empty() => {
            let slot = env.ok_or_else(|| {
                BuildError::unsupported(
                    "ech-opts without a config is not implemented for this connection",
                )
            })?;
            let lookup: Arc<dyn EchLookup> = Arc::new(EnvEch {
                slot: slot.clone(),
                query_server_name: ech.query_server_name.clone(),
            });
            (None, Some(lookup))
        }
        Some(ech) => (
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(ech.config.as_bytes())
                    .map_err(|err| {
                        BuildError::invalid(format!(
                            "base64 decode ech config string failed: {err}"
                        ))
                    })?,
            ),
            None,
        ),
    };
    let fingerprint = client_fingerprint(&tls.client_fingerprint);
    let reality = match &tls.reality {
        Some(reality) if !reality.public_key.is_empty() => {
            if !tls.enabled {
                return Err(BuildError::invalid("REALITY requires TLS"));
            }
            if fingerprint.is_none_or(|fp| fp == ClientFingerprint::None) {
                return Err(BuildError::invalid(
                    "REALITY is based on uTLS, please set a client-fingerprint",
                ));
            }
            let mut options = RealityOptions::parse(
                &reality.public_key,
                &reality.short_id,
                reality.support_x25519_mlkem768,
            )?;
            options.client_version = reality.client_version.unwrap_or([1, 8, 2]);
            options.mldsa65_verify.clone_from(&reality.mldsa65_verify);
            Some(options)
        }
        _ => None,
    };
    Ok(TlsOptions {
        server_name: non_empty(&spec.sni),
        alpn: spec.alpn,
        skip_cert_verify: tls.skip_cert_verify,
        name_cert_verify: non_empty(&tls.name_cert_verify),
        fingerprint: non_empty(&tls.fingerprint),
        certificate: client_identity(&tls.certificate, ctx)?,
        private_key: client_identity(&tls.private_key, ctx)?,
        client_fingerprint: fingerprint,
        reality,
        ech_config_list,
        ech_lookup,
    })
}

/// An inline PEM block stays as written; anything else is a file, which mihomo resolves
/// against the home directory and refuses outside it.
fn client_identity(value: &str, ctx: &BuildCtx) -> Result<Option<String>, BuildError> {
    if value.is_empty() || value.contains("-----BEGIN") {
        return Ok(non_empty(value));
    }
    Ok(Some(
        ctx.resolve_file(value)?.to_string_lossy().into_owned(),
    ))
}

pub(crate) fn connector(
    tls: &TlsOpts,
    spec: TlsSpec,
    ctx: &BuildCtx,
    env: Option<&EnvSlot>,
) -> Result<TlsConnector, BuildError> {
    Ok(TlsConnector::new(
        tls_options(tls, spec, ctx, env)?,
        ctx.trust.clone(),
    )?)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use concord_config::proxy::RealityOpts;

    use super::*;

    use concord_common::sync::lock;

    fn spec() -> TlsSpec {
        TlsSpec {
            sni: "a.test".into(),
            alpn: vec!["h2".into()],
        }
    }

    fn test_ctx() -> BuildCtx {
        BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new()))
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn a_client_certificate_path_resolves_inside_the_home_directory_only() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx().with_home(Arc::new(concord_platform::HomeDir::new(dir.path())));
        let tls = |path: &str| TlsOpts {
            enabled: true,
            certificate: path.into(),
            private_key: "-----BEGIN PRIVATE KEY-----".into(),
            ..TlsOpts::default()
        };
        let options = tls_options(&tls("client.pem"), spec(), &ctx, None).unwrap();
        let resolved = options.certificate.unwrap();
        assert!(resolved.ends_with("client.pem") && resolved.len() > "client.pem".len());
        assert_eq!(
            options.private_key.as_deref(),
            Some("-----BEGIN PRIVATE KEY-----")
        );
        let outside = dir.path().parent().unwrap().join("id.pem");
        let err = tls_options(&tls(&outside.to_string_lossy()), spec(), &ctx, None).unwrap_err();
        assert!(
            err.to_string().contains("not subpath of home directory"),
            "{err}"
        );
    }

    #[test]
    fn only_a_known_node_fingerprint_counts() {
        assert_eq!(client_fingerprint(""), None);
        assert_eq!(client_fingerprint("nonsense"), None);
        assert_eq!(
            client_fingerprint("chrome"),
            Some(ClientFingerprint::Chrome)
        );
    }

    #[test]
    fn deprecated_names_are_read_as_their_modern_fingerprint() {
        for name in [
            "chrome_psk",
            "chrome_psk_shuffle",
            "chrome_padding_psk_shuffle",
            "chrome_pq",
            "chrome_pq_psk",
        ] {
            assert_eq!(client_fingerprint(name), Some(ClientFingerprint::Chrome));
        }
        assert_eq!(
            client_fingerprint("randomized"),
            Some(ClientFingerprint::Random)
        );
    }

    #[test]
    fn reality_accepts_a_deprecated_fingerprint() {
        let tls = TlsOpts {
            enabled: true,
            client_fingerprint: "chrome_pq".into(),
            reality: Some(RealityOpts {
                public_key: "A".repeat(43),
                short_id: "ab".into(),
                support_x25519_mlkem768: false,
                ..RealityOpts::default()
            }),
            ..TlsOpts::default()
        };
        let options = tls_options(&tls, spec(), &test_ctx(), None).unwrap();
        assert_eq!(options.client_fingerprint, Some(ClientFingerprint::Chrome));
        assert!(options.reality.is_some());
    }

    #[test]
    fn reality_needs_tls_and_a_fingerprint() {
        let reality = RealityOpts {
            public_key: "A".repeat(43),
            short_id: "ab".into(),
            support_x25519_mlkem768: false,
            ..RealityOpts::default()
        };
        let mut tls = TlsOpts {
            reality: Some(reality),
            ..TlsOpts::default()
        };
        let err = tls_options(&tls, spec(), &test_ctx(), None).unwrap_err();
        assert!(err.to_string().contains("requires TLS"));
        tls.enabled = true;
        let err = tls_options(&tls, spec(), &test_ctx(), None).unwrap_err();
        assert!(err.to_string().contains("client-fingerprint"));
        tls.client_fingerprint = "chrome".into();
        let options = tls_options(&tls, spec(), &test_ctx(), None).unwrap();
        assert!(options.reality.is_some());
    }

    #[test]
    fn identity_fields_reach_the_tls_options() {
        let tls = TlsOpts {
            enabled: true,
            skip_cert_verify: true,
            fingerprint: "AA:BB".into(),
            ..TlsOpts::default()
        };
        let options = tls_options(&tls, spec(), &test_ctx(), None).unwrap();
        assert!(options.skip_cert_verify);
        assert_eq!(options.fingerprint.as_deref(), Some("AA:BB"));
        assert_eq!(options.server_name.as_deref(), Some("a.test"));
        assert_eq!(options.alpn, ["h2"]);
    }

    #[test]
    fn ech_without_a_config_looks_the_record_up() {
        let tls = |config: &str| TlsOpts {
            enabled: true,
            ech: Some(concord_config::proxy::EchOpts {
                enable: true,
                config: config.to_string(),
                ..Default::default()
            }),
            ..TlsOpts::default()
        };
        assert!(
            tls_options(&tls(""), spec(), &test_ctx(), None)
                .unwrap_err()
                .is_unsupported()
        );
        let slot: EnvSlot = Arc::new(arc_swap::ArcSwapOption::empty());
        let options = tls_options(&tls(""), spec(), &test_ctx(), Some(&slot)).unwrap();
        assert!(options.ech_config_list.is_none() && options.ech_lookup.is_some());
        assert!(
            !tls_options(&tls("!"), spec(), &test_ctx(), None)
                .unwrap_err()
                .is_unsupported()
        );
        let options = tls_options(&tls("AQID"), spec(), &test_ctx(), None).unwrap();
        assert_eq!(options.ech_config_list.as_deref(), Some(&[1u8, 2, 3][..]));
        assert!(options.ech_lookup.is_none());
    }

    struct EchRecords(Mutex<Vec<String>>, io::Result<Vec<u8>>);

    #[async_trait]
    impl concord_common::HostResolver for EchRecords {
        async fn lookup(
            &self,
            _: &str,
            _: concord_common::IpVersion,
            _: Initiator,
        ) -> io::Result<concord_common::LookupIps> {
            Err(io::Error::other("no ip lookups here"))
        }

        async fn resolve_ech(&self, host: &str, initiator: Initiator) -> io::Result<Vec<u8>> {
            assert_eq!(initiator, Initiator::Proxy);
            lock(&self.0).push(host.to_string());
            match &self.1 {
                Ok(list) => Ok(list.clone()),
                Err(err) => Err(io::Error::new(err.kind(), err.to_string())),
            }
        }
    }

    async fn handshake_with(
        query_server_name: &str,
        answer: io::Result<Vec<u8>>,
    ) -> (Arc<EchRecords>, io::Result<()>) {
        let tls = TlsOpts {
            enabled: true,
            ech: Some(concord_config::proxy::EchOpts {
                enable: true,
                query_server_name: query_server_name.to_string(),
                ..Default::default()
            }),
            ..TlsOpts::default()
        };
        let slot: EnvSlot = Arc::new(arc_swap::ArcSwapOption::empty());
        let connector = connector(
            &tls,
            spec(),
            &BuildCtx::new(concord_tls::TrustStore::new(b"", Vec::new())),
            Some(&slot),
        )
        .unwrap();
        let records = Arc::new(EchRecords(Mutex::default(), answer));
        let mut env = crate::testing::test_env();
        env.resolver = records.clone();
        let (near, _far) = tokio::io::duplex(1024);
        let early = connector.connect(Box::new(near), "a.test").await.map(drop);
        assert!(early.is_err(), "no environment yet");
        slot.store(Some(Arc::new(env)));
        let (near, _far) = tokio::io::duplex(1024);
        let result = connector.connect(Box::new(near), "a.test").await.map(drop);
        (records, result)
    }

    #[tokio::test]
    async fn the_lookup_asks_for_the_sni_or_the_query_server_name() {
        let miss = || Err(io::Error::other("no ECH config found in DNS records"));
        let (records, result) = handshake_with("", miss()).await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "resolve ECH config error: no ECH config found in DNS records"
        );
        assert_eq!(*lock(&records.0), ["a.test"]);
        let (records, _) = handshake_with("ech.example.com", miss()).await;
        assert_eq!(*lock(&records.0), ["ech.example.com"]);
    }

    #[tokio::test]
    async fn an_unusable_answer_fails_the_handshake_not_the_build() {
        let (_, result) = handshake_with("", Ok(vec![1, 2, 3])).await;
        assert!(result.unwrap_err().to_string().contains("ech"));
    }
}
