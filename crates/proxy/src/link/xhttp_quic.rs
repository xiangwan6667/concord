use std::sync::Arc;
use std::time::Duration;

use concord_common::{Address, DialCx, Initiator};
use concord_config::proxy::TlsOpts;
use concord_transport::QuicDialFn;

use super::{EnvSlot, POOL_DIALS, pool_chain};
use crate::ctx::{BuildCtx, BuildError};
use crate::node::Egress;
use crate::quic::{ObfsSpec, QuicLink, quic_crypto, transport_config};
use crate::tlsmap::{TlsSpec, tls_options};

pub(super) fn dial(
    egress: &Egress,
    tls: &TlsOpts,
    (server, port): (&str, u16),
    slot: &EnvSlot,
    ctx: &BuildCtx,
    period: i64,
) -> Result<QuicDialFn, BuildError> {
    if !tls.enabled {
        return Err(BuildError::invalid("xhttp HTTP/3 requires TLS"));
    }
    if tls.shadow_tls.is_some() {
        return Err(BuildError::invalid(
            "xhttp HTTP/3 does not support ShadowTLS",
        ));
    }
    if tls.jls.is_some() {
        return Err(BuildError::invalid("xhttp HTTP/3 does not support JLS"));
    }
    if tls
        .reality
        .as_ref()
        .is_some_and(|r| !r.public_key.is_empty())
    {
        return Err(BuildError::invalid("xhttp HTTP/3 does not support REALITY"));
    }
    let sni = if tls.server_name.is_empty() {
        server.to_string()
    } else {
        tls.server_name.clone()
    };
    let options = tls_options(
        tls,
        TlsSpec {
            sni: sni.clone(),
            alpn: vec!["h3".into()],
        },
        ctx,
        Some(slot),
    )?;
    let link = Arc::new(QuicLink {
        egress: egress.clone(),
        server: Address::new(server, port),
        server_name: Some(sni),
        crypto: quic_crypto(&options, ctx.trust.clone(), &["h3"], slot.clone())?,
        transport: Arc::new(h3_transport(period)?),
        obfs: ObfsSpec::None,
        hop: None,
        datagram_frame: None,
        tasks: ctx.tasks.clone(),
    });
    let slot = slot.clone();
    Ok(Arc::new(move || {
        let (link, slot) = (link.clone(), slot.clone());
        Box::pin(async move {
            let chain = pool_chain(link.egress.name())?;
            let env = slot
                .load_full()
                .ok_or_else(|| std::io::Error::other("xhttp QUIC dial without an environment"))?;
            POOL_DIALS
                .scope(chain, async {
                    let cx = DialCx::new(&env, Initiator::Proxy, None);
                    let conn = Arc::new(link.connect_any(&cx).await?);
                    Ok((conn.conn.clone(), conn as Arc<dyn Send + Sync>))
                })
                .await
        })
    }))
}

const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const KEEP_ALIVE: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
struct H3Settings {
    idle: Duration,
    keep_alive: Option<Duration>,
    server_bidi: u32,
    datagram_buffer: Option<usize>,
}

impl H3Settings {
    fn new(period: i64) -> Self {
        Self {
            idle: IDLE_TIMEOUT,
            keep_alive: match period {
                0 => Some(KEEP_ALIVE),
                value if value < 0 => None,
                value => Some(Duration::from_secs(value.unsigned_abs()).min(IDLE_TIMEOUT / 2)),
            },
            server_bidi: 0,
            datagram_buffer: None,
        }
    }

    fn transport(self) -> Result<quinn::TransportConfig, BuildError> {
        let idle = self
            .idle
            .try_into()
            .map_err(|err| BuildError::invalid(format!("xhttp idle timeout: {err}")))?;
        let mut transport = transport_config();
        transport
            .max_concurrent_bidi_streams(self.server_bidi.into())
            .max_idle_timeout(Some(idle))
            .keep_alive_interval(self.keep_alive)
            .datagram_receive_buffer_size(self.datagram_buffer);
        Ok(transport)
    }
}

fn h3_transport(period: i64) -> Result<quinn::TransportConfig, BuildError> {
    H3Settings::new(period).transport()
}

#[cfg(test)]
mod tests {
    use super::*;
    use concord_common::{BoxStream, CoreError, NodeDialer, PacketSession};
    use concord_config::{Capabilities, ProxyParse, parse_proxy};
    use serde_json::{Value, json};

    fn outbound(extra: Value) -> Result<Arc<dyn concord_common::Outbound>, BuildError> {
        let mut value = json!({"name": "h3", "type": "vless", "server": "127.0.0.1", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "tls": true, "network": "xhttp", "alpn": ["h3"],
            "xhttp-opts": {"path": "/xh"}});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let ProxyParse::Ok(def) =
            parse_proxy(value.as_object().unwrap(), &Capabilities::full()).unwrap()
        else {
            panic!("quarantined");
        };
        crate::build_outbound(
            &def,
            &BuildCtx::new(concord_tls::TrustStore::new(b"", vec![])),
        )
    }

    #[test]
    fn xhttp_h3_requires_tls_and_rejects_reality() {
        assert!(outbound(json!({})).is_ok());
        assert!(
            outbound(json!({"shadow-tls-opts": {"password": "pw", "version": 3}}))
                .err()
                .unwrap()
                .to_string()
                .contains("HTTP/3 does not support ShadowTLS")
        );
        assert!(
            outbound(json!({"jls-opts": {"username": "name", "password": "secret"}}))
                .err()
                .unwrap()
                .to_string()
                .contains("HTTP/3 does not support JLS")
        );
        assert!(
            outbound(json!({"tls": false}))
                .err()
                .unwrap()
                .to_string()
                .contains("requires TLS")
        );
        assert!(outbound(json!({"client-fingerprint": "chrome", "reality-opts": {"public-key": "A".repeat(43)}})).err().unwrap().to_string().contains("HTTP/3 does not support REALITY"));
    }

    #[test]
    fn xhttp_h3_quic_settings_match_reference() {
        for (period, seconds) in [(0, Some(10)), (-1, None), (37, Some(37)), (400, Some(150))] {
            assert_eq!(
                H3Settings::new(period),
                H3Settings {
                    idle: Duration::from_secs(300),
                    keep_alive: seconds.map(Duration::from_secs),
                    server_bidi: 0,
                    datagram_buffer: None,
                }
            );
        }
    }

    #[tokio::test]
    async fn xhttp_h3_wire_disables_server_bidi_and_datagrams() {
        use concord_config::proxy::CommonOpts;
        use futures_util::FutureExt;
        let (endpoint, port) = crate::testing::quic_server(b"h3", |socket| socket);
        let ctx = BuildCtx::new(concord_tls::TrustStore::new(b"", vec![]));
        let slot = Arc::new(arc_swap::ArcSwapOption::new(Some(Arc::new(
            crate::testing::test_env(),
        ))));
        let dial = dial(
            &Egress::new("h3", &CommonOpts::default()),
            &TlsOpts {
                enabled: true,
                skip_cert_verify: true,
                server_name: "localhost".into(),
                ..Default::default()
            },
            ("127.0.0.1", port),
            &slot,
            &ctx,
            0,
        )
        .unwrap();
        let (client, server) = tokio::join!(dial(), async {
            endpoint.accept().await.unwrap().await.unwrap()
        });
        let (conn, _guard) = client.unwrap();
        assert_eq!(server.max_datagram_size(), None);
        assert!(server.open_bi().now_or_never().is_none());
        conn.close(0u32.into(), b"done");
    }

    struct Hop;

    #[async_trait::async_trait]
    impl NodeDialer for Hop {
        async fn dial_via(
            &self,
            _: &str,
            _: &DialCx<'_>,
            _: &Address,
        ) -> std::io::Result<BoxStream> {
            panic!("HTTP/3 must dial UDP");
        }

        async fn associate_via(
            &self,
            name: &str,
            _: &DialCx<'_>,
            _: &Address,
        ) -> std::io::Result<Arc<dyn PacketSession>> {
            Err(CoreError::UnknownNode(name.to_owned()).into())
        }
    }

    #[tokio::test]
    async fn xhttp_h3_dialer_proxy_uses_a_udp_association() {
        let outbound = outbound(json!({"dialer-proxy": "udp-hop"})).unwrap();
        let env = crate::testing::test_env_with(Arc::new(Hop));
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let err = outbound
            .connect(&cx, &Address::new("example.com", 80))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(CoreError::of(&err), Some(CoreError::UnknownNode(name)) if name == "udp-hop"),
            "{err}"
        );
    }
}
