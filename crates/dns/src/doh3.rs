use std::io;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use concord_common::sync::lock;
use concord_tls::TlsOptions;
use hickory_proto::op::Message;
use quinn::crypto::rustls::QuicClientConfig;

use crate::client::{
    Client, ClientRef, Params, checked, decode, encode, with_random_id, with_timeout,
};
use crate::dialer::{Connector, Cx};
use crate::doh::DohTarget;
use crate::shared_dial::SharedDial;

const ALPN: &str = "h3";
const MAX_BODY: usize = 65_535;

type Requests = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Clone)]
struct Session {
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    requests: Requests,
}

/// `https://` over HTTP/3.
pub(crate) struct Doh3Client {
    target: DohTarget,
    connector: Arc<Connector>,
    config: quinn::ClientConfig,
    session: SharedDial<Session>,
}

impl Doh3Client {
    pub(crate) fn new(
        target: DohTarget,
        connector: Arc<Connector>,
        params: &Params<'_>,
    ) -> io::Result<Self> {
        let options = TlsOptions {
            skip_cert_verify: params.is_true("skip-cert-verify"),
            name_cert_verify: params.get("name-cert-verify").map(str::to_string),
            ..TlsOptions::default()
        };
        let tls = concord_tls::quic_client_config(
            &options,
            Arc::clone(&connector.shared().trust),
            &[ALPN],
        )
        .map_err(io::Error::other)?;
        let crypto = QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
        Ok(Doh3Client {
            target,
            connector,
            config: quinn::ClientConfig::new(Arc::new(crypto)),
            session: SharedDial::new(),
        })
    }

    async fn dial(&self, cx: Cx) -> io::Result<Session> {
        let (socket, peer) = self
            .connector
            .quic_socket(&self.target.host, self.target.port, cx)
            .await?;
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(self.config.clone());
        let conn = endpoint
            .connect(peer, self.target.host.trim_matches(['[', ']']))
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        let (mut driver, requests) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Ok(Session {
            _endpoint: endpoint,
            conn,
            requests,
        })
    }

    async fn round_trip(&self, mut requests: Requests, query: &[u8]) -> io::Result<Message> {
        let request = self.target.request(query, true)?.map(|_| ());
        let mut stream = requests
            .send_request(request)
            .await
            .map_err(io::Error::other)?;
        stream.finish().await.map_err(io::Error::other)?;
        let response = stream.recv_response().await.map_err(io::Error::other)?;
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await.map_err(io::Error::other)? {
            if body.len() + chunk.remaining() > MAX_BODY {
                return Err(io::Error::other("DoH3 response body too large"));
            }
            body.extend_from_slice(chunk.chunk());
        }
        if response.status() != http::StatusCode::OK {
            return Err(io::Error::other(format!(
                "expected status 200, got {} from {}",
                response.status().as_u16(),
                self.address()
            )));
        }
        decode(&body)
    }
}

#[async_trait]
impl Client for Doh3Client {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        let original = req.metadata.id;
        let mut query = with_random_id(req);
        query.metadata.id = 0;
        let bytes = encode(&query)?;
        with_timeout(async {
            let mut reused = true;
            loop {
                let session = self
                    .session
                    .get(
                        |session| session.conn.close_reason().is_none(),
                        self.dial(cx),
                    )
                    .await?;
                reused &= session.reused;
                let answer = self
                    .round_trip(session.value.requests, &bytes)
                    .await
                    .and_then(|resp| checked(&query, resp));
                match answer {
                    Ok(mut resp) => {
                        resp.metadata.id = original;
                        return Ok(resp);
                    }
                    Err(err) => {
                        close(self.session.take());
                        if !reused {
                            return Err(err);
                        }
                        reused = false;
                    }
                }
            }
        })
        .await
    }

    fn address(&self) -> String {
        format!("https://{}{}", self.target.host_port(), self.target.path())
    }

    fn reset(&self) {
        close(self.session.reset());
    }
}

fn close(session: Option<Session>) {
    if let Some(session) = session {
        session.conn.close(0u32.into(), b"");
    }
}

/// `prefer-h3`: the first answer decides, as mihomo's probe of QUIC against TLS does.
/// A later failure of HTTP/3 falls back to the other transport for that query.
pub(crate) struct PreferH3Client {
    h3: ClientRef,
    h2: ClientRef,
    chosen: Mutex<Option<Choice>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Choice {
    H3,
    H2,
}

impl PreferH3Client {
    pub(crate) fn new(h3: ClientRef, h2: ClientRef) -> Self {
        PreferH3Client {
            h3,
            h2,
            chosen: Mutex::new(None),
        }
    }

    fn chosen(&self) -> Option<Choice> {
        *lock(&self.chosen)
    }

    fn choose(&self, choice: Choice) {
        {
            let mut slot = lock(&self.chosen);
            slot.get_or_insert(choice);
        }
    }
}

#[async_trait]
impl Client for PreferH3Client {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        match self.chosen() {
            Some(Choice::H2) => self.h2.exchange(req, cx).await,
            Some(Choice::H3) => match self.h3.exchange(req, cx).await {
                Ok(resp) => Ok(resp),
                Err(err) => {
                    tracing::debug!("{} fell back to HTTP/2 after {err}", self.h3.address());
                    self.h2.exchange(req, cx).await
                }
            },
            None => {
                let h3 = self.h3.exchange(req, cx);
                let h2 = self.h2.exchange(req, cx);
                tokio::pin!(h3, h2);
                tokio::select! {
                    first = &mut h3 => match first {
                        Ok(resp) => {
                            self.choose(Choice::H3);
                            Ok(resp)
                        }
                        Err(_) => {
                            let resp = h2.await?;
                            self.choose(Choice::H2);
                            Ok(resp)
                        }
                    },
                    first = &mut h2 => match first {
                        Ok(resp) => {
                            self.choose(Choice::H2);
                            Ok(resp)
                        }
                        Err(_) => {
                            let resp = h3.await?;
                            self.choose(Choice::H3);
                            Ok(resp)
                        }
                    },
                }
            }
        }
    }

    fn address(&self) -> String {
        self.h2.address()
    }

    fn reset(&self) {
        self.h3.reset();
        self.h2.reset();
    }
}
