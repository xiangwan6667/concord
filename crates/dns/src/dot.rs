use std::io;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use concord_common::sync::lock;
use concord_tls::TlsOptions;
use hickory_proto::op::Message;
use rustls_pki_types::ServerName;

use crate::client::{BoxIo, Client, Params, exchange_framed, with_random_id, with_timeout};
use crate::dialer::{Connector, Cx};
use crate::resets::{Resets, Ticket};

const MAX_IDLE: usize = 8;

pub(crate) fn tls_connector(
    connector: &Connector,
    params: &Params<'_>,
    alpn: &[&str],
) -> io::Result<tokio_rustls::TlsConnector> {
    let options = TlsOptions {
        skip_cert_verify: params.is_true("skip-cert-verify"),
        name_cert_verify: params.get("name-cert-verify").map(str::to_string),
        ..TlsOptions::default()
    };
    let config =
        concord_tls::http_client_config_for(&options, Arc::clone(&connector.shared().trust), alpn)
            .map_err(io::Error::other)?;
    Ok(tokio_rustls::TlsConnector::from(config))
}

pub(crate) fn server_name(host: &str) -> io::Result<ServerName<'static>> {
    ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))
}

/// `tls://`: connections stay open between queries, newest first.
pub(crate) struct DotClient {
    host: String,
    port: u16,
    connector: Arc<Connector>,
    tls: tokio_rustls::TlsConnector,
    reuse: bool,
    idle: Mutex<Vec<BoxIo>>,
    resets: Resets,
}

impl DotClient {
    pub(crate) fn new(
        host: String,
        port: u16,
        connector: Arc<Connector>,
        params: &Params<'_>,
    ) -> io::Result<Self> {
        let tls = tls_connector(&connector, params, &[])?;
        Ok(DotClient {
            host,
            port,
            connector,
            tls,
            reuse: !params.is_true("disable-reuse"),
            idle: Mutex::new(Vec::new()),
            resets: Resets::new(),
        })
    }

    fn take_idle(&self) -> Option<BoxIo> {
        if !self.reuse {
            return None;
        }
        lock(&self.idle).pop()
    }

    fn put_idle(&self, conn: BoxIo, ticket: Ticket) {
        if !self.reuse {
            return;
        }
        {
            let mut idle = lock(&self.idle);
            if !self.resets.none_since(ticket) {
                return;
            }
            if idle.len() >= MAX_IDLE {
                idle.remove(0);
            }
            idle.push(conn);
        }
    }

    async fn dial(&self, cx: Cx) -> io::Result<BoxIo> {
        let tcp = self.connector.tcp(&self.host, self.port, cx).await?;
        let name = server_name(&self.host)?;
        let tls = self.tls.connect(name, tcp).await?;
        Ok(Box::new(tls))
    }
}

#[async_trait]
impl Client for DotClient {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        let original = req.metadata.id;
        let req = with_random_id(req);
        with_timeout(async {
            loop {
                let ticket = self.resets.ticket();
                let (mut conn, reused) = match self.take_idle() {
                    Some(conn) => (conn, true),
                    None => (self.resets.dial(ticket, self.dial(cx)).await?, false),
                };
                match exchange_framed(&mut conn, &req).await {
                    Ok(mut resp) => {
                        resp.metadata.id = original;
                        self.put_idle(conn, ticket);
                        return Ok(resp);
                    }
                    Err(err) if !reused => return Err(err),
                    Err(_) => {}
                }
            }
        })
        .await
    }

    fn address(&self) -> String {
        format!("tls://{}:{}", self.host, self.port)
    }

    fn reset(&self) {
        self.resets.bump();
        {
            let mut idle = lock(&self.idle);
            idle.clear();
        }
    }
}
