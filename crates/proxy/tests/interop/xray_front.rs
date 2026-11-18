use super::*;
use bytes::{Buf, Bytes};

pub(super) struct Front {
    pub(super) port: u16,
    task: tokio::task::JoinHandle<()>,
    driver: tokio::task::JoinHandle<()>,
    endpoint: quinn::Endpoint,
}

impl Drop for Front {
    fn drop(&mut self) {
        self.task.abort();
        self.driver.abort();
        self.endpoint.close(0u32.into(), b"");
    }
}

/// A CDN-style H2 front: the origin's single H3 handler owns both session halves.
pub(super) async fn start(origin: u16) -> Front {
    let tls = concord_tls::quic_client_config(
        &concord_tls::TlsOptions {
            skip_cert_verify: true,
            ..Default::default()
        },
        TrustStore::new(b"", vec![]),
        &["h3"],
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));
    let conn = endpoint
        .connect(([127, 0, 0, 1], origin).into(), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, requests) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((io, _)) = listener.accept().await {
            let requests = requests.clone();
            tokio::spawn(async move {
                let mut http = h2::server::handshake(io).await.unwrap();
                while let Some(Ok((request, mut respond))) = http.accept().await {
                    let mut requests = requests.clone();
                    tokio::spawn(async move {
                        let (mut parts, _) = request.into_parts();
                        assert_eq!(parts.method, "GET");
                        parts.version = http::Version::HTTP_3;
                        let Ok(mut stream) = requests
                            .send_request(http::Request::from_parts(parts, ()))
                            .await
                        else {
                            return;
                        };
                        if stream.finish().await.is_err() {
                            return;
                        }
                        let Ok(mut response) = stream.recv_response().await else {
                            return;
                        };
                        *response.version_mut() = http::Version::HTTP_2;
                        let Ok(mut send) = respond.send_response(response, false) else {
                            return;
                        };
                        while let Ok(Some(mut data)) = stream.recv_data().await {
                            let bytes = data.copy_to_bytes(data.remaining());
                            if send.send_data(bytes, false).is_err() {
                                return;
                            }
                        }
                        let _ = send.send_data(Bytes::new(), true);
                    });
                }
            });
        }
    });
    Front {
        port,
        task,
        driver,
        endpoint,
    }
}
