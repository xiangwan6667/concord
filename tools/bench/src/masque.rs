use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn serve(listen: SocketAddr) -> Result<bool, String> {
    tokio::runtime::Runtime::new()
        .map_err(|e| e.to_string())?
        .block_on(server(listen))
        .map(|()| true)
        .map_err(|e| e.to_string())
}

async fn server(listen: SocketAddr) -> io::Result<()> {
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(io::Error::other)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(
        vec![pair.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(pair.signing_key.serialize_der()).into(),
    )
    .map_err(io::Error::other)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(io::Error::other)?,
        )),
        listen,
    )?;
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(error) = connection(incoming).await {
                eprintln!("MASQUE peer: {error}");
            }
        });
    }
    Ok(())
}

async fn connection(incoming: quinn::Incoming) -> io::Result<()> {
    let conn = incoming.await.map_err(io::Error::other)?;
    let mut http = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(io::Error::other)?;
    while let Some(resolver) = http.accept().await.map_err(io::Error::other)? {
        tokio::spawn(async move {
            let request = async {
                let (request, mut stream) =
                    resolver.resolve_request().await.map_err(io::Error::other)?;
                if request.method() != http::Method::CONNECT
                    || request.extensions().get::<h3::ext::Protocol>().is_some()
                {
                    stream
                        .send_response(
                            http::Response::builder()
                                .status(405)
                                .body(())
                                .map_err(io::Error::other)?,
                        )
                        .await
                        .map_err(io::Error::other)?;
                    return stream.finish().await.map_err(io::Error::other);
                }
                let target = request
                    .uri()
                    .authority()
                    .ok_or_else(|| io::Error::other("CONNECT has no authority"))?
                    .as_str();
                let tcp = match tokio::net::TcpStream::connect(target).await {
                    Ok(tcp) => tcp,
                    Err(err) => {
                        stream
                            .send_response(
                                http::Response::builder()
                                    .status(502)
                                    .body(())
                                    .map_err(io::Error::other)?,
                            )
                            .await
                            .map_err(io::Error::other)?;
                        stream.finish().await.map_err(io::Error::other)?;
                        return Err(err);
                    }
                };
                tcp.set_nodelay(true)?;
                stream
                    .send_response(http::Response::new(()))
                    .await
                    .map_err(io::Error::other)?;
                let (mut send, mut recv) = stream.split();
                let (mut read, mut write) = tcp.into_split();
                let upload = async {
                    while let Some(mut data) = recv.recv_data().await.map_err(io::Error::other)? {
                        while data.has_remaining() {
                            let n = write.write(data.chunk()).await?;
                            if n == 0 {
                                return Err(io::ErrorKind::WriteZero.into());
                            }
                            data.advance(n);
                        }
                    }
                    write.shutdown().await
                };
                let download = async {
                    // Match tokio's copy buffer; no extra batching or delay in the peer.
                    let mut buffer = [0; 8192];
                    loop {
                        let n = read.read(&mut buffer).await?;
                        if n == 0 {
                            return send.finish().await.map_err(io::Error::other);
                        }
                        send.send_data(Bytes::copy_from_slice(&buffer[..n]))
                            .await
                            .map_err(io::Error::other)?;
                    }
                };
                tokio::try_join!(upload, download)?;
                Ok::<(), io::Error>(())
            };
            if let Err(error) = request.await {
                eprintln!("MASQUE stream: {error}");
            }
        });
    }
    Ok(())
}
