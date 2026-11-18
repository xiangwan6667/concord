use std::io;
use std::time::Duration;

use concord_common::{BoxStream, DialCx};
use concord_transport::h2io::{Activity, H2Body, Incoming, client_builder, spawn_connection};
use http::{Method, Request, Uri};

use super::config::Config;
use crate::quic::io_error;

pub(super) async fn connect(config: &Config, cx: &DialCx<'_>) -> io::Result<BoxStream> {
    let io = config.link.egress.dial(cx, &config.link.server).await?;
    let tls = concord_tls::connect_config(&config.tls, &config.sni, io).await?;
    if tls.negotiated_alpn() != Some(b"h2") {
        return Err(io::Error::other("MASQUE server did not negotiate h2"));
    }
    connect_io(Box::new(tls), &config.uri, &config.link.tasks).await
}

pub(super) async fn connect_io(
    io: BoxStream,
    uri: &Uri,
    tasks: &concord_common::Tasks,
) -> io::Result<BoxStream> {
    let authority = uri
        .authority()
        .ok_or_else(|| io::Error::other("MASQUE URI has no authority"))?;
    let authority = if authority.port().is_some() {
        authority.to_string()
    } else {
        format!("{}:443", authority.as_str())
    };
    let uri = Uri::builder()
        .authority(authority)
        .build()
        .map_err(io_error)?;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .header("accept-encoding", "gzip")
        .body(())
        .map_err(io_error)?;
    let (sender, connection) = client_builder()
        .max_header_list_size(10 << 20)
        .handshake::<_, bytes::Bytes>(io)
        .await
        .map_err(io_error)?;
    let activity = Activity::new();
    spawn_connection(
        tasks,
        connection,
        Some(Duration::from_secs(30)),
        activity.clone(),
    );
    let mut sender = sender.ready().await.map_err(io_error)?;
    let (response, send) = sender.send_request(request, false).map_err(io_error)?;
    let response = response.await.map_err(io_error)?;
    if response.status() != http::StatusCode::OK {
        return Err(io::Error::other(format!(
            "MASQUE CONNECT rejected: {}",
            response.status()
        )));
    }
    Ok(Box::new(
        H2Body::new(send, Incoming::Body(response.into_body())).with_activity(activity),
    ))
}
