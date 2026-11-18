use std::io;

use bytes::Bytes;
use concord_common::{BoxStream, Tasks};
use http::{Method, Request, Uri};
use rand::Rng;

use crate::h2io::{
    Activity, CONN_WINDOW, H2Body, Incoming, STREAM_WINDOW, h2_io_error, spawn_connection,
};

#[derive(Clone, Debug, Default)]
pub struct H2Options {
    pub hosts: Vec<String>,
    pub path: String,
}

/// Runs one PUT request over the given connection and exposes its bodies as the
/// byte stream, as mihomo's vmess `h2` network does. The connection must already
/// have negotiated `h2`; nothing here pools it.
pub(crate) async fn connect(
    io: BoxStream,
    opts: &H2Options,
    tasks: &Tasks,
) -> io::Result<BoxStream> {
    if opts.hosts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hosts is empty",
        ));
    }
    let host = opts
        .hosts
        .get(rand::rng().random_range(0..opts.hosts.len()))
        .map(String::as_str)
        .unwrap_or_default();
    let path = if opts.path.is_empty() {
        "/"
    } else {
        &opts.path
    };
    let uri = Uri::builder()
        .scheme("https")
        .authority(host)
        .path_and_query(path)
        .build()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let request = Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header("accept-encoding", "identity")
        .header("user-agent", "Go-http-client/2.0")
        .body(())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let (sender, conn) = h2::client::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .enable_push(false)
        .handshake::<_, Bytes>(io)
        .await
        .map_err(h2_io_error)?;
    let activity = Activity::new();
    spawn_connection(tasks, conn, None, activity);
    let mut sender = sender.ready().await.map_err(h2_io_error)?;
    let (response, send) = sender.send_request(request, false).map_err(h2_io_error)?;
    Ok(Box::new(H2Body::new(send, Incoming::Response(response))))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn put_request_carries_a_picked_host_and_echoes_both_ways() {
        let (client, server) = duplex(1 << 20);
        let seen = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = conn.accept().await.unwrap().unwrap();
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let (parts, mut body) = request.into_parts();
            let send = respond
                .send_response(
                    http::Response::builder().status(200).body(()).unwrap(),
                    false,
                )
                .unwrap();
            let mut stream = H2Body::new(send, Incoming::Done);
            let mut got = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                body.flow_control().release_capacity(chunk.len()).unwrap();
                got.extend_from_slice(&chunk);
                if got.len() >= 5 {
                    break;
                }
            }
            stream.write_all(&got).await.unwrap();
            stream.shutdown().await.unwrap();
            (parts, got)
        });
        let opts = H2Options {
            hosts: vec!["a.example.com".into()],
            path: "/vm".into(),
        };
        let mut conn = connect(Box::new(client), &opts, &Default::default())
            .await
            .unwrap();
        conn.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        conn.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");
        let (parts, got) = seen.await.unwrap();
        assert_eq!(parts.method, Method::PUT);
        assert_eq!(parts.uri.path(), "/vm");
        assert_eq!(parts.uri.authority().unwrap().as_str(), "a.example.com");
        assert_eq!(parts.headers["accept-encoding"], "identity");
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn empty_host_list_is_rejected() {
        let (client, _server) = duplex(64);
        let err = connect(Box::new(client), &H2Options::default(), &Default::default())
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
