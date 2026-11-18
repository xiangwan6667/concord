use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Buf;
use concord_transport::{QuicDialFn, XhttpDial, XhttpDownload, XhttpReuse};

use super::*;

#[path = "../support/quic.rs"]
mod quic;
pub(super) fn endpoints() -> (quinn::Endpoint, quinn::Endpoint) {
    quic::endpoints_with_transport(
        quinn::TransportConfig::default(),
        quinn::TransportConfig::default(),
    )
}

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

pub(super) async fn serve_request(
    request: http::Request<()>,
    mut stream: ServerStream,
    server: Arc<XhttpServer>,
) {
    assert_eq!(request.version(), http::Version::HTTP_3);
    assert_eq!(
        request.uri().authority().unwrap().as_str(),
        "cdn.example.com"
    );
    let referer = request.headers().get("referer").unwrap().to_str().unwrap();
    let padding = referer.split("x_padding=").nth(1).unwrap();
    assert!((100..=1000).contains(&padding.len()) && padding.bytes().all(|b| b == b'X'));
    let pieces: Vec<_> = request
        .uri()
        .path()
        .strip_prefix("/xh/")
        .unwrap()
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    match (request.method().as_str(), pieces.as_slice()) {
        ("GET", [id]) => {
            let mut rx = server.session(id, |s| s.download.take()).unwrap();
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            while let Some(chunk) = rx.recv().await {
                if stream.send_data(Bytes::from(chunk)).await.is_err() {
                    break;
                }
            }
        }
        ("POST", [id, seq]) => {
            let seq: u64 = seq.parse().unwrap();
            assert!(request.headers().get("content-type").is_none());
            let mut payload = vec![];
            while let Ok(Some(mut data)) = stream.recv_data().await {
                payload.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            *lock(&server.packets) += 1;
            server.session(id, |s| {
                s.pending.insert(seq, payload);
                while let Some(next) = s.pending.remove(&s.next) {
                    s.next += 1;
                    let _ = s.echo.send(next);
                }
            });
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            let _ = stream.finish().await;
        }
        ("POST", [id]) => {
            assert_eq!(request.headers()["content-type"], "application/grpc");
            let echo = server.session(id, |s| s.echo.clone());
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            while let Ok(Some(mut data)) = stream.recv_data().await {
                let _ = echo.send(data.copy_to_bytes(data.remaining()).to_vec());
            }
            let _ = stream.finish().await;
        }
        ("POST", []) => {
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            while let Ok(Some(mut data)) = stream.recv_data().await {
                let chunk = data.copy_to_bytes(data.remaining());
                if stream.send_data(chunk).await.is_err() {
                    return;
                }
            }
            let _ = stream.finish().await;
        }
        other => panic!("unrouted {other:?}"),
    }
}

fn quic_dial(
    server: Arc<XhttpServer>,
    accepts: Arc<AtomicUsize>,
) -> (QuicDialFn, tokio::task::JoinHandle<()>) {
    let (endpoint, client) = endpoints();
    let remote = endpoint.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let server = server.clone();
            accepts.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else {
                    return;
                };
                let mut http = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();
                while let Ok(Some(request)) = http.accept().await {
                    let Ok((req, stream)) = request.resolve_request().await else {
                        continue;
                    };
                    tokio::spawn(serve_request(req, stream, server.clone()));
                }
            });
        }
    });
    let dial: QuicDialFn = Arc::new(move || {
        let client = client.clone();
        Box::pin(async move {
            let conn = client.connect(remote, "localhost").unwrap().await.unwrap();
            Ok((conn, Arc::new(client) as Arc<dyn Send + Sync>))
        })
    });
    (dial, handle)
}

#[tokio::test]
async fn xhttp_h3_preserves_headers_padding_modes_and_independent_halves() {
    for mode in ["stream-one", "stream-up", "packet-up"] {
        for separate_download in [false, true] {
            if mode == "stream-one" && separate_download {
                continue;
            }
            let server = Arc::new(XhttpServer::default());
            let (dial, peer) = quic_dial(server.clone(), Arc::new(AtomicUsize::new(0)));
            let download = separate_download.then(|| XhttpDownload {
                host: "cdn.example.com".into(),
                path: "/xh".into(),
                headers: vec![],
                reuse: None,
                keep_alive_period: -1,
                http1: false,
                dial: XhttpDial::Tcp(xhttp_dial(server)),
            });
            let client = XhttpClient::new(
                xhttp_opts(mode),
                XhttpDial::Quic(dial),
                download,
                Default::default(),
            )
            .unwrap();
            let mut stream = client.dial().await.unwrap();
            let payload = pattern(120_000);
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut got = vec![0; payload.len()];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, payload, "{mode} separate={separate_download}");
            stream.shutdown().await.unwrap();
            if mode == "stream-one" {
                let mut tail = vec![];
                tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut tail))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(tail.is_empty());
            }
            drop(stream);
            client.close();
            peer.abort();
        }
    }
}

#[tokio::test]
async fn xhttp_h3_xmux_reuses_connections_and_reset_dials_again() {
    let accepts = Arc::new(AtomicUsize::new(0));
    let (dial, peer) = quic_dial(Arc::new(XhttpServer::default()), accepts.clone());
    let mut options = xhttp_opts("stream-one");
    options.reuse = Some(XhttpReuse {
        max_connections: "1".into(),
        ..XhttpReuse::default()
    });
    let client =
        XhttpClient::new(options, XhttpDial::Quic(dial), None, Default::default()).unwrap();
    for i in 0..3 {
        if i == 2 {
            client.close();
        }
        let mut stream = client.dial().await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut got = [0; 5];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got, b"hello");
        assert_eq!(accepts.load(Ordering::SeqCst), if i == 2 { 2 } else { 1 });
    }
    client.close();
    peer.abort();
}
