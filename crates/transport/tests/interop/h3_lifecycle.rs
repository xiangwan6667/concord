use super::*;
use concord_transport::{QuicDialFn, XhttpDial, XhttpReuse};
use std::sync::Weak;
use std::time::Duration;

type Peer = ::h3::server::Connection<h3_quinn::Connection, Bytes>;
type Lease = Arc<Mutex<Option<Weak<dyn Send + Sync>>>>;

fn manual_peer() -> (
    QuicDialFn,
    mpsc::UnboundedReceiver<quinn::Connection>,
    Lease,
    tokio::task::JoinHandle<()>,
) {
    let (endpoint, client) = super::h3_tests::endpoints();
    let remote = endpoint.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let peer = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            if let Ok(conn) = incoming.await {
                let _ = tx.send(conn);
            }
        }
    });
    let lease: Lease = Arc::default();
    let saved = lease.clone();
    let dial: QuicDialFn = Arc::new(move || {
        let client = client.clone();
        let saved = saved.clone();
        Box::pin(async move {
            let conn = client.connect(remote, "localhost").unwrap().await.unwrap();
            let guard: Arc<dyn Send + Sync> = Arc::new(client);
            *lock(&saved) = Some(Arc::downgrade(&guard));
            Ok((conn, guard))
        })
    });
    (dial, rx, lease, peer)
}

fn client(dial: QuicDialFn, mode: &str) -> Arc<XhttpClient> {
    let mut opts = xhttp_opts(mode);
    opts.reuse = Some(XhttpReuse {
        max_connections: "1".into(),
        ..Default::default()
    });
    XhttpClient::new(opts, XhttpDial::Quic(dial), None, Default::default()).unwrap()
}

#[tokio::test]
async fn xhttp_h3_abandoned_upload_resets_but_shutdown_finishes() {
    for mode in ["stream-one", "stream-up"] {
        for finish in [false, true] {
            let (dial, mut connections, _, peer) = manual_peer();
            let (tx, mut rx) = mpsc::unbounded_channel();
            let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
            let serve = tokio::spawn(async move {
                let conn = connections.recv().await.unwrap();
                let mut http = Peer::new(h3_quinn::Connection::new(conn)).await.unwrap();
                while let Ok(Some(request)) = http.accept().await {
                    let (req, mut stream) = request.resolve_request().await.unwrap();
                    let tx = tx.clone();
                    let ready_tx = ready_tx.clone();
                    tokio::spawn(async move {
                        stream.send_response(http::Response::new(())).await.unwrap();
                        if req.method() != http::Method::POST {
                            return;
                        }
                        let _ = ready_tx.send(());
                        loop {
                            match stream.recv_data().await {
                                Ok(Some(_)) => {}
                                Ok(None) => {
                                    let _ = tx.send(None);
                                    break;
                                }
                                Err(::h3::error::StreamError::RemoteTerminate { code, .. }) => {
                                    let _ = tx.send(Some(code.value()));
                                    break;
                                }
                                Err(err) => panic!("unexpected upload end: {err}"),
                            }
                        }
                    });
                }
            });
            let client = client(dial, mode);
            let mut stream = client.dial().await.unwrap();
            stream.write_all(b"partial body").await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), ready_rx.recv())
                .await
                .unwrap()
                .unwrap();
            if finish {
                stream.shutdown().await.unwrap();
            }
            drop(stream);
            let result = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result, if finish { None } else { Some(0x10c) }, "{mode}");
            client.close();
            serve.abort();
            peer.abort();
        }
    }
}

#[tokio::test]
async fn xhttp_h3_goaway_retries_without_exposing_a_failed_dial() {
    let (dial, mut connections, _, peer) = manual_peer();
    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = accepts.clone();
    let old = Arc::new(Mutex::new(None));
    let saved = old.clone();
    let serve = tokio::spawn(async move {
        while let Some(conn) = connections.recv().await {
            let first = observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
            if first {
                *lock(&saved) = Some(conn.clone());
            }
            tokio::spawn(async move {
                let mut http = Peer::new(h3_quinn::Connection::new(conn)).await.unwrap();
                while let Ok(Some(request)) = http.accept().await {
                    let (req, stream) = request.resolve_request().await.unwrap();
                    tokio::spawn(super::h3_tests::serve_request(req, stream, Arc::default()));
                    if first {
                        http.shutdown(0).await.unwrap();
                        std::future::pending::<()>().await;
                    }
                }
            });
        }
    });
    let client = client(dial, "stream-one");
    let mut streams = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut stream = client.dial().await.unwrap();
            stream.write_all(b"hello").await.unwrap();
            let mut got = [0; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello");
            streams.push(stream);
            if accepts.load(std::sync::atomic::Ordering::SeqCst) == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(lock(&old).as_ref().unwrap().close_reason().is_none());
    client.close();
    serve.abort();
    peer.abort();
}

#[tokio::test]
async fn xhttp_h3_closed_driver_releases_guard_without_another_request() {
    let (dial, mut connections, lease, peer) = manual_peer();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let serve = tokio::spawn(async move {
        let conn = connections.recv().await.unwrap();
        let mut http = Peer::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        let request = http.accept().await.unwrap().unwrap();
        let (_, mut stream) = request.resolve_request().await.unwrap();
        stream.send_response(http::Response::new(())).await.unwrap();
        closed_rx.await.unwrap();
        conn.close(0x100u32.into(), b"done");
    });
    let client = client(dial, "stream-one");
    let stream = client.dial().await.unwrap();
    assert!(lock(&lease).as_ref().unwrap().upgrade().is_some());
    closed_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while lock(&lease).as_ref().unwrap().upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(stream);
    client.close();
    serve.await.unwrap();
    peer.abort();
}

#[tokio::test]
async fn xhttp_h3_peer_reset_preserves_connection_reset_kind() {
    let (dial, mut connections, _, peer) = manual_peer();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let serve = tokio::spawn(async move {
        let conn = connections.recv().await.unwrap();
        let mut http = Peer::new(h3_quinn::Connection::new(conn)).await.unwrap();
        let request = http.accept().await.unwrap().unwrap();
        let (_, mut stream) = request.resolve_request().await.unwrap();
        stream.stop_stream(::h3::error::Code::H3_REQUEST_CANCELLED);
        release_rx.await.unwrap();
    });
    let client = client(dial, "stream-one");
    let mut stream = client.dial().await.unwrap();
    let err = tokio::time::timeout(Duration::from_secs(10), stream.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    release_tx.send(()).unwrap();
    drop(stream);
    client.close();
    serve.await.unwrap();
    peer.abort();
}

#[tokio::test]
async fn xhttp_h3_truncated_data_is_an_error_without_a_panic() {
    let (dial, mut connections, _, peer) = manual_peer();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let serve = tokio::spawn(async move {
        let conn = connections.recv().await.unwrap();
        let mut control = conn.open_uni().await.unwrap();
        control.write_all(&[0, 4, 0]).await.unwrap();
        let (mut send, _recv) = conn.accept_bi().await.unwrap();
        // RFC 9204 static :status=200, then DATA declaring 16 bytes but carrying only ten.
        send.write_all(&[1, 3, 0, 0, 0xd9, 0, 16]).await.unwrap();
        send.write_all(&[42; 10]).await.unwrap();
        send.finish().unwrap();
        let _ = release_rx.await;
    });
    let client = client(dial, "stream-one");
    let mut stream = client.dial().await.unwrap();
    let mut body = Vec::new();
    let err = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut body))
        .await
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("H3_FRAME_ERROR"), "{err}");
    let _ = release_tx.send(());
    drop(stream);
    client.close();
    serve.await.unwrap();
    peer.abort();
}
