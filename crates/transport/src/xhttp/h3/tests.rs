use super::*;
use futures_util::FutureExt;
use std::time::Duration;

#[path = "../../../tests/support/quic.rs"]
mod quic;

#[tokio::test]
async fn xhttp_h3_fixed_body_cancellation_resets_a_blocked_send() {
    let mut server_transport = quinn::TransportConfig::default();
    server_transport.stream_receive_window(1024u32.into());
    let mut client_transport = quinn::TransportConfig::default();
    client_transport.send_window(1024);
    let (endpoint, client) = quic::endpoints_with_transport(server_transport, client_transport);
    let remote = endpoint.local_addr().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (read_tx, read_rx) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.unwrap().await.unwrap();
        let mut http = ::h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let request = http.accept().await.unwrap().unwrap();
        let (_, mut stream) = request.resolve_request().await.unwrap();
        ready_tx.send(()).unwrap();
        read_rx.await.unwrap();
        loop {
            match stream.recv_data().await {
                Ok(Some(_)) => {}
                Err(::h3::error::StreamError::RemoteTerminate { code, .. }) => {
                    assert_eq!(code, ::h3::error::Code::H3_REQUEST_CANCELLED);
                    break;
                }
                Ok(None) => panic!("truncated POST ended with FIN"),
                Err(err) => panic!("unexpected stream error: {err}"),
            }
        }
    });
    let dial: QuicDialFn = Arc::new(move || {
        let client = client.clone();
        Box::pin(async move {
            let conn = client.connect(remote, "localhost").unwrap().await.unwrap();
            Ok((conn, Arc::new(client) as Arc<dyn Send + Sync>))
        })
    });
    let transport = H3Transport::new(dial, Default::default());
    let request = Built::test_new(
        "POST",
        "localhost",
        "/packet/0",
        crate::http1::HeaderMap::default(),
    );
    let mut fixed = Box::pin(transport.fixed(&request, vec![0x42; 32 * 1024]));
    tokio::select! {
        result = &mut fixed => panic!("body unexpectedly completed: {result:?}"),
        _ = ready_rx => {},
    }
    assert!(fixed.as_mut().now_or_never().is_none());
    drop(fixed);
    read_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), peer)
        .await
        .unwrap()
        .unwrap();
    transport.close();
}
