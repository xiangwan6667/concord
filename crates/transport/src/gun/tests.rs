use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

use concord_common::sync::lock;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use super::*;

type Request = (String, String, String, String, String);

#[derive(Default)]
struct Seen {
    requests: Mutex<Vec<Request>>,
    connections: AtomicUsize,
}

fn dial_to_server(seen: Arc<Seen>, status: u16) -> DialFn {
    Arc::new(move || {
        let seen = seen.clone();
        Box::pin(async move {
            let (client, server) = duplex(1 << 20);
            seen.connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(mut conn) = h2::server::handshake(server).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    let seen = seen.clone();
                    tokio::spawn(async move {
                        let (parts, body) = request.into_parts();
                        let header = |name: &str| {
                            parts
                                .headers
                                .get(name)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default()
                                .to_string()
                        };
                        lock(&seen.requests).push((
                            parts.method.to_string(),
                            parts.uri.path().to_string(),
                            parts
                                .uri
                                .authority()
                                .map(ToString::to_string)
                                .unwrap_or_default(),
                            header("content-type"),
                            header("user-agent"),
                        ));
                        let response = http::Response::builder().status(status).body(()).unwrap();
                        let send = respond.send_response(response, false).unwrap();
                        let mut framed = gun_framed(H2Body::new(send, Incoming::Body(body)));
                        let mut buf = vec![0u8; 8192];
                        loop {
                            match framed.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if framed.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = framed.shutdown().await;
                    });
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    })
}

fn opts() -> GrpcOptions {
    GrpcOptions {
        service_name: "svc".into(),
        authority: "node.example.com:443".into(),
        ..GrpcOptions::default()
    }
}

#[tokio::test]
async fn advertises_the_reference_h2_flow_control_and_frame_limits() {
    let (near, mut far) = duplex(1 << 16);
    let observed = tokio::spawn(async move { crate::h2io::tests::client_settings(&mut far).await });
    let io = Box::new(near) as BoxStream;
    let (sender, conn) = client_builder().handshake::<_, Bytes>(io).await.unwrap();
    let driver = tokio::spawn(conn);
    let (settings, update) = observed.await.unwrap();
    assert_eq!(settings.get(&2), Some(&0));
    assert_eq!(settings.get(&4), Some(&(4 << 20)));
    assert_eq!(settings.get(&5), Some(&(1 << 20)));
    assert_eq!(settings.get(&6), Some(&(10 << 20)));
    assert_eq!(update, 1 << 30);
    drop(sender);
    driver.abort();
}

#[test]
fn service_paths_match_gun() {
    assert_eq!(service_path(""), "/GunService/Tun");
    assert_eq!(service_path("abc"), "/abc/Tun");
    assert_eq!(service_path("/custom/path"), "/custom/path");
}

#[tokio::test]
async fn request_shape_and_large_echo() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(
        opts(),
        dial_to_server(seen.clone(), 200),
        Default::default(),
    );
    let conn = client.dial().await.unwrap();
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 247) as u8).collect();
    let send = payload.clone();
    let (mut rd, mut wr) = tokio::io::split(conn);
    let writer = tokio::spawn(async move {
        wr.write_all(&send).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    rd.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();
    assert_eq!(got, payload);
    let requests = lock(&seen.requests);
    assert_eq!(
        requests[0],
        (
            "POST".to_string(),
            "/svc/Tun".to_string(),
            "node.example.com:443".to_string(),
            "application/grpc".to_string(),
            "grpc-go/1.36.0".to_string()
        )
    );
}

#[tokio::test]
async fn custom_user_agent_is_sent() {
    let seen = Arc::new(Seen::default());
    let mut o = opts();
    o.user_agent = "my-agent".into();
    let client = GunClient::new(o, dial_to_server(seen.clone(), 200), Default::default());
    let mut conn = client.dial().await.unwrap();
    conn.write_all(b"x").await.unwrap();
    let mut one = [0u8; 1];
    conn.read_exact(&mut one).await.unwrap();
    assert_eq!(lock(&seen.requests)[0].4, "my-agent");
}

#[tokio::test]
async fn streams_share_one_connection_by_default() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(
        opts(),
        dial_to_server(seen.clone(), 200),
        Default::default(),
    );
    let mut conns = Vec::new();
    for _ in 0..5 {
        conns.push(client.dial().await.unwrap());
    }
    for (idx, conn) in conns.iter_mut().enumerate() {
        let msg = [idx as u8; 3];
        conn.write_all(&msg).await.unwrap();
        let mut back = [0u8; 3];
        conn.read_exact(&mut back).await.unwrap();
        assert_eq!(back, msg);
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn max_streams_opens_another_connection_when_full() {
    let seen = Arc::new(Seen::default());
    let mut o = opts();
    o.max_streams = 2;
    let client = GunClient::new(o, dial_to_server(seen.clone(), 200), Default::default());
    let mut conns = Vec::new();
    for _ in 0..5 {
        conns.push(client.dial().await.unwrap());
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 3);
    drop(conns);
    let _again = client.dial().await.unwrap();
    assert_eq!(seen.connections.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn max_connections_bounds_the_pool_and_min_streams_fills_first() {
    let seen = Arc::new(Seen::default());
    let mut o = opts();
    o.max_connections = 2;
    o.min_streams = 3;
    let client = GunClient::new(o, dial_to_server(seen.clone(), 200), Default::default());
    let mut conns = Vec::new();
    for _ in 0..3 {
        conns.push(client.dial().await.unwrap());
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
    for _ in 0..4 {
        conns.push(client.dial().await.unwrap());
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn half_close_still_delivers_the_reply() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(opts(), dial_to_server(seen, 200), Default::default());
    let mut conn = client.dial().await.unwrap();
    conn.write_all(b"last words").await.unwrap();
    conn.shutdown().await.unwrap();
    let mut got = Vec::new();
    conn.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"last words");
}

#[tokio::test]
async fn a_failing_status_is_a_read_error() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(opts(), dial_to_server(seen, 404), Default::default());
    let mut conn = client.dial().await.unwrap();
    conn.write_all(b"x").await.unwrap();
    let mut buf = [0u8; 1];
    let err = conn.read(&mut buf).await.unwrap_err();
    assert!(err.to_string().contains("404"));
}

#[tokio::test]
async fn a_dead_connection_is_replaced() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(
        opts(),
        dial_to_server(seen.clone(), 200),
        Default::default(),
    );
    drop(client.dial().await.unwrap());
    {
        let transport = lock(&client.pool).first().cloned().unwrap();
        transport.sender.lock().await.take();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut conn = client.dial().await.unwrap();
    conn.write_all(b"ok").await.unwrap();
    let mut back = [0u8; 2];
    conn.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ok");
}

#[tokio::test]
async fn split_halves_echo_concurrently_and_shutdown_keeps_reading() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(opts(), dial_to_server(seen, 200), Default::default());
    let (mut rd, mut wr) = client.dial().await.unwrap().into_split();
    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 241) as u8).collect();
    let send = payload.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&send).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    rd.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();
    assert_eq!(got, payload);
}
