#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "tests drive loopback TLS peers and assert wire frames"
)]

use super::*;
use concord_config::proxy::{Capabilities, ProxyKind, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

fn pool() -> Arc<Pool> {
    Pool::new(30, Padding::parse(b"stop=0").unwrap())
}

async fn next<S: AsyncRead + Unpin>(io: &mut S) -> (u8, Vec<u8>) {
    loop {
        let kind = io.read_u8().await.unwrap();
        let length = io.read_u16().await.unwrap();
        let mut data = vec![0; usize::from(length)];
        io.read_exact(&mut data).await.unwrap();
        if kind != 0 {
            return (kind, data);
        }
    }
}

#[tokio::test]
async fn canceled_stream_sends_reset_and_drains_before_reuse() {
    let pool = pool();
    let (client, mut peer) = tokio::io::duplex(65536);
    let mut stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool.clone(), 0);
    stream.write_all(b"request").await.unwrap();
    assert_eq!(next(&mut peer).await, (5, b"request".to_vec()));
    drop(stream);
    assert_eq!(next(&mut peer).await, (8, Vec::new()));
    assert!(pool.take().1.is_none());
    let mut end = Vec::new();
    frame(&mut end, 5, b"late response").unwrap();
    frame(&mut end, 7, &[]).unwrap();
    peer.write_all(&end).await.unwrap();
    let lane = tokio::time::timeout(Duration::from_secs(1), pool.available())
        .await
        .unwrap();
    let mut reused = MiuStream::new(lane, pool.clone(), 0);
    reused.write_all(b"next").await.unwrap();
    assert_eq!(next(&mut peer).await, (5, b"next".to_vec()));
}

#[tokio::test(start_paused = true)]
async fn canceled_stream_timeout_and_reset_generation_discard_old_lanes() {
    for reset in [false, true] {
        let pool = pool();
        let (client, mut peer) = tokio::io::duplex(65536);
        let stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool.clone(), 0);
        drop(stream);
        assert_eq!(next(&mut peer).await, (8, Vec::new()));
        if reset {
            pool.clear();
            peer.write_all(&[7, 0, 0]).await.unwrap();
        }
        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(4), peer.read_to_end(&mut remaining))
            .await
            .unwrap()
            .unwrap();
        assert!(remaining.is_empty());
        assert!(pool.take().1.is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn open_waits_for_the_first_payload_or_the_server_first_deadline() {
    for server_first in [false, true] {
        let pool = pool();
        let (client, mut peer) = tokio::io::duplex(65536);
        let mut open = Vec::new();
        frame(&mut open, 4, b"destination").unwrap();
        let mut stream =
            MiuStream::new(IdleLane::new(Box::new(client), None), pool, 0).with_open(open, false);
        if server_first {
            let read = tokio::spawn(async move {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                byte
            });
            assert_eq!(next(&mut peer).await, (4, b"destination".to_vec()));
            peer.write_all(&[5, 0, 1, 42]).await.unwrap();
            assert_eq!(read.await.unwrap(), [42]);
        } else {
            stream.write_all(b"payload").await.unwrap();
            assert_eq!(next(&mut peer).await, (4, b"destination".to_vec()));
            assert_eq!(next(&mut peer).await, (5, b"payload".to_vec()));
        }
    }
}

#[tokio::test]
async fn a_first_write_wakes_a_reader_waiting_for_the_open_deadline() {
    use std::pin::Pin;
    use tokio::io::ReadBuf;

    let (client, mut peer) = tokio::io::duplex(65536);
    let mut open = Vec::new();
    frame(&mut open, 4, b"destination").unwrap();
    let stream =
        MiuStream::new(IdleLane::new(Box::new(client), None), pool(), 0).with_open(open, false);
    let (mut read, mut write) = concord_common::split_with_lock(stream);
    let (started, pending) = tokio::sync::oneshot::channel();
    let reader = tokio::spawn(async move {
        let mut started = Some(started);
        let mut byte = [0];
        std::future::poll_fn(|cx| {
            if let Some(started) = started.take() {
                started.send(()).unwrap();
            }
            Pin::new(&mut *read).poll_read(cx, &mut ReadBuf::new(&mut byte))
        })
        .await
        .unwrap();
        byte
    });
    pending.await.unwrap();
    write.write_all(b"request").await.unwrap();
    assert_eq!(next(&mut peer).await, (4, b"destination".to_vec()));
    assert_eq!(next(&mut peer).await, (5, b"request".to_vec()));
    peer.write_all(&[5, 0, 1, 42]).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .unwrap()
            .unwrap(),
        [42]
    );
}

#[tokio::test]
async fn downstream_data_or_more_than_64k_uplink_rules_out_replay() {
    for downstream in [false, true] {
        let pool = pool();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let link = test_link(listener.local_addr().unwrap().port());
        let (client, mut peer) = tokio::io::duplex(256 * 1024);
        let env = crate::testing::test_env();
        let mut stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool, 0)
            .replay_pooled(link, [7; 32], env, Vec::new());
        if downstream {
            peer.write_all(&[5, 0, 1, 42]).await.unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [42]);
        } else {
            stream.write_all(&vec![42; (64 << 10) + 1]).await.unwrap();
        }
        drop(peer);
        let result =
            tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut Vec::new()))
                .await
                .unwrap();
        assert!(result.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
    }
}

fn test_link(port: u16) -> Arc<Link> {
    let node = json!({"name":"replay", "type":"miu", "server":"127.0.0.1", "port":port,
        "psk":"0123456789abcdef", "skip-cert-verify":true, "sni":"localhost"});
    let ProxyParse::Ok(def) =
        parse_proxy(node.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("Miu must parse");
    };
    let ProxyKind::Miu(opts) = &def.kind else {
        panic!("Miu must retain its type")
    };
    Arc::new(
        simple_link(
            &def,
            &opts.server,
            opts.port,
            &opts.tls,
            &BuildCtx::new(TrustStore::new(b"", Vec::new())),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn dead_pooled_lane_replays_the_uplink_and_half_close_once() {
    let pool = pool();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let link = test_link(listener.local_addr().unwrap().port());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(socket)
            .await
            .unwrap();
        let mut token = [0; 32];
        tls.read_exact(&mut token).await.unwrap();
        assert_eq!(token, [7; 32]);
        let padding = tls.read_u16().await.unwrap();
        let mut pad = vec![0; usize::from(padding)];
        tls.read_exact(&mut pad).await.unwrap();
        assert_eq!(next(&mut tls).await.0, 1);
        assert_eq!(next(&mut tls).await, (4, b"destination".to_vec()));
        assert_eq!(next(&mut tls).await, (5, b"remembered".to_vec()));
        assert_eq!(next(&mut tls).await, (7, Vec::new()));
        let mut response = Vec::new();
        frame(&mut response, 5, b"echo").unwrap();
        frame(&mut response, 7, &[]).unwrap();
        tls.write_all(&response).await.unwrap();
        tls.flush().await.unwrap();
        tls
    });
    let (client, mut old_peer) = tokio::io::duplex(65536);
    let mut open = Vec::new();
    frame(&mut open, 4, b"destination").unwrap();
    let mut stream = MiuStream::new(IdleLane::new(Box::new(client), None), pool.clone(), 0)
        .replay_pooled(link, [7; 32], crate::testing::test_env(), open);
    stream.write_all(b"remembered").await.unwrap();
    assert_eq!(next(&mut old_peer).await, (5, b"remembered".to_vec()));
    stream.shutdown().await.unwrap();
    assert_eq!(next(&mut old_peer).await, (7, Vec::new()));
    drop(old_peer);
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"echo");
    let tls = peer.await.unwrap();
    drop(stream);
    assert_eq!(pool.take().0, 1);
    drop(tls);
}
