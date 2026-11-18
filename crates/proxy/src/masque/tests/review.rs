use super::*;
use std::future::poll_fn;
use std::pin::Pin;
use tokio::io::AsyncWrite;

fn config(server: &fixture::Server, network: &str) -> Config {
    let def = definition(server, network, json!({}));
    let concord_config::proxy::ProxyKind::Masque(opts) = &def.kind else {
        unreachable!()
    };
    Config::new(
        opts,
        Egress::new(&def.name, &def.common),
        &BuildCtx::new(TrustStore::new(b"", vec![])),
    )
    .unwrap()
}

#[tokio::test]
async fn masque_settings_match_quic_go_and_ip_waits_for_peer_settings() {
    // quic-go 2548683b http3/client.go:33,123-127 and frames.go:263-296:
    // MAX_FIELD_SECTION_SIZE 10 MiB; IP adds standard and draft datagrams; L4 adds nothing.
    for (network, expected) in [
        ("h3", "00040a0680a000003301427601"),
        ("h3-l4proxy", "0004050680a00000"),
    ] {
        let gate = Arc::new(tokio::sync::Notify::new());
        let (server, wire) =
            fixture::settings_server(gate.clone(), b"\0\x04\x02\x33\x01".to_vec()).await;
        let config = config(&server, network);
        let env = test_env();
        let connecting = tokio::spawn(async move {
            let cx = DialCx::new(&env, Initiator::Direct, None);
            h3::Client::connect(&config, &cx).await
        });
        let wire = tokio::time::timeout(Duration::from_secs(2), wire)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(wire, hex::decode(expected).unwrap());
        if network == "h3" {
            assert!(!connecting.is_finished());
        }
        gate.notify_one();
        let client = tokio::time::timeout(Duration::from_secs(2), connecting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(client.usable());
        drop(client);
    }
}

#[tokio::test]
async fn masque_ip_rejects_peer_with_http_datagrams_disabled() {
    let server = fixture::h3_server_options(
        false,
        200,
        fixture::H3Options {
            datagrams: Some(false),
            ..Default::default()
        },
    )
    .await;
    let node = client(&server, "h3", json!({}));
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        node.connect(&cx, &Address::new("10.8.0.1", 7)),
    )
    .await
    .unwrap();
    let Err(error) = result else {
        panic!("peer without H3 datagrams was accepted");
    };
    assert!(error.to_string().contains("did not enable HTTP datagrams"));
    assert_eq!(
        server.requests.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn masque_initial_path_mtu_drops_large_udp_without_shrinking_the_ip_stack() {
    let server = fixture::h3_server(false, 200).await;
    let mut config = config(&server, "h3");
    // Hold Quinn at its initial 1242-byte path; a 1200-byte UDP payload plus IP headers cannot fit.
    Arc::get_mut(&mut config.link.transport)
        .unwrap()
        .mtu_discovery_config(None);
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let tunnel = Tunnel::connect(&config, &cx).await.unwrap();
    let port = tunnel.stack.bind_udp().unwrap();
    let target = "10.8.0.1:7".parse().unwrap();
    poll_fn(|cx| port.poll_send_to(cx, &[42; 1200], target))
        .await
        .unwrap();
    poll_fn(|cx| port.poll_send_to(cx, b"after-large", target))
        .await
        .unwrap();
    let mut reply = [0; 1600];
    let (len, _) = tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| port.poll_recv_from(cx, &mut reply)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&reply[..len], b"after-large");
    assert!(tunnel.usable());
}

#[tokio::test]
async fn masque_cancelled_pending_write_does_not_credit_the_new_short_buffer() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let server = fixture::h3_server_options(
        true,
        200,
        fixture::H3Options {
            stream_window: Some(1024),
            body_gate: Some(gate.clone()),
            ..Default::default()
        },
    )
    .await;
    let node = client(&server, "h3-l4proxy", json!({}));
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let stream = node
        .connect(&cx, &Address::new("10.8.0.1", 7))
        .await
        .unwrap();
    let (mut read, mut write) = stream.into_split();
    let old = vec![b'A'; 8192];
    poll_fn(|cx| {
        assert!(Pin::new(&mut write).poll_write(cx, &old).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    gate.notify_one();
    tokio::time::timeout(Duration::from_secs(2), write.write_all(b"B"))
        .await
        .unwrap()
        .unwrap();
    write.shutdown().await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), read.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    let mut expected = old;
    expected.extend_from_slice(b"Bafter-fin");
    assert_eq!(reply, expected);
}

#[tokio::test]
async fn masque_l4_response_reset_preserves_the_shared_client() {
    let server = fixture::h3_server_options(
        true,
        200,
        fixture::H3Options {
            fail_first: true,
            ..Default::default()
        },
    )
    .await;
    let node = client(&server, "h3-l4proxy", json!({}));
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    assert!(
        node.connect(&cx, &Address::new("10.8.0.1", 7))
            .await
            .is_err()
    );
    tcp_echo(&*node, &Address::new("10.8.0.1", 7), b"after-fin").await;
    assert_eq!(
        server
            .connections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn masque_l4_dropping_the_writer_sends_fin_instead_of_reset() {
    let server = fixture::h3_server(true, 200).await;
    let node = client(&server, "h3-l4proxy", json!({}));
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let stream = node
        .connect(&cx, &Address::new("10.8.0.1", 7))
        .await
        .unwrap();
    let (mut read, mut write) = stream.into_split();
    write.write_all(b"drop-fin").await.unwrap();
    drop(write);
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), read.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"drop-finafter-fin");
}

#[tokio::test]
async fn masque_ip_accepts_the_legacy_peer_datagram_setting() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let (server, wire) =
        fixture::settings_server(gate.clone(), b"\0\x04\x03\x42\x76\x01".to_vec()).await;
    let config = config(&server, "h3");
    let env = test_env();
    let connecting = tokio::spawn(async move {
        let cx = DialCx::new(&env, Initiator::Direct, None);
        h3::Client::connect(&config, &cx).await
    });
    wire.await.unwrap();
    gate.notify_one();
    let client = tokio::time::timeout(Duration::from_secs(2), connecting)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(client.usable());
}

#[tokio::test]
async fn masque_l4_dropping_a_pending_writer_finishes_its_data_frame() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let server = fixture::h3_server_options(
        true,
        200,
        fixture::H3Options {
            stream_window: Some(1024),
            body_gate: Some(gate.clone()),
            ..Default::default()
        },
    )
    .await;
    let node = client(&server, "h3-l4proxy", json!({}));
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let stream = node
        .connect(&cx, &Address::new("10.8.0.1", 7))
        .await
        .unwrap();
    let (mut read, mut write) = stream.into_split();
    let mut data = vec![b'A'; 8192];
    poll_fn(|cx| {
        assert!(Pin::new(&mut write).poll_write(cx, &data).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(write);
    gate.notify_one();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), read.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    data.extend_from_slice(b"after-fin");
    assert_eq!(reply, data);
}

#[tokio::test]
async fn masque_l4_rejected_target_preserves_another_active_stream() {
    let server = fixture::h3_server_options(
        true,
        200,
        fixture::H3Options {
            reject_port: Some(8),
            ..Default::default()
        },
    )
    .await;
    let node = client(&server, "h3-l4proxy", json!({}));
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let mut active = node
        .connect(&cx, &Address::new("10.8.0.1", 7))
        .await
        .unwrap();
    active.write_all(b"before").await.unwrap();
    let mut reply = [0; 6];
    active.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"before");
    let result = node.connect(&cx, &Address::new("10.8.0.1", 8)).await;
    let Err(error) = result else {
        panic!("rejected target was accepted")
    };
    assert!(error.to_string().contains("403"));
    active.write_all(b"after").await.unwrap();
    active.shutdown().await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), active.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"afterafter-fin");
    tcp_echo(&*node, &Address::new("10.8.0.1", 7), b"after-fin").await;
    assert_eq!(
        server
            .connections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn masque_ip_rejects_http_datagrams_without_quic_datagram_support() {
    let server = fixture::h3_server_options(
        false,
        200,
        fixture::H3Options {
            disable_quic_datagrams: true,
            ..Default::default()
        },
    )
    .await;
    let node = client(&server, "h3", json!({}));
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        node.connect(&cx, &Address::new("10.8.0.1", 7)),
    )
    .await
    .unwrap();
    let Err(error) = result else {
        panic!("peer without QUIC datagrams was accepted")
    };
    assert!(error.to_string().contains("did not enable QUIC datagrams"));
    assert_eq!(
        server.requests.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn masque_l4_failed_pending_write_never_acknowledges_a_retry() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let server = fixture::h3_server_options(
        true,
        200,
        fixture::H3Options {
            stream_window: Some(1024),
            body_gate: Some(gate.clone()),
            body_error: true,
            ..Default::default()
        },
    )
    .await;
    let node = client(&server, "h3-l4proxy", json!({}));
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let stream = node
        .connect(&cx, &Address::new("10.8.0.1", 7))
        .await
        .unwrap();
    let (_read, mut write) = stream.into_split();
    let data = vec![b'A'; 8192];
    poll_fn(|cx| {
        assert!(Pin::new(&mut write).poll_write(cx, &data).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    gate.notify_one();
    let failed = tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| Pin::new(&mut write).poll_write(cx, &data)),
    )
    .await
    .unwrap();
    assert!(failed.is_err());
    for _ in 0..2 {
        assert!(
            poll_fn(|cx| Pin::new(&mut write).poll_write(cx, &data))
                .await
                .is_err()
        );
    }
    assert!(write.flush().await.is_err());
    assert!(write.shutdown().await.is_err());
}

#[tokio::test]
async fn masque_handshake_timeout_cancels_a_peer_waiting_for_settings() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let (server, wire) = fixture::settings_server(gate, b"\0\x04\x02\x33\x01".to_vec()).await;
    let node = client(&server, "h3", json!({"handshake-timeout": 1}));
    let dialing = tokio::spawn(async move {
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        node.connect(&cx, &Address::new("10.8.0.1", 7)).await
    });
    tokio::time::timeout(Duration::from_secs(2), wire)
        .await
        .unwrap()
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), dialing)
        .await
        .unwrap()
        .unwrap();
    let Err(error) = result else {
        panic!("peer without SETTINGS ignored the handshake timeout")
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}
