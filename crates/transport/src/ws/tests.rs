use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

use super::*;

async fn read_request(server: &mut DuplexStream) -> (String, Vec<u8>) {
    let mut reader = HeadReader::default();
    let head = reader.read_head(server).await.unwrap();
    (String::from_utf8(head).unwrap(), reader.into_rest())
}

const SWITCH: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: x\r\n\r\n";

fn opts(path: &str) -> WsOptions {
    WsOptions {
        path: path.to_string(),
        ..WsOptions::default()
    }
}

#[tokio::test]
async fn request_bytes_follow_net_http_ordering() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("/ws path?x=1&b=2");
    o.headers = vec![
        ("user-agent".into(), "Mozilla/5.0".into()),
        ("X-Custom".into(), "one".into()),
    ];
    let task = tokio::spawn(async move {
        apply(Box::new(client), &o, "example.com", &Default::default()).await
    });
    let (head, _) = read_request(&mut server).await;
    server.write_all(SWITCH).await.unwrap();
    task.await.unwrap().unwrap();

    let lines: Vec<&str> = head.split("\r\n").collect();
    assert_eq!(lines[0], "GET /ws%20path?x=1&b=2 HTTP/1.1");
    assert_eq!(lines[1], "Host: example.com");
    assert_eq!(lines[2], "User-Agent: Mozilla/5.0");
    assert_eq!(lines[3], "Connection: Upgrade");
    assert!(lines[4].starts_with("Sec-Websocket-Key: "));
    assert_eq!(lines[4].len(), "Sec-Websocket-Key: ".len() + 24);
    assert_eq!(lines[5], "Sec-Websocket-Version: 13");
    assert_eq!(lines[6], "Upgrade: websocket");
    assert_eq!(lines[7], "X-Custom: one");
    assert_eq!(lines[8], "");
}

#[tokio::test]
async fn default_user_agent_and_host_override() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("");
    o.headers = vec![("Host".into(), "front.example.net".into())];
    let task = tokio::spawn(async move {
        apply(Box::new(client), &o, "198.51.100.7", &Default::default()).await
    });
    let (head, _) = read_request(&mut server).await;
    server.write_all(SWITCH).await.unwrap();
    task.await.unwrap().unwrap();
    assert!(head.starts_with(
        "GET / HTTP/1.1\r\nHost: front.example.net\r\nUser-Agent: Go-http-client/1.1\r\n"
    ));
    assert!(!head.contains("198.51.100.7"));
}

#[tokio::test]
async fn non_101_status_is_an_error() {
    let (client, mut server) = duplex(8192);
    let task =
        tokio::spawn(
            async move { apply(Box::new(client), &opts("/"), "h", &Default::default()).await },
        );
    read_request(&mut server).await;
    server
        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let err = task.await.unwrap().err().unwrap();
    assert!(err.to_string().contains("400"));
}

#[tokio::test]
async fn missing_upgrade_headers_are_an_error() {
    let (client, mut server) = duplex(8192);
    let task =
        tokio::spawn(
            async move { apply(Box::new(client), &opts("/"), "h", &Default::default()).await },
        );
    read_request(&mut server).await;
    server
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
        .await
        .unwrap();
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn frames_round_trip_and_masking_is_set_on_client_frames() {
    let (client, mut server) = duplex(1 << 20);
    let task = tokio::spawn(async move {
        apply(Box::new(client), &opts("/"), "h", &Default::default())
            .await
            .unwrap()
    });
    let (_, rest) = read_request(&mut server).await;
    assert!(rest.is_empty());
    server.write_all(SWITCH).await.unwrap();
    let mut client = task.await.unwrap();

    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut raw = [0u8; 10];
    server.read_exact(&mut raw).await.unwrap();
    assert_eq!(raw[0], 0x82);
    assert_eq!(raw[1], 0x80 | 4);
    let key = [raw[2], raw[3], raw[4], raw[5]];
    let mut body = [raw[6], raw[7], raw[8], raw[9]];
    frame::apply_mask(key, 0, &mut body);
    assert_eq!(&body, b"ping");

    let mut ws_server = WsStream::new(server, false);
    let big: Vec<u8> = (0..70_000u32).map(|i| (i % 253) as u8).collect();
    let send = big.clone();
    let echo = tokio::spawn(async move {
        let mut got = vec![0u8; send.len()];
        ws_server.write_all(&send).await.unwrap();
        ws_server.flush().await.unwrap();
        ws_server.read_exact(&mut got).await.unwrap();
        got
    });
    let mut received = vec![0u8; big.len()];
    client.read_exact(&mut received).await.unwrap();
    assert_eq!(received, big);
    client.write_all(&big).await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(echo.await.unwrap(), big);
}

#[tokio::test]
async fn early_data_rides_in_the_protocol_header_and_the_rest_follows_as_frames() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("/ws");
    o.max_early_data = 4;
    o.early_data_header_name = "Sec-WebSocket-Protocol".into();
    let mut client = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap();

    let writer = tokio::spawn(async move {
        client.write_all(b"abcdefgh").await.unwrap();
        client.flush().await.unwrap();
        client.write_all(b"ijkl").await.unwrap();
        client.flush().await.unwrap();
        client
    });
    let (head, _) = read_request(&mut server).await;
    assert!(
        head.contains("\r\nSec-Websocket-Protocol: YWJjZA\r\n"),
        "{head}"
    );
    assert!(head.starts_with("GET /ws HTTP/1.1\r\n"));
    server.write_all(SWITCH).await.unwrap();
    let mut ws_server = WsStream::new(server, false);
    let mut got = [0u8; 8];
    ws_server.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"efghijkl");
    drop(writer.await.unwrap());
}

#[tokio::test]
async fn early_data_without_a_header_name_extends_the_path() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("/ws");
    o.max_early_data = 16;
    let mut client = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap();
    let writer = tokio::spawn(async move {
        client.write_all(b"abcd").await.unwrap();
        client.flush().await.unwrap();
        client
    });
    let (head, _) = read_request(&mut server).await;
    assert!(head.starts_with("GET /wsYWJjZA HTTP/1.1\r\n"), "{head}");
    server.write_all(SWITCH).await.unwrap();
    drop(writer.await.unwrap());
}

#[tokio::test]
async fn ed_query_turns_on_early_data_and_leaves_the_rest_of_the_query() {
    let (client, mut server) = duplex(8192);
    let o = opts("/ws?z=1&ed=2048&a=b");
    let mut client = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap();
    let writer = tokio::spawn(async move {
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        client
    });
    let (head, _) = read_request(&mut server).await;
    assert!(head.starts_with("GET /ws?a=b&z=1 HTTP/1.1\r\n"), "{head}");
    assert!(head.contains("\r\nSec-Websocket-Protocol: aGVsbG8\r\n"));
    server.write_all(SWITCH).await.unwrap();
    drop(writer.await.unwrap());
}

#[tokio::test]
async fn reads_wait_for_the_first_write_when_the_handshake_is_delayed() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("/");
    o.max_early_data = 8;
    o.early_data_header_name = "Sec-WebSocket-Protocol".into();
    let mut client = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        buf
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!task.is_finished());
    let mut probe = [0u8; 1];
    let peek = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        server.read(&mut probe),
    )
    .await;
    assert!(peek.is_err(), "nothing is sent before the first write");
    task.abort();
}

#[tokio::test]
async fn v2ray_http_upgrade_is_unframed_and_carries_leftover_bytes() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("/up");
    o.v2ray_http_upgrade = true;
    let task = tokio::spawn(async move {
        let mut c = apply(Box::new(client), &o, "h", &Default::default())
            .await
            .unwrap();
        c.write_all(b"raw-out").await.unwrap();
        let mut got = [0u8; 6];
        c.read_exact(&mut got).await.unwrap();
        got
    });
    let (head, _) = read_request(&mut server).await;
    assert!(!head.contains("Sec-Websocket-Key"));
    assert!(!head.contains("Sec-Websocket-Version"));
    let mut reply = SWITCH.to_vec();
    reply.extend_from_slice(b"raw-in");
    server.write_all(&reply).await.unwrap();
    let mut got = [0u8; 7];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"raw-out");
    assert_eq!(&task.await.unwrap(), b"raw-in");
}

#[tokio::test]
async fn fast_open_writes_before_the_response_arrives() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("/up");
    o.v2ray_http_upgrade = true;
    o.v2ray_http_upgrade_fast_open = true;
    let mut c = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap();
    c.write_all(b"early").await.unwrap();
    c.flush().await.unwrap();
    let (_, rest) = read_request(&mut server).await;
    let mut got = rest;
    while got.len() < 5 {
        let mut buf = [0u8; 5];
        let n = server.read(&mut buf).await.unwrap();
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"early");
    server.write_all(SWITCH).await.unwrap();
    server.write_all(b"late").await.unwrap();
    let mut buf = [0u8; 4];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"late");
}

#[tokio::test]
async fn fast_open_rejects_a_bad_response_on_first_read() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("/up");
    o.v2ray_http_upgrade = true;
    o.v2ray_http_upgrade_fast_open = true;
    let mut c = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap();
    read_request(&mut server).await;
    server
        .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    assert!(c.read(&mut buf).await.is_err());
}

#[tokio::test]
async fn server_close_frame_surfaces_as_eof() {
    let (client, mut server) = duplex(8192);
    let task = tokio::spawn(async move {
        apply(Box::new(client), &opts("/"), "h", &Default::default())
            .await
            .unwrap()
    });
    read_request(&mut server).await;
    server.write_all(SWITCH).await.unwrap();
    let mut client = task.await.unwrap();
    let mut close = Vec::new();
    frame::encode_frame(&mut close, 0x8, &1000u16.to_be_bytes(), false);
    server.write_all(&close).await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    assert!(out.is_empty());
}

#[tokio::test]
async fn lazy_halves_hand_over_after_the_first_write_and_shutdown_keeps_reading() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("/");
    o.max_early_data = 8;
    o.early_data_header_name = "Sec-WebSocket-Protocol".into();
    let (mut read, mut write) = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap()
        .into_split();
    let reader = tokio::spawn(async move {
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        got
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!reader.is_finished());
    write.write_all(b"hello").await.unwrap();
    let (head, _) = read_request(&mut server).await;
    assert!(
        head.contains("Sec-Websocket-Protocol: aGVsbG8\r\n"),
        "{head}"
    );
    let mut reply = SWITCH.to_vec();
    frame::encode_frame(&mut reply, 0x2, b"down", false);
    server.write_all(&reply).await.unwrap();
    write.write_all(b" more").await.unwrap();
    write.shutdown().await.unwrap();
    let mut close = Vec::new();
    frame::encode_frame(&mut close, 0x8, &1000u16.to_be_bytes(), false);
    server.write_all(&close).await.unwrap();
    assert_eq!(reader.await.unwrap(), b"down");
}

#[tokio::test]
async fn lazy_halves_fail_reads_when_the_writer_shuts_down_first() {
    let (client, _server) = duplex(8192);
    let mut o = opts("/");
    o.max_early_data = 8;
    o.early_data_header_name = "Sec-WebSocket-Protocol".into();
    let (mut read, mut write) = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap()
        .into_split();
    write.shutdown().await.unwrap();
    let mut buf = [0u8; 1];
    assert!(read.read(&mut buf).await.is_err());
}

#[tokio::test]
async fn lazy_halves_fail_reads_when_the_writer_drops_before_writing() {
    let (client, _server) = duplex(8192);
    let mut o = opts("/");
    o.max_early_data = 8;
    o.early_data_header_name = "Sec-WebSocket-Protocol".into();
    let (mut read, write) = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap()
        .into_split();
    let reader = tokio::spawn(async move {
        let mut buf = [0u8; 1];
        read.read(&mut buf).await
    });
    tokio::task::yield_now().await;
    drop(write);
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), reader)
        .await
        .expect("the read half waited on a handshake nobody will start")
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn fast_open_halves_move_data_both_ways_and_shutdown_keeps_reading() {
    let (client, mut server) = duplex(8192);
    let mut o = opts("/up");
    o.v2ray_http_upgrade = true;
    o.v2ray_http_upgrade_fast_open = true;
    let (mut read, mut write) = apply(Box::new(client), &o, "h", &Default::default())
        .await
        .unwrap()
        .into_split();
    let writer = tokio::spawn(async move {
        write.write_all(b"early").await.unwrap();
        write.shutdown().await.unwrap();
    });
    let reader = tokio::spawn(async move {
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        got
    });
    let (_, mut sent) = read_request(&mut server).await;
    while sent.len() < 5 {
        let mut buf = [0u8; 5];
        let n = server.read(&mut buf).await.unwrap();
        sent.extend_from_slice(&buf[..n]);
    }
    assert_eq!(sent, b"early");
    writer.await.unwrap();
    server.write_all(SWITCH).await.unwrap();
    server.write_all(b"late").await.unwrap();
    server.shutdown().await.unwrap();
    assert_eq!(reader.await.unwrap(), b"late");
}
