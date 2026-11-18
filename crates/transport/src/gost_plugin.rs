use std::io;

use concord_common::{BoxStream, Tasks};

use crate::singmux::smux_stream;
use crate::v2ray_plugin::V2rayPluginOptions;
use crate::ws;

pub(crate) async fn apply(
    io: BoxStream,
    opts: &V2rayPluginOptions,
    tasks: &Tasks,
) -> io::Result<BoxStream> {
    let stream = ws::apply(io, &opts.ws, &opts.host, tasks).await?;
    if opts.mux {
        smux_stream(stream, tasks).await
    } else {
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http1::HeadReader;
    use crate::ws::{WsOptions, WsStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn gost_websocket_carries_raw_bytes_or_smux_v1() {
        for mux in [false, true] {
            let (near, mut far) = duplex(8192);
            let options = V2rayPluginOptions {
                host: "bing.com".into(),
                ws: WsOptions {
                    path: "/gost?x=1".into(),
                    headers: vec![
                        ("Host".into(), "edge.example".into()),
                        ("X-Test".into(), "value".into()),
                    ],
                    ..WsOptions::default()
                },
                mux,
            };
            let task = tokio::spawn(async move {
                let mut io = apply(Box::new(near), &options, &Default::default())
                    .await
                    .unwrap();
                io.write_all(b"hello").await.unwrap();
                let mut got = [0; 2];
                io.read_exact(&mut got).await.unwrap();
                assert_eq!(&got, b"ok");
            });
            let head = HeadReader::default().read_head(&mut far).await.unwrap();
            let head = String::from_utf8(head).unwrap();
            assert!(head.starts_with("GET /gost?x=1 HTTP/1.1\r\nHost: edge.example\r\n"));
            assert!(head.contains("X-Test: value\r\n"));
            far.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
            let mut far = WsStream::new(far, false);
            let mut wire = vec![0; if mux { 21 } else { 5 }];
            far.read_exact(&mut wire).await.unwrap();
            let mut want = Vec::new();
            if mux {
                want.extend_from_slice(&[1, 0, 0, 0, 3, 0, 0, 0, 1, 2, 5, 0, 3, 0, 0, 0]);
            }
            want.extend_from_slice(b"hello");
            assert_eq!(wire, want);
            let mut reply = Vec::new();
            if mux {
                reply.extend_from_slice(&[1, 2, 2, 0, 3, 0, 0, 0]);
            }
            reply.extend_from_slice(b"ok");
            far.write_all(&reply).await.unwrap();
            task.await.unwrap();
        }
    }
}
