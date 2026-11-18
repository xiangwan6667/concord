use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use concord_common::layered::{Layered, ReadLayer, WriteLayer};
use concord_common::{BoxStream, Tasks};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{MuxSession, SmuxSession};

const FIRST_STREAM_ID: u32 = 3;

/// One smux v1 stream, with keepalive disabled and a session lasting until both halves close.
pub(crate) async fn smux_stream(io: BoxStream, tasks: &Tasks) -> io::Result<BoxStream> {
    let session = Arc::new(SmuxSession::with_first_id(io, FIRST_STREAM_ID, tasks));
    let stream = session.open().await?;
    Ok(Box::new(Layered::new(
        stream,
        Keep {
            _session: session.clone(),
        },
        Keep { _session: session },
    )))
}

struct Keep {
    _session: Arc<SmuxSession>,
}

impl ReadLayer for Keep {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(io).poll_read(cx, buf)
    }
}

impl WriteLayer for Keep {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(io).poll_write(cx, data)
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn single_smux_stream_matches_gost_frames_and_keeps_session_after_split() {
        let (near, mut far) = duplex(128);
        let stream = smux_stream(Box::new(near), &Default::default())
            .await
            .unwrap();
        let (read, mut write) = stream.into_split();
        write.write_all(b"hi").await.unwrap();
        let mut wire = [0; 18];
        far.read_exact(&mut wire).await.unwrap();
        assert_eq!(
            wire,
            [1, 0, 0, 0, 3, 0, 0, 0, 1, 2, 2, 0, 3, 0, 0, 0, b'h', b'i']
        );
        drop(read);
        write.write_all(b"ok").await.unwrap();
        let mut wire = [0; 10];
        far.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire, [1, 2, 2, 0, 3, 0, 0, 0, b'o', b'k']);
        drop(write);
        let mut fin = [0; 8];
        far.read_exact(&mut fin).await.unwrap();
        assert_eq!(fin, [1, 1, 0, 0, 3, 0, 0, 0]);
        assert_eq!(far.read_to_end(&mut Vec::new()).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn single_smux_shutdown_drains_large_upload_and_fin_before_closing() {
        let (near, mut far) = duplex(128);
        let stream = smux_stream(Box::new(near), &Default::default())
            .await
            .unwrap();
        let data: Vec<u8> = (0..2 * 1024 * 1024 + 19).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();
        let task = tokio::spawn(async move {
            let (read, mut write) = stream.into_split();
            drop(read);
            write.write_all(&data).await.unwrap();
            write.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        loop {
            let mut header = [0; 8];
            far.read_exact(&mut header).await.unwrap();
            let [version, command, lo, hi, s0, s1, s2, s3] = header;
            assert_eq!((version, u32::from_le_bytes([s0, s1, s2, s3])), (1, 3));
            let len = usize::from(u16::from_le_bytes([lo, hi]));
            match command {
                0 => assert_eq!(len, 0),
                1 => {
                    assert_eq!(len, 0);
                    break;
                }
                2 => {
                    let mut payload = vec![0; len];
                    far.read_exact(&mut payload).await.unwrap();
                    received.extend_from_slice(&payload);
                }
                other => panic!("unexpected command {other}"),
            }
        }
        task.await.unwrap();
        assert_eq!(received, expected);
        assert_eq!(far.read_to_end(&mut Vec::new()).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn single_smux_stream_reads_fragmented_payload_and_fin() {
        let (near, mut far) = duplex(128);
        let stream = smux_stream(Box::new(near), &Default::default())
            .await
            .unwrap();
        let (mut read, write) = stream.into_split();
        let mut syn = [0; 8];
        far.read_exact(&mut syn).await.unwrap();
        for byte in [
            1, 3, 0, 0, 0, 0, 0, 0, 1, 2, 2, 0, 3, 0, 0, 0, b'o', b'k', 1, 1, 0, 0, 3, 0, 0, 0,
        ] {
            far.write_all(&[byte]).await.unwrap();
        }
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ok");
        drop(write);
    }
    struct Tracked {
        inner: tokio::io::DuplexStream,
        dropped: Arc<tokio::sync::Notify>,
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.dropped.notify_one();
        }
    }

    impl AsyncRead for Tracked {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Tracked {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl concord_common::Stream for Tracked {
        concord_common::stream_policy!(default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp, into_split);
    }

    #[tokio::test(start_paused = true)]
    async fn single_smux_stalled_peer_releases_connection_after_close_deadline() {
        use futures_util::FutureExt;
        use std::time::Duration;
        let (near, _far) = duplex(1);
        let dropped = Arc::new(tokio::sync::Notify::new());
        let stream = smux_stream(
            Box::new(Tracked {
                inner: near,
                dropped: dropped.clone(),
            }),
            &Default::default(),
        )
        .await
        .unwrap();
        drop(stream);
        tokio::task::yield_now().await;
        assert!(dropped.notified().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(29)).await;
        tokio::task::yield_now().await;
        assert!(dropped.notified().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::time::timeout(Duration::from_secs(1), dropped.notified())
            .await
            .unwrap();
    }
}
