use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::layered::{Layered, ReadLayer, WriteLayer, poll_drain};
use concord_common::{BoxStream, Tasks};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ws::{self, WsOptions};

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEP_ALIVE: u8 = 0x04;
const OPTION_DATA: u8 = 0x01;
const MAX_META: usize = 512;
const MAX_DATA: usize = 32 * 1024;

#[derive(Clone, Debug, Default)]
pub struct V2rayPluginOptions {
    /// The plugin's `host` (`bing.com` unless set): the request's `Host` header. The
    /// TLS layer below takes its SNI from the same place.
    pub host: String,
    pub ws: WsOptions,
    /// The plugin's mux framing (mux.cool for v2ray-plugin, smux v1 for gost-plugin).
    /// On unless the plugin options say `mux: false`.
    pub mux: bool,
}

pub(crate) async fn apply(
    io: BoxStream,
    opts: &V2rayPluginOptions,
    tasks: &Tasks,
) -> io::Result<BoxStream> {
    let stream = ws::apply(io, &opts.ws, &opts.host, tasks).await?;
    if opts.mux {
        return Ok(mux(stream));
    }
    Ok(stream)
}

enum Read {
    MetaLen { buf: [u8; 2], have: usize },
    Meta { left: usize, meta: Vec<u8> },
    DataLen { buf: [u8; 2], have: usize },
    Data { left: usize },
    Ended,
}

impl Read {
    fn meta_len() -> Read {
        Read::MetaLen {
            buf: [0; 2],
            have: 0,
        }
    }
}

struct MuxWrite {
    out: Vec<u8>,
    out_off: usize,
    inflight: Option<usize>,
    new_frame: Option<Vec<u8>>,
    ended_sent: bool,
}

fn new_session_frame() -> Vec<u8> {
    let mut frame = vec![0, 0, 0, 0, STATUS_NEW, 0, 0x01, 0, 0];
    frame.push(0x01);
    frame.extend_from_slice(&[127, 0, 0, 1]);
    let meta_len = (frame.len() - 2) as u16;
    if let Some(prefix) = frame.get_mut(..2) {
        prefix.copy_from_slice(&meta_len.to_be_bytes());
    }
    frame
}

/// A client for v2ray-plugin's mux with one session to `127.0.0.1:0`, which is
/// all the plugin's server side needs from a shadowsocks client.
fn mux(io: BoxStream) -> BoxStream {
    let write = MuxWrite {
        out: Vec::new(),
        out_off: 0,
        inflight: None,
        new_frame: Some(new_session_frame()),
        ended_sent: false,
    };
    Box::new(Layered::new(io, Read::meta_len(), write))
}

impl ReadLayer for Read {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut *self {
                Read::Ended => return Poll::Ready(Ok(())),
                Read::MetaLen { buf: raw, have } | Read::DataLen { buf: raw, have } => {
                    let Some(window) = raw.get_mut(*have..) else {
                        return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                    };
                    let mut window = ReadBuf::new(window);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *have += got;
                    if *have < 2 {
                        continue;
                    }
                    let value = usize::from(u16::from_be_bytes(*raw));
                    let is_meta = matches!(*self, Read::MetaLen { .. });
                    *self = if is_meta {
                        if !(4..=MAX_META).contains(&value) {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid metalen",
                            )));
                        }
                        Read::Meta {
                            left: value,
                            meta: Vec::with_capacity(value),
                        }
                    } else {
                        Read::Data { left: value }
                    };
                }
                Read::Meta { left, meta } => {
                    let mut tmp = [0u8; MAX_META];
                    let Some(window) = tmp.get_mut(..*left) else {
                        return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                    };
                    let mut window = ReadBuf::new(window);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    meta.extend_from_slice(window.filled());
                    *left -= got;
                    if *left > 0 {
                        continue;
                    }
                    let status = meta.get(2).copied().unwrap_or(0);
                    let option = meta.get(3).copied().unwrap_or(0);
                    *self = match (status, option) {
                        (STATUS_END, _) => Read::Ended,
                        (STATUS_KEEP_ALIVE, _) => Read::meta_len(),
                        (_, OPTION_DATA) => Read::DataLen {
                            buf: [0; 2],
                            have: 0,
                        },
                        _ => Read::meta_len(),
                    };
                }
                Read::Data { left } => {
                    if *left == 0 {
                        *self = Read::meta_len();
                        continue;
                    }
                    let take = (*left).min(buf.remaining());
                    if take == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let target = buf.initialize_unfilled_to(take);
                    let mut window = ReadBuf::new(target);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    buf.advance(got);
                    *left -= got;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl WriteLayer for MuxWrite {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(done) = self.inflight {
            ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
            self.inflight = None;
            return Poll::Ready(Ok(done));
        }
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        let take = data.len().min(MAX_DATA);
        let Some(chunk) = data.get(..take).filter(|c| !c.is_empty()) else {
            return Poll::Ready(Ok(0));
        };
        if let Some(frame) = self.new_frame.take() {
            self.out = frame;
        }
        self.out
            .extend_from_slice(&[0, 4, 0, 0, STATUS_KEEP, OPTION_DATA]);
        self.out
            .extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        self.out.extend_from_slice(chunk);
        self.inflight = Some(take);
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        self.inflight = None;
        Poll::Ready(Ok(take))
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.ended_sent {
            self.ended_sent = true;
            if let Some(frame) = self.new_frame.take() {
                self.out.extend_from_slice(&frame);
            }
            self.out.extend_from_slice(&[0, 4, 0, 0, STATUS_END, 0]);
        }
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[test]
    fn new_session_frame_matches_the_plugin() {
        assert_eq!(
            new_session_frame(),
            vec![0, 12, 0, 0, 1, 0, 1, 0, 0, 1, 127, 0, 0, 1]
        );
    }

    #[tokio::test]
    async fn first_write_carries_the_session_then_keep_frames_and_end_on_close() {
        let (client, mut server) = duplex(8192);
        let mut conn = mux(Box::new(client));
        conn.write_all(b"hi").await.unwrap();
        conn.write_all(b"yo").await.unwrap();
        conn.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        let mut want = vec![0, 12, 0, 0, 1, 0, 1, 0, 0, 1, 127, 0, 0, 1];
        want.extend_from_slice(&[0, 4, 0, 0, 2, 1, 0, 2, b'h', b'i']);
        want.extend_from_slice(&[0, 4, 0, 0, 2, 1, 0, 2, b'y', b'o']);
        want.extend_from_slice(&[0, 4, 0, 0, 3, 0]);
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn reads_skip_keepalives_and_other_frames_and_stop_at_end() {
        let (client, mut server) = duplex(8192);
        let mut conn = mux(Box::new(client));
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0, 4, 0, 0, STATUS_KEEP_ALIVE, 0]);
        wire.extend_from_slice(&[0, 6, 0, 0, STATUS_KEEP, 0, 9, 9]);
        wire.extend_from_slice(&[0, 4, 0, 0, STATUS_KEEP, OPTION_DATA, 0, 3, b'a', b'b', b'c']);
        wire.extend_from_slice(&[0, 4, 0, 0, STATUS_KEEP, OPTION_DATA, 0, 2, b'd', b'e']);
        wire.extend_from_slice(&[0, 4, 0, 0, STATUS_END, 0]);
        server.write_all(&wire).await.unwrap();
        let mut got = Vec::new();
        conn.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"abcde");
    }

    #[tokio::test]
    async fn oversized_meta_is_an_error() {
        let (client, mut server) = duplex(8192);
        let mut conn = mux(Box::new(client));
        server.write_all(&[0x04, 0x00, 0, 0]).await.unwrap();
        let mut buf = [0u8; 4];
        assert!(conn.read(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn the_halves_move_data_both_ways_and_shutdown_keeps_reading() {
        let (client, server) = duplex(8192);
        let (mut read, mut write) = mux(Box::new(client)).into_split();
        let (mut far_read, mut far_write) = tokio::io::split(server);
        let writer = tokio::spawn(async move {
            write.write_all(b"hi").await.unwrap();
            write.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        let mut sent = vec![0u8; 14 + 10 + 6];
        far_read.read_exact(&mut sent).await.unwrap();
        assert_eq!(
            sent.get(sent.len() - 6..),
            Some(&[0, 4, 0, 0, STATUS_END, 0][..])
        );
        writer.await.unwrap();
        far_write
            .write_all(&[0, 4, 0, 0, STATUS_KEEP, OPTION_DATA, 0, 2, b'o', b'k'])
            .await
            .unwrap();
        far_write
            .write_all(&[0, 4, 0, 0, STATUS_END, 0])
            .await
            .unwrap();
        assert_eq!(reader.await.unwrap(), b"ok");
    }
}
