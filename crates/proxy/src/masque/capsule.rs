#![allow(
    clippy::indexing_slicing,
    reason = "wire indices follow fixed header widths and explicit packet length checks"
)]

use std::io;

use bytes::Bytes;
use quinn_proto::VarInt;
use quinn_proto::coding::Codec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) async fn varint(read: &mut (impl AsyncRead + Unpin)) -> io::Result<u64> {
    let first = read.read_u8().await?;
    let size = 1usize << (first >> 6);
    let mut raw = [0; 8];
    raw[0] = first;
    read.read_exact(&mut raw[1..size]).await?;
    VarInt::decode(&mut &raw[..size])
        .map(VarInt::into_inner)
        .map_err(io::Error::other)
}

pub(super) async fn skip(read: &mut (impl AsyncRead + Unpin), length: u64) -> io::Result<()> {
    let copied = tokio::io::copy(&mut read.take(length), &mut tokio::io::sink()).await?;
    if copied != length {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

pub(super) fn encode(kind: u32, payload: &mut bytes::BytesMut) -> io::Result<()> {
    let mut raw = [0; 16];
    let mut room = raw.as_mut_slice();
    VarInt::from_u32(kind).encode(&mut room);
    VarInt::from_u64(payload.len() as u64)
        .map_err(io::Error::other)?
        .encode(&mut room);
    let header = 16 - room.len();
    let len = payload.len();
    payload.resize(len + header, 0);
    payload.copy_within(..len, header);
    payload[..header].copy_from_slice(&raw[..header]);
    Ok(())
}

pub(super) async fn send(
    write: &mut (impl AsyncWrite + Unpin),
    kind: u32,
    payload: &[u8],
) -> io::Result<()> {
    let mut raw = [0; 16];
    let mut room = raw.as_mut_slice();
    VarInt::from_u32(kind).encode(&mut room);
    VarInt::from_u64(payload.len() as u64)
        .map_err(io::Error::other)?
        .encode(&mut room);
    let len = 16 - room.len();
    write.write_all(&raw[..len]).await?;
    write.write_all(payload).await?;
    write.flush().await
}

pub(super) fn routes() -> Bytes {
    let mut body = Vec::new();
    body.push(4);
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&[255; 4]);
    body.push(0);
    body.push(6);
    body.extend_from_slice(&[0; 16]);
    body.extend_from_slice(&[255; 16]);
    body.push(0);
    body.into()
}

pub(super) fn decrement_hop(packet: &mut [u8]) -> bool {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 && packet[8] > 1 => {
            packet[8] -= 1;
            packet[10..12].fill(0);
            let mut sum: u32 = packet[..20]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
                .sum();
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            true
        }
        Some(6) if packet.len() >= 40 && packet[7] > 1 => {
            packet[7] -= 1;
            true
        }
        _ => false,
    }
}
