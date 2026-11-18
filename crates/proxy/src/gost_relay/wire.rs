use std::io;

use concord_common::{Address, PacketBuf};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::addr_codec::SOCKS;
use crate::dgram::{Decoded, Decoder, Encoder};

const VERSION: u8 = 1;
const CONNECT: u8 = 1;
const CONNECT_UDP: u8 = 0x81;
const FEATURE_AUTH: u8 = 1;
const FEATURE_ADDRESS: u8 = 2;
const FEATURE_NETWORK: u8 = 4;
const NETWORK_TCP: u16 = 0;
const NETWORK_UDP: u16 = 1;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn feature(out: &mut Vec<u8>, kind: u8, payload: &[u8]) -> io::Result<()> {
    let len = u16::try_from(payload.len()).map_err(|_| invalid("relay feature too large"))?;
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

pub(super) fn request(
    target: Option<&Address>,
    udp: bool,
    username: &str,
    password: &str,
) -> io::Result<Vec<u8>> {
    let mut features = Vec::new();
    if !username.is_empty() || !password.is_empty() {
        let user_len =
            u8::try_from(username.len()).map_err(|_| invalid("relay username too long"))?;
        let pass_len =
            u8::try_from(password.len()).map_err(|_| invalid("relay password too long"))?;
        let mut auth = vec![user_len];
        auth.extend_from_slice(username.as_bytes());
        auth.push(pass_len);
        auth.extend_from_slice(password.as_bytes());
        feature(&mut features, FEATURE_AUTH, &auth)?;
    }
    if let Some(target) = target {
        let mut address = Vec::new();
        match target {
            Address::Socket(socket) => SOCKS.write(&Address::from(*socket), &mut address)?,
            _ => SOCKS.write(target, &mut address)?,
        }
        feature(&mut features, FEATURE_ADDRESS, &address)?;
    }
    let network = if udp { NETWORK_UDP } else { NETWORK_TCP };
    feature(&mut features, FEATURE_NETWORK, &network.to_be_bytes())?;
    let len = u16::try_from(features.len()).map_err(|_| invalid("relay features too large"))?;
    let mut out = vec![VERSION, if udp { CONNECT_UDP } else { CONNECT }];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&features);
    Ok(out)
}

pub(super) async fn response(io: &mut (impl AsyncRead + Unpin)) -> io::Result<()> {
    let mut head = [0; 4];
    io.read_exact(&mut head).await?;
    let [version, status, hi, lo] = head;
    if version != VERSION {
        return Err(invalid(format!("gost relay bad version: {version}")));
    }
    if status != 0 {
        return Err(invalid(format!(
            "gost relay connect failed with status 0x{status:02x} ({})",
            status_text(status)
        )));
    }
    let mut remaining = usize::from(u16::from_be_bytes([hi, lo]));
    let mut discard = [0; 256];
    while remaining != 0 {
        let count = remaining.min(discard.len());
        let chunk = discard
            .get_mut(..count)
            .ok_or_else(|| invalid("relay feature buffer"))?;
        io.read_exact(chunk).await?;
        remaining -= count;
    }
    Ok(())
}

fn status_text(status: u8) -> &'static str {
    match status {
        0 => "ok",
        1 => "bad request",
        2 => "unauthorized",
        3 => "forbidden",
        4 => "timeout",
        5 => "service unavailable",
        6 => "host unreachable",
        7 => "network unreachable",
        8 => "internal server error",
        _ => "unknown",
    }
}

pub(super) struct Frames(pub Address);

impl Encoder for Frames {
    fn headroom(&self) -> usize {
        2
    }

    fn encode(&mut self, packet: &mut PacketBuf, target: &Address) -> io::Result<()> {
        if target != &self.0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gost relay UDP association is bound to another destination",
            ));
        }
        let len = u16::try_from(packet.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "gost relay UDP packet too large",
            )
        })?;
        packet.prepend(2).copy_from_slice(&len.to_be_bytes());
        Ok(())
    }
}

impl Decoder for Frames {
    fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded> {
        let Some(&[hi, lo]) = input.get(..2) else {
            return Ok(Decoded::NeedMore);
        };
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        if input.len() < len + 2 {
            return Ok(Decoded::NeedMore);
        }
        Ok(Decoded::Packet {
            addr: None,
            payload: 2..len + 2,
            consumed: len + 2,
        })
    }
}
