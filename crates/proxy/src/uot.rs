use std::io;
use std::sync::Arc;

use concord_common::{Address, BoxStream, PacketBuf, PacketSession, Tasks};

use crate::addr_codec::{MAX_ADDR_LEN, SOCKS, UOT};
use crate::dgram::{Decoded, Decoder, Encoder, StreamSession};
use crate::lazy::HeadFirst;

const MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
const LEGACY_MAGIC: &str = "sp.udp-over-tcp.arpa";
pub(crate) const LEGACY_VERSION: u8 = 1;

/// The destination a UoT stream is opened to. Version 0 means 2, as in sing.
pub(crate) fn destination(version: u8) -> Address {
    let host = if matches!(version, 0 | 2) {
        MAGIC
    } else {
        LEGACY_MAGIC
    };
    Address::Domain(host.into(), 0)
}

/// The packets of one UDP flow over `stream`, which was opened to [`destination`].
pub(crate) fn session(
    stream: BoxStream,
    version: u8,
    hint: &Address,
    tasks: &Tasks,
) -> io::Result<Arc<dyn PacketSession>> {
    let mut request = Vec::new();
    if version != LEGACY_VERSION {
        request.push(0);
        SOCKS.write(hint, &mut request)?;
    }
    Ok(Arc::new(StreamSession::new(
        Box::new(HeadFirst::new(stream, request)),
        UotFrames,
        UotFrames,
        hint.clone(),
        tasks,
    )))
}

struct UotFrames;

impl Encoder for UotFrames {
    fn headroom(&self) -> usize {
        MAX_ADDR_LEN + 2
    }

    fn encode(&mut self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        let len = u16::try_from(pkt.len()).map_err(|_| io::Error::other("datagram too long"))?;
        pkt.prepend(2).copy_from_slice(&len.to_be_bytes());
        let addr_len = UOT.len(dst);
        UOT.write_into(dst, pkt.prepend(addr_len))?;
        Ok(())
    }
}

impl Decoder for UotFrames {
    fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded> {
        let Some((addr, used)) = UOT.parse(input)? else {
            return Ok(Decoded::NeedMore);
        };
        let Some(&[hi, lo]) = input.get(used..used + 2) else {
            return Ok(Decoded::NeedMore);
        };
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        let start = used + 2;
        if input.len() < start + len {
            return Ok(Decoded::NeedMore);
        }
        Ok(Decoded::Packet {
            addr: Some(addr),
            payload: start..start + len,
            consumed: start + len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let dst = Address::new("example.com", 5353);
        let mut pkt = PacketBuf::with_headroom(UotFrames.headroom());
        pkt.extend_from_slice(b"abc");
        UotFrames.encode(&mut pkt, &dst).unwrap();
        let mut wire = pkt.as_slice().to_vec();
        assert_eq!(wire.first(), Some(&2));
        let Decoded::Packet { addr, payload, .. } = UotFrames.decode(&mut wire).unwrap() else {
            panic!("expected a packet");
        };
        assert_eq!(addr, Some(dst));
        assert_eq!(&wire[payload], b"abc");
    }

    #[test]
    fn version_zero_is_version_two() {
        assert_eq!(destination(0), destination(2));
        assert_ne!(destination(1), destination(2));
    }
}
