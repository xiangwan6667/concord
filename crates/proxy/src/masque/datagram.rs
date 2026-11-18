#![allow(
    clippy::indexing_slicing,
    reason = "wire indices follow fixed header widths and explicit packet length checks"
)]

use std::io;

use bytes::BytesMut;
use quinn_proto::VarInt;
use quinn_proto::coding::Codec;

const HEADER_MAX: usize = 9;

fn quarter_id(stream_id: u64) -> io::Result<VarInt> {
    if stream_id > VarInt::MAX.into_inner() || !stream_id.is_multiple_of(4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP datagram requires a client-initiated bidirectional stream",
        ));
    }
    VarInt::from_u64(stream_id / 4).map_err(io::Error::other)
}

pub(super) fn header_len(stream_id: u64) -> io::Result<usize> {
    let mut raw = [0; HEADER_MAX];
    let mut room = raw.as_mut_slice();
    quarter_id(stream_id)?.encode(&mut room);
    Ok(HEADER_MAX - room.len() + 1)
}

pub(super) fn encode(stream_id: u64, packet: &mut BytesMut) -> io::Result<()> {
    let quarter = quarter_id(stream_id)?;
    let mut header = [0; HEADER_MAX];
    let mut available = header.as_mut_slice();
    quarter.encode(&mut available);
    VarInt::from_u32(0).encode(&mut available);
    let used = HEADER_MAX - available.len();
    let len = packet.len();
    packet.resize(len + used, 0);
    packet.copy_within(..len, used);
    packet[..used].copy_from_slice(&header[..used]);
    Ok(())
}

pub(super) fn decode(stream_id: u64, mut packet: &[u8]) -> io::Result<Option<&[u8]>> {
    let expected = quarter_id(stream_id)?;
    let quarter = VarInt::decode(&mut packet).map_err(|_| truncated())?;
    if quarter.into_inner() > VarInt::MAX.into_inner() / 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP datagram quarter stream ID exceeds the QUIC stream ID range",
        ));
    }
    if quarter != expected {
        return Ok(None);
    }
    let context = VarInt::decode(&mut packet).map_err(|_| truncated())?;
    Ok((context.into_inner() == 0).then_some(packet))
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "truncated HTTP datagram header")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masque_datagram_nonzero_stream_ids_have_their_quarter_on_the_wire() {
        for (stream, header) in [
            (0, vec![0, 0]),
            (4, vec![1, 0]),
            (252, vec![63, 0]),
            (256, vec![0x40, 0x40, 0]),
            (65536, vec![0x80, 0, 0x40, 0, 0]),
            (
                VarInt::MAX.into_inner() - 3,
                vec![0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0],
            ),
        ] {
            let payload = b"\x45\x00ip packet";
            let mut packet = BytesMut::from(payload.as_slice());
            encode(stream, &mut packet).unwrap();
            assert_eq!(header_len(stream).unwrap(), header.len());
            let mut expected = header;
            expected.extend_from_slice(payload);
            assert_eq!(packet.as_ref(), expected);
            assert_eq!(
                decode(stream, expected.as_slice()).unwrap(),
                Some(payload.as_slice())
            );
        }
    }

    #[test]
    fn masque_datagram_ignores_other_requests_and_unknown_contexts() {
        assert_eq!(decode(4, &[0, 0, 0x45]).unwrap(), None);
        assert_eq!(decode(4, &[1, 1, 0x45]).unwrap(), None);
        assert_eq!(decode(4, &[1, 0x40, 0x40, 0x45]).unwrap(), None);
        assert_eq!(decode(4, &[1, 0, 0x45]).unwrap(), Some([0x45].as_slice()));
    }

    #[test]
    fn masque_datagram_rejects_truncated_and_overflowing_headers() {
        for bytes in [
            &[][..],
            &[0x40],
            &[1],
            &[1, 0x40],
            &[0xd0, 0, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(
                decode(4, bytes).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        for stream in [1, 2, 3, 1 << 62] {
            let mut packet = BytesMut::from(b"ip".as_slice());
            assert_eq!(
                encode(stream, &mut packet).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(packet.as_ref(), b"ip");
        }
    }
}
