use std::io;

use bytes::BytesMut;
use concord_common::stream_buffer::BufferRequirements;

use super::frame::{Chunk, Opener, Sealer};

pub(super) trait Encode: Send + Unpin + 'static {
    fn seal_stream(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()>;
    fn seal_chunk(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()>;
    fn seal_zero(&mut self, out: &mut Vec<u8>) -> io::Result<()>;
    fn write_requirements(&self) -> BufferRequirements;
}

pub(super) trait Decode: Send + Unpin + 'static {
    fn open(&mut self, input: &mut BytesMut, plain: &mut BytesMut) -> io::Result<Option<Chunk>>;
    fn at_chunk_boundary(&self) -> bool;
}

impl Encode for Sealer {
    fn seal_stream(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        self.seal_stream(out, data)
    }
    fn seal_chunk(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        self.seal_chunk(out, data)
    }
    fn seal_zero(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        self.seal_zero(out)
    }
    fn write_requirements(&self) -> BufferRequirements {
        self.write_requirements()
    }
}

impl Decode for Opener {
    fn open(&mut self, input: &mut BytesMut, plain: &mut BytesMut) -> io::Result<Option<Chunk>> {
        self.open(input, plain)
    }
    fn at_chunk_boundary(&self) -> bool {
        self.at_chunk_boundary()
    }
}
