use std::convert::Infallible;
use std::io;

/// Only Linux moves bytes between sockets with `splice`, so elsewhere no pipe is ever made.
pub struct SplicePipe(Infallible);

impl SplicePipe {
    pub const AVAILABLE: bool = false;

    pub fn new() -> io::Result<Self> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub fn queued(&self) -> usize {
        match self.0 {}
    }

    pub fn fill<T: ?Sized>(&mut self, _src: &T) -> io::Result<usize> {
        match self.0 {}
    }

    pub fn drain<T: ?Sized>(&mut self, _dst: &T) -> io::Result<usize> {
        match self.0 {}
    }
}
