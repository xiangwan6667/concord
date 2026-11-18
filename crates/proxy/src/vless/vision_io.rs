use concord_tls::{TlsRead, TlsWrite};
use tokio::io::{AsyncRead, AsyncWrite};

use super::encryption::{EncryptedRead, EncryptedWrite};

pub(crate) trait VisionRead: AsyncRead + Send + Unpin + 'static {
    type Raw: AsyncRead + Send + Unpin + ?Sized;
    fn raw_read(&mut self) -> &mut Self::Raw;
    fn has_pending_plaintext(&mut self) -> bool;
    fn drain_plaintext(&mut self, out: &mut Vec<u8>);
    fn at_record_boundary(&self) -> bool;
}

pub(crate) trait VisionWrite: AsyncWrite + Send + Unpin + 'static {
    type Raw: AsyncWrite + Send + Unpin + ?Sized;
    fn raw_write(&mut self) -> &mut Self::Raw;
}

impl VisionRead for TlsRead {
    type Raw = concord_common::BoxRead;
    fn raw_read(&mut self) -> &mut Self::Raw {
        self.raw_mut()
    }
    fn has_pending_plaintext(&mut self) -> bool {
        TlsRead::has_pending_plaintext(self)
    }
    fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        self.drain_plaintext(out);
    }
    fn at_record_boundary(&self) -> bool {
        self.at_record_boundary()
    }
}

impl VisionWrite for TlsWrite {
    type Raw = concord_common::BoxWrite;
    fn raw_write(&mut self) -> &mut Self::Raw {
        self.raw_mut()
    }
}

impl VisionRead for EncryptedRead {
    type Raw = dyn AsyncRead + Send + Unpin;
    fn raw_read(&mut self) -> &mut Self::Raw {
        self.raw_mut()
    }
    fn has_pending_plaintext(&mut self) -> bool {
        EncryptedRead::has_pending_plaintext(self)
    }
    fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        self.drain_plaintext(out);
    }
    fn at_record_boundary(&self) -> bool {
        self.at_record_boundary()
    }
}

impl VisionWrite for EncryptedWrite {
    type Raw = dyn AsyncWrite + Send + Unpin;
    fn raw_write(&mut self) -> &mut Self::Raw {
        self.raw_mut()
    }
}
