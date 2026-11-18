use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{Address, BoxStream, DialCx, Outbound, OutboundInfo, PacketSession};
use tokio::io::AsyncWriteExt;

use super::codec::Encode;
use super::stream::SnellStream;
use super::udp::SnellPackets;
use super::v6_frame::{Mode, Opener, Sealer};
use super::v6_profile::Profile;
use crate::node::Link;
use crate::util::invalid_data;

pub(super) struct SnellV6 {
    pub(super) info: OutboundInfo,
    pub(super) link: Link,
    pub(super) psk: Vec<u8>,
    pub(super) userkey: Vec<u8>,
    pub(super) mode: Mode,
    pub(super) profile: Option<Arc<Profile>>,
    pub(super) reuse: bool,
}

pub(super) fn header(command: u8, userkey: &[u8], dst: Option<&Address>) -> io::Result<Vec<u8>> {
    let len = u8::try_from(userkey.len()).map_err(|_| invalid_data("snell userkey too long"))?;
    let mut out = vec![super::PROTOCOL, command, len];
    out.extend_from_slice(userkey);
    if let Some(dst) = dst {
        let legacy = super::request(dst, command)?;
        out.extend_from_slice(legacy.get(3..).unwrap_or_default());
    }
    Ok(out)
}

#[async_trait]
impl Outbound for SnellV6 {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let raw = self.link.open(cx).await?;
        let mut stream = SnellStream::with_codecs(
            raw,
            Sealer::new(self.mode, &self.psk, self.profile.clone())?,
            Opener::new(self.mode, &self.psk, self.profile.clone()),
        );
        let command = if self.reuse {
            super::CONNECT_V2
        } else {
            stream.without_end_chunk();
            super::CONNECT
        };
        stream.queue(&header(command, &self.userkey, Some(dst))?)?;
        stream.flush().await?;
        Ok(Box::new(stream))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let mut raw = self.link.open(cx).await?;
        let mut sealer = Sealer::new(self.mode, &self.psk, self.profile.clone())?;
        let mut wire = Vec::new();
        sealer.seal_stream(&mut wire, &header(super::UDP, &self.userkey, None)?)?;
        raw.write_all(&wire).await?;
        raw.flush().await?;
        let packets = SnellPackets::with_codecs(
            raw,
            sealer,
            Opener::new(self.mode, &self.psk, self.profile.clone()),
        );
        packets.read_reply().await?;
        Ok(Arc::new(packets))
    }
}
