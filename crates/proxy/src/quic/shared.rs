use std::sync::Arc;

use bytes::Bytes;
use quinn::VarInt;
use tokio::task::JoinHandle;

use super::QuicConn;

/// Hands a connection's datagrams to the UDP sessions they belong to.
pub(crate) trait DatagramHub: Send + Sync + 'static {
    fn dispatch(&self, datagram: &Bytes);

    /// Ends every session. Runs when the connection stops yielding datagrams and again when
    /// the `SharedConn` drops, so a second call must be harmless.
    fn close_all(&self);
}

/// A QUIC connection a node shares among its streams and UDP sessions, with the task that
/// reads its datagrams into the hub. Dropping it ends that task and the hub's sessions.
pub(crate) struct SharedConn<H: DatagramHub> {
    pub(crate) quic: QuicConn,
    pub(crate) hub: Arc<H>,
    reader: JoinHandle<()>,
}

impl<H: DatagramHub> SharedConn<H> {
    pub(crate) fn new(quic: QuicConn, hub: H) -> Self {
        let hub = Arc::new(hub);
        let reader = {
            let (conn, hub) = (quic.conn.clone(), hub.clone());
            quic.tasks.spawn(async move {
                while let Ok(datagram) = conn.read_datagram().await {
                    hub.dispatch(&datagram);
                }
                hub.close_all();
            })
        };
        SharedConn { quic, hub, reader }
    }

    pub(crate) fn alive(&self) -> bool {
        self.quic.conn.close_reason().is_none()
    }

    pub(crate) fn close(&self) {
        self.quic.conn.close(VarInt::from_u32(0), b"");
    }
}

impl<H: DatagramHub> Drop for SharedConn<H> {
    fn drop(&mut self) {
        self.reader.abort();
        self.hub.close_all();
    }
}
