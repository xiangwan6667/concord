use std::future::poll_fn;

use tokio::io::AsyncWriteExt;

use super::*;

impl Stack {
    pub(crate) fn serve_tcp_echo(self: &Arc<Self>, port: u16) -> JoinHandle<()> {
        let (accepted, mut streams) = mpsc::unbounded_channel();
        lock(&self.inner).listeners.insert(port, accepted);
        tokio::spawn(async move {
            while let Some(stream) = streams.recv().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = tokio::io::split(stream);
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                    let _ = writer.shutdown().await;
                });
            }
        })
    }

    pub(crate) fn serve_udp(
        self: &Arc<Self>,
        port: u16,
        answer: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static,
    ) -> JoinHandle<()> {
        let Ok(socket) = self.bind_udp_at(port) else {
            return tokio::spawn(async {});
        };
        let mtu = lock(&self.inner).mtu;
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu];
            while let Ok((n, from)) = poll_fn(|cx| socket.poll_recv_from(cx, &mut buf)).await {
                if let Some(reply) = buf.get(..n).and_then(&answer) {
                    let _ = poll_fn(|cx| socket.poll_send_to(cx, &reply, from)).await;
                }
            }
        })
    }
}
