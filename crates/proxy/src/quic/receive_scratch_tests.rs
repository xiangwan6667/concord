use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use concord_common::sync::lock;
use quinn::udp::{BATCH_SIZE, RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, TokioRuntime, UdpPoller};
use tokio::sync::Notify;

#[derive(Debug, Default)]
struct Observed {
    addresses: Mutex<BTreeMap<usize, usize>>,
    polled: Notify,
}

#[derive(Debug)]
struct RecordingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    observed: Arc<Observed>,
    id: usize,
}

impl AsyncUdpSocket for RecordingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let payload = EndpointConfig::default().get_max_udp_payload_size() as usize;
        assert_eq!(bufs.len(), BATCH_SIZE);
        assert!(
            bufs.iter()
                .all(|buf| buf.len() == payload * self.max_receive_segments())
        );
        lock(&self.observed.addresses).insert(self.id, bufs[0].as_ptr() as usize);
        self.observed.polled.notify_one();
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn endpoints_on_one_poller_share_receive_scratch_at_full_batch_capacity() {
    let observed = Arc::new(Observed::default());
    let mut endpoints = Vec::new();
    for id in 0..4 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let socket = Arc::new(RecordingSocket {
            inner: TokioRuntime.wrap_udp_socket(socket).unwrap(),
            observed: observed.clone(),
            id,
        });
        endpoints.push(
            Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                None,
                socket,
                Arc::new(TokioRuntime),
            )
            .unwrap(),
        );
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while lock(&observed.addresses).len() < endpoints.len() {
            observed.polled.notified().await;
        }
    })
    .await
    .expect("every endpoint polls its socket");
    let distinct: BTreeSet<_> = lock(&observed.addresses).values().copied().collect();
    assert_eq!(
        distinct.len(),
        1,
        "receive scratch follows polling, not endpoint lifetime"
    );
    drop(endpoints);
}
