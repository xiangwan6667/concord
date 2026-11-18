use std::io;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, DialCx, DialEnv, Initiator, Outbound, OutboundInfo, PacketBuf,
    PacketSession, Tasks,
};
use concord_config::proxy::SmuxOpts;
use concord_transport::{
    Brutal, MuxDialFn, MuxProtocol, PacketReader, PacketWriter, SingMuxClient, SingMuxOptions,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::ctx::BuildError;
use crate::lazy::Kick;
use crate::link::EnvSlot;
use crate::util::parse_bps;

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const QUEUE: usize = 128;

struct Muxed {
    info: OutboundInfo,
    inner: Arc<dyn Outbound>,
    client: Arc<SingMuxClient>,
    slot: EnvSlot,
    only_tcp: bool,
    tasks: Tasks,
}

impl Muxed {
    fn remember(&self, cx: &DialCx<'_>) {
        self.slot.store(Some(Arc::new(cx.env.clone())));
    }
}

#[async_trait]
impl Outbound for Muxed {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        self.remember(cx);
        Ok(Box::new(Kick::new(self.client.connect_tcp(dst).await?)))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if self.only_tcp {
            return self.inner.associate(cx, hint).await;
        }
        self.remember(cx);
        let (reader, writer) = self.client.listen_packet(Some(hint)).await?;
        Ok(Arc::new(MuxPackets::new(
            reader,
            writer,
            hint.clone(),
            &self.tasks,
        )))
    }

    fn multi_destination_udp(&self) -> bool {
        !self.only_tcp || self.inner.multi_destination_udp()
    }

    fn reset_sessions(&self) {
        self.inner.reset_sessions();
        let client = self.client.clone();
        self.tasks
            .spawn_detached(async move { client.close().await });
    }
}

struct MuxPackets {
    outgoing: mpsc::Sender<(Vec<u8>, Address)>,
    incoming: Mutex<mpsc::Receiver<(Vec<u8>, Option<Address>)>>,
    hint: Address,
    tasks: [JoinHandle<()>; 2],
}

impl MuxPackets {
    fn new(
        mut reader: PacketReader,
        mut writer: PacketWriter,
        hint: Address,
        tasks: &Tasks,
    ) -> Self {
        let (outgoing, mut queue) = mpsc::channel::<(Vec<u8>, Address)>(QUEUE);
        let (feed, incoming) = mpsc::channel(QUEUE);
        let write = tasks.spawn(async move {
            while let Some((payload, to)) = queue.recv().await {
                if writer.send(&payload, Some(&to)).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });
        let read = tasks.spawn(async move {
            while let Ok(packet) = reader.recv().await {
                if feed.send(packet).await.is_err() {
                    break;
                }
            }
        });
        MuxPackets {
            outgoing,
            incoming: Mutex::new(incoming),
            hint,
            tasks: [write, read],
        }
    }
}

impl Drop for MuxPackets {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl PacketSession for MuxPackets {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        match self
            .outgoing
            .try_send((pkt.as_slice().to_vec(), dst.clone()))
        {
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        let received = lock(&self.incoming).poll_recv(cx);
        match received {
            Poll::Ready(Some((payload, from))) => {
                buf.extend_from_slice(&payload);
                Poll::Ready(Ok(from.unwrap_or_else(|| self.hint.clone())))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn dial_through(inner: Arc<dyn Outbound>, slot: EnvSlot) -> MuxDialFn {
    Arc::new(move |target: Address| {
        let (inner, slot) = (inner.clone(), slot.clone());
        Box::pin(async move {
            let env: Arc<DialEnv> = slot
                .load_full()
                .ok_or_else(|| io::Error::other("smux dial without an environment"))?;
            let cx = DialCx::new(&env, Initiator::Proxy, None);
            inner.connect(&cx, &target).await
        })
    })
}

pub(crate) fn wrap(
    inner: Arc<dyn Outbound>,
    opts: &SmuxOpts,
    tasks: &Tasks,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let brutal = opts
        .brutal
        .as_ref()
        .filter(|brutal| brutal.enabled)
        .map(|brutal| Brutal {
            send_bps: parse_bps(&brutal.up),
            receive_bps: parse_bps(&brutal.down),
        });
    let protocol =
        MuxProtocol::parse(&opts.protocol).map_err(|err| BuildError::invalid(err.to_string()))?;
    let slot: EnvSlot = Arc::new(ArcSwapOption::empty());
    let client = SingMuxClient::new(
        SingMuxOptions {
            protocol,
            max_connections: opts.max_connections as usize,
            min_streams: opts.min_streams as usize,
            max_streams: opts.max_streams as usize,
            padding: opts.padding,
            tcp_timeout: TCP_TIMEOUT,
            brutal,
        },
        dial_through(inner.clone(), slot.clone()),
        tasks.clone(),
    );
    let mut info = inner.info().clone();
    info.udp = info.udp || !opts.only_tcp;
    Ok(Arc::new(Muxed {
        info,
        inner,
        client,
        slot,
        only_tcp: opts.only_tcp,
        tasks: tasks.clone(),
    }))
}
