use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use concord_api::ControlService;
use concord_proto::MAX_MESSAGE;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::channel::{Incoming, MessageChannel, MessageReader, MessageWriter, SendError};
use crate::session::Session;

const OUTBOX_DEPTH: usize = 16;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub max_message: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            max_message: MAX_MESSAGE,
        }
    }
}

pub struct Server<S: ControlService> {
    service: Arc<S>,
    config: ServerConfig,
}

static DELIVERY_FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);

/// Must not reach the log stream: log entries are handed back to this writer, so
/// reporting a send failure through them feeds the failure into itself.
fn report_delivery(message: std::fmt::Arguments<'_>) {
    if !DELIVERY_FAILURE_REPORTED.swap(true, Ordering::Relaxed) {
        eprintln!("[ERROR] {message}");
    }
}

async fn write_loop<W: MessageWriter>(
    mut writer: W,
    mut outbox: mpsc::Receiver<Vec<u8>>,
    broken: CancellationToken,
) {
    while let Some(message) = outbox.recv().await {
        match writer.send(message).await {
            Ok(()) => DELIVERY_FAILURE_REPORTED.store(false, Ordering::Relaxed),
            Err(SendError::Dropped(err)) => {
                report_delivery(format_args!(
                    "server write error, dropped one message: {err}"
                ));
            }
            Err(SendError::Broken(err)) => {
                report_delivery(format_args!("server write error: {err}"));
                broken.cancel();
                return;
            }
        }
    }
}

impl<S: ControlService> Server<S> {
    pub fn new(service: Arc<S>) -> Self {
        Self::with_config(service, ServerConfig::default())
    }

    pub fn with_config(service: Arc<S>, config: ServerConfig) -> Self {
        Server { service, config }
    }

    pub fn service(&self) -> &S {
        &self.service
    }

    /// Serves one connection until the peer closes it or a write breaks it.
    /// Everything the connection started is stopped before this returns: running
    /// requests are dropped and every subscription leaves its topic.
    pub async fn serve<C: MessageChannel>(&self, channel: C) {
        let (mut reader, writer) = channel.split();
        let (outbox, outgoing) = mpsc::channel(OUTBOX_DEPTH);
        let (serial, mut queue) = mpsc::unbounded_channel();
        let session = Session::new(
            self.service.clone(),
            self.config.max_message,
            outbox,
            serial,
        );
        let broken = CancellationToken::new();
        let mut tasks = JoinSet::new();
        tasks.spawn(write_loop(writer, outgoing, broken.clone()));
        tasks.spawn(async move {
            while let Some(job) = queue.recv().await {
                job.await;
            }
        });

        loop {
            let received = tokio::select! {
                biased;
                () = broken.cancelled() => break,
                received = reader.recv() => received,
            };
            match received {
                Ok(Some(Incoming::Message(bytes))) => {
                    if let Err(reason) = session.handle(&bytes, &mut tasks) {
                        session.reject_unparsable(&reason).await;
                    }
                }
                Ok(Some(Incoming::Oversized { len })) => session.reject_oversized(len).await,
                Ok(None) => break,
                Err(err) => {
                    if err.kind() != std::io::ErrorKind::UnexpectedEof {
                        tracing::error!("server read error: {err}");
                    }
                    break;
                }
            }
        }
        session.close();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}
