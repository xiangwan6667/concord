use std::collections::HashMap;
use std::io;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use concord_api::Control;
use concord_api::sync::lock;
use concord_rpc::{Incoming, MessageChannel, MessageReader, MessageWriter, SendError, Server};
use tokio::runtime::Handle;
use tokio::sync::mpsc;

/// Where one session's outgoing messages go. `false` says the host is gone: the
/// session ends and the subscriptions it held leave their topics.
pub trait Receiver: Send + 'static {
    fn deliver(&mut self, message: Vec<u8>) -> bool;
}

struct HostReader(mpsc::UnboundedReceiver<Vec<u8>>);

struct HostWriter {
    id: u64,
    receiver: Box<dyn Receiver>,
}

struct HostChannel {
    id: u64,
    input: mpsc::UnboundedReceiver<Vec<u8>>,
    receiver: Box<dyn Receiver>,
}

impl MessageReader for HostReader {
    async fn recv(&mut self) -> io::Result<Option<Incoming>> {
        Ok(self.0.recv().await.map(Incoming::Message))
    }
}

impl MessageWriter for HostWriter {
    async fn send(&mut self, message: Vec<u8>) -> Result<(), SendError> {
        if self.receiver.deliver(message) {
            Ok(())
        } else {
            notice(
                true,
                format!("session {}: the receiver is gone, ending it", self.id),
            );
            Err(SendError::Broken(io::ErrorKind::BrokenPipe.into()))
        }
    }
}

impl MessageChannel for HostChannel {
    type Reader = HostReader;
    type Writer = HostWriter;

    fn split(self) -> (HostReader, HostWriter) {
        (
            HostReader(self.input),
            HostWriter {
                id: self.id,
                receiver: self.receiver,
            },
        )
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    lock(mutex)
}

/// The sessions of one core. Each is a connection of the RPC server that lives
/// until its host closes it or its receiver reports the host gone.
pub struct Hub {
    handle: Handle,
    server: Arc<Server<Control>>,
    sessions: Mutex<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>,
    next: AtomicU64,
}

impl Hub {
    pub fn new(handle: Handle, server: Arc<Server<Control>>) -> Arc<Hub> {
        Arc::new(Hub {
            handle,
            server,
            sessions: Mutex::new(HashMap::new()),
            next: AtomicU64::new(0),
        })
    }

    /// The id of the new session, which is never 0.
    pub fn open(self: &Arc<Self>, receiver: Box<dyn Receiver>) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (input, frames) = mpsc::unbounded_channel();
        locked(&self.sessions).insert(id, input);
        notice(false, format!("session {id} opened"));
        let hub = self.clone();
        self.handle.spawn(async move {
            hub.server
                .serve(HostChannel {
                    id,
                    input: frames,
                    receiver,
                })
                .await;
            locked(&hub.sessions).remove(&id);
            notice(false, format!("session {id} ended"));
        });
        id
    }

    /// One complete message. `false` when the session is gone.
    pub fn send(&self, session: u64, message: Vec<u8>) -> bool {
        locked(&self.sessions)
            .get(&session)
            .is_some_and(|input| input.send(message).is_ok())
    }

    /// Ends the session, cancelling everything it started. Closing twice is harmless.
    pub fn close(&self, session: u64) {
        locked(&self.sessions).remove(&session);
    }

    /// A descriptor the host opened for the core, to be named by `tun.start`. Ownership moves to the core.
    #[cfg(unix)]
    pub fn adopt_fd(&self, fd: OwnedFd) -> u64 {
        self.server.service().adopted_fds().adopt(fd)
    }
}

static HUB: OnceLock<Arc<Hub>> = OnceLock::new();
static NOTICE: OnceLock<fn(&str)> = OnceLock::new();

/// Routes session lifecycle lines to the host's own log. The log stream to Flutter is gone exactly when they matter,
/// and the host's `tracing` subscriber may filter them out.
pub fn set_notice(sink: fn(&str)) {
    let _ = NOTICE.set(sink);
}

fn notice(warn: bool, message: String) {
    match NOTICE.get() {
        Some(sink) => sink(&message),
        None if warn => tracing::warn!("{message}"),
        None => tracing::info!("{message}"),
    }
}

/// Makes `hub` the one the exported functions use. `false` when one is installed already.
pub fn install(hub: Arc<Hub>) -> bool {
    HUB.set(hub).is_ok()
}

pub fn hub() -> Option<&'static Arc<Hub>> {
    HUB.get()
}
