mod h2mux;
mod inbox;
mod padding;
mod single;
mod smux;
pub(crate) use single::smux_stream;
#[cfg(test)]
mod tests;
mod wire;
mod yamux;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use concord_common::{Address, BoxStream, Tasks};
use futures_util::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use self::h2mux::H2MuxSession;
use self::padding::{encode_request, padding_conn, protocol_conn};
use self::smux::SmuxSession;
use self::wire::{Kind, client_stream, mux_destination, packet_pair};
use self::yamux::YamuxSession;
use crate::http1::invalid;

pub use self::wire::{PacketReader, PacketWriter};

trait MuxSession: Send + Sync {
    fn open(&self) -> BoxFuture<'_, io::Result<BoxStream>>;
    fn streams(&self) -> usize;
    fn is_closed(&self) -> bool;
    fn close(&self);
    fn can_take_new_request(&self) -> bool {
        true
    }
}

/// Dials the node for one mux session; the address is always the fixed
/// `sp.mux.sing-box.arpa:444` that sing-box servers recognise.
pub type MuxDialFn =
    Arc<dyn Fn(Address) -> BoxFuture<'static, io::Result<BoxStream>> + Send + Sync>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MuxProtocol {
    #[default]
    H2Mux,
    Smux,
    Yamux,
}

impl MuxProtocol {
    /// An empty name is `h2mux`, as in sing-mux.
    pub fn parse(name: &str) -> io::Result<Self> {
        match name {
            "" | "h2mux" => Ok(MuxProtocol::H2Mux),
            "smux" => Ok(MuxProtocol::Smux),
            "yamux" => Ok(MuxProtocol::Yamux),
            other => Err(invalid(format!("unknown protocol: {other}"))),
        }
    }

    fn id(self) -> u8 {
        match self {
            MuxProtocol::Smux => 0,
            MuxProtocol::Yamux => 1,
            MuxProtocol::H2Mux => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Brutal {
    pub send_bps: u64,
    pub receive_bps: u64,
}

#[derive(Clone, Debug)]
pub struct SingMuxOptions {
    pub protocol: MuxProtocol,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub padding: bool,
    pub tcp_timeout: Duration,
    pub brutal: Option<Brutal>,
}

impl Default for SingMuxOptions {
    fn default() -> Self {
        SingMuxOptions {
            protocol: MuxProtocol::default(),
            max_connections: 0,
            min_streams: 0,
            max_streams: 0,
            padding: false,
            tcp_timeout: Duration::from_secs(5),
            brutal: None,
        }
    }
}

/// The client's socket keeps the system congestion control after the Brutal
/// exchange: `tcp-brutal` is a Linux module sing-mux ignores when missing.
pub struct SingMuxClient {
    opts: SingMuxOptions,
    dial: MuxDialFn,
    sessions: tokio::sync::Mutex<Vec<Arc<dyn MuxSession>>>,
    tasks: Tasks,
}

impl SingMuxClient {
    pub fn new(mut opts: SingMuxOptions, dial: MuxDialFn, tasks: Tasks) -> Arc<Self> {
        if opts.max_streams == 0 && opts.max_connections == 0 {
            opts.min_streams = 8;
        }
        if opts.tcp_timeout.is_zero() {
            opts.tcp_timeout = Duration::from_secs(5);
        }
        Arc::new(SingMuxClient {
            opts,
            dial,
            sessions: tokio::sync::Mutex::new(Vec::new()),
            tasks,
        })
    }

    pub async fn connect_tcp(&self, destination: &Address) -> io::Result<BoxStream> {
        let stream = self.open_stream().await?;
        Ok(Box::new(client_stream(stream, Kind::Tcp, destination)?))
    }

    /// A UDP flow to one fixed destination.
    pub async fn connect_udp(
        &self,
        destination: &Address,
    ) -> io::Result<(PacketReader, PacketWriter)> {
        let stream = self.open_stream().await?;
        let stream = client_stream(stream, Kind::Udp, destination)?;
        Ok(packet_pair(stream, false))
    }

    /// A UDP socket whose every packet names its own address.
    pub async fn listen_packet(
        &self,
        first: Option<&Address>,
    ) -> io::Result<(PacketReader, PacketWriter)> {
        let stream = self.open_stream().await?;
        let destination = first.cloned().unwrap_or_else(mux_destination);
        let stream = client_stream(stream, Kind::UdpAddr, &destination)?;
        Ok(packet_pair(stream, true))
    }

    /// Closes every session; the next stream dials a new one. sing-mux's `Close` is its
    /// `Reset` (`client.go:256-268`), which leaves the client usable.
    pub async fn close(&self) {
        for session in self.sessions.lock().await.drain(..) {
            session.close();
        }
    }

    async fn open_stream(&self) -> io::Result<BoxStream> {
        let mut last = io::Error::other("no attempt was made");
        for _ in 0..2 {
            let session = match self.offer().await {
                Ok(session) => session,
                Err(err) => {
                    last = err;
                    continue;
                }
            };
            match tokio::time::timeout(self.opts.tcp_timeout, session.open()).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(err)) => last = err,
                Err(_) => last = io::ErrorKind::TimedOut.into(),
            }
        }
        Err(last)
    }

    async fn offer(&self) -> io::Result<Arc<dyn MuxSession>> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|session| {
            if session.is_closed() {
                session.close();
                false
            } else {
                true
            }
        });
        if self.opts.brutal.is_some()
            && let Some(first) = sessions.first()
        {
            return Ok(first.clone());
        }
        let best = sessions
            .iter()
            .filter(|session| session.can_take_new_request())
            .min_by_key(|session| session.streams())
            .cloned();
        if let Some(session) = best {
            let streams = session.streams();
            let reuse = streams == 0
                || if self.opts.max_connections > 0 {
                    sessions.len() >= self.opts.max_connections || streams < self.opts.min_streams
                } else {
                    self.opts.max_streams > 0 && streams < self.opts.max_streams
                };
            if reuse {
                return Ok(session);
            }
        }
        let session = tokio::time::timeout(self.opts.tcp_timeout, self.new_session())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        sessions.push(session.clone());
        Ok(session)
    }

    async fn new_session(&self) -> io::Result<Arc<dyn MuxSession>> {
        let conn = (self.dial)(mux_destination()).await?;
        let version = u8::from(self.opts.padding);
        let request = encode_request(version, self.opts.protocol.id(), self.opts.padding);
        let mut conn: BoxStream = protocol_conn(conn, request);
        if self.opts.padding {
            conn = padding_conn(conn);
        }
        let session: Arc<dyn MuxSession> = match self.opts.protocol {
            MuxProtocol::Smux => Arc::new(SmuxSession::new(conn, &self.tasks)),
            MuxProtocol::Yamux => Arc::new(YamuxSession::new(conn, &self.tasks)),
            MuxProtocol::H2Mux => Arc::new(H2MuxSession::new(conn, &self.tasks).await?),
        };
        if let Some(brutal) = self.opts.brutal
            && let Err(err) = brutal_exchange(session.as_ref(), brutal.receive_bps).await
        {
            session.close();
            return Err(io::Error::new(
                err.kind(),
                format!("brutal exchange: {err}"),
            ));
        }
        Ok(session)
    }
}

const BRUTAL_EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";

async fn brutal_exchange(session: &dyn MuxSession, receive_bps: u64) -> io::Result<u64> {
    let stream = session.open().await?;
    let destination = Address::Domain(BRUTAL_EXCHANGE_DOMAIN.into(), 0);
    let mut stream = client_stream(stream, Kind::Tcp, &destination)?;
    stream.write_all(&receive_bps.to_be_bytes()).await?;
    stream.flush().await?;
    let granted = if stream.read_u8().await? == 0 {
        let mut length = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = stream.read_u8().await?;
            length |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let mut message = Vec::new();
        (&mut stream).take(length).read_to_end(&mut message).await?;
        return Err(io::Error::other(format!(
            "remote error: {}",
            String::from_utf8_lossy(&message)
        )));
    } else {
        stream.read_u64().await?
    };
    let _ = stream.shutdown().await;
    Ok(granted)
}
