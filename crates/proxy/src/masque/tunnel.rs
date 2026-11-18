use std::io;
use std::sync::Arc;

use concord_common::{BoxRead, BoxStream, BoxWrite, DialCx, Tasks};
use gotatun::packet::PacketBufPool;
use gotatun::tun::{IpRecv, IpSend};
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, ReusableBoxFuture};

use super::body::{Body, Sent};
use super::config::Config;
use super::h3::{Client, Driver};
use super::{capsule, datagram};
use crate::stack::{Stack, StackConfig, StackRecv, StackSend};
use crate::wireguard::dns::RemoteDns;

pub(super) struct Tunnel {
    pub(super) stack: Arc<Stack>,
    pub(super) dns: RemoteDns,
    stop: CancellationToken,
    _driver: JoinHandle<()>,
    _send: JoinHandle<()>,
    _recv: JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Tunnel {
    pub(super) fn usable(&self) -> bool {
        !self.stop.is_cancelled()
    }
    pub(super) fn close(&self) {
        self.stop.cancel();
    }

    pub(super) async fn connect(config: &Config, cx: &DialCx<'_>) -> io::Result<Arc<Self>> {
        let (body, h3): (BoxStream, _) = if config.network == "h2" {
            (super::h2::connect(config, cx).await?, None)
        } else {
            let client = Client::connect(config, cx).await?;
            let stream = client.request(config, None).await?;
            let id = stream.id().into_inner();
            (
                Box::new(Body::new(stream, client.clone())),
                Some((client, id)),
            )
        };
        let mtu = config.mtu;
        let tasks = &config.link.tasks;
        let wired = Stack::start(
            &StackConfig {
                addrs: config.addrs.clone(),
                mtu,
            },
            tasks,
        );
        let stack = wired.stack;
        let (read, mut write) = body.into_split();
        if h3.is_some() {
            capsule::send(&mut write, 3, &capsule::routes()).await?;
        }
        let stop = tasks.child_token();
        let (send, recv) = if let Some((client, id)) = h3 {
            h3_operations(wired.send, wired.recv, read, write, client, id)
        } else {
            h2_operations(wired.send, wired.recv, read, write, mtu)
        };
        let (send, recv) = (spawn_io(send, &stop, tasks), spawn_io(recv, &stop, tasks));
        Ok(Arc::new(Self {
            stack,
            dns: RemoteDns::new(
                config.dns.clone(),
                config.addrs.iter().any(|ip| ip.is_ipv6()),
            ),
            stop,
            _driver: wired.driver,
            _send: send,
            _recv: recv,
        }))
    }
}

enum Operation {
    SendH3 {
        outgoing: StackRecv,
        write: BoxWrite,
        client: Arc<Client>,
        id: u64,
    },
    RecvH3 {
        incoming: StackSend,
        read: BoxRead,
        client: Arc<Client>,
        id: u64,
    },
    SendH2 {
        outgoing: StackRecv,
        write: BoxWrite,
    },
    RecvH2 {
        incoming: StackSend,
        read: BoxRead,
        mtu: usize,
    },
}

// A single concrete future shares Tokio's task machinery across MASQUE background work.
enum Task {
    Io {
        operation: Operation,
        stop: CancellationToken,
    },
    Connection {
        driver: Box<Driver>,
        conn: quinn::Connection,
    },
    Finish {
        sending: ReusableBoxFuture<'static, Sent>,
        client: Arc<Client>,
    },
}

async fn drive(task: Task) {
    match task {
        Task::Io { operation, stop } => match operation {
            Operation::SendH3 {
                outgoing,
                write,
                client,
                id,
            } => {
                tokio::select! {
                    () = stop.cancelled() => {}
                    _ = send_h3(outgoing, &client, id) => { stop.cancel(); }
                }
                drop(write);
            }
            Operation::RecvH3 {
                incoming,
                mut read,
                client,
                id,
            } => {
                tokio::select! {
                    () = stop.cancelled() => {}
                    _ = recv_h3(incoming, &client, id) => { stop.cancel(); }
                    _ = drain(&mut read) => { stop.cancel(); }
                }
            }
            Operation::SendH2 {
                outgoing,
                mut write,
            } => {
                tokio::select! {
                    () = stop.cancelled() => {}
                    _ = send_h2(outgoing, &mut write) => { stop.cancel(); }
                }
            }
            Operation::RecvH2 {
                incoming,
                mut read,
                mtu,
            } => {
                tokio::select! {
                    () = stop.cancelled() => {}
                    _ = recv_h2(incoming, &mut read, mtu) => { stop.cancel(); }
                }
            }
        },
        Task::Connection { mut driver, conn } => {
            driver.wait_idle().await;
            conn.close(quinn::VarInt::from_u32(0), b"HTTP/3 driver ended");
        }
        Task::Finish { sending, client } => {
            let (mut stream, result) = sending.await;
            if result.is_ok() {
                let _ = stream.finish().await;
            }
            drop(client);
        }
    }
}

fn spawn_io(operation: Operation, stop: &CancellationToken, tasks: &Tasks) -> JoinHandle<()> {
    tasks.spawn(drive(Task::Io {
        operation,
        stop: stop.clone(),
    }))
}

pub(super) fn spawn_driver(
    driver: Driver,
    conn: quinn::Connection,
    tasks: &Tasks,
) -> JoinHandle<()> {
    tasks.spawn(drive(Task::Connection {
        driver: Box::new(driver),
        conn,
    }))
}

pub(super) fn finish_write(sending: ReusableBoxFuture<'static, Sent>, client: Arc<Client>) {
    let tasks = client.tasks.clone();
    tasks.spawn_detached(drive(Task::Finish { sending, client }));
}

fn h3_operations(
    incoming: StackSend,
    outgoing: StackRecv,
    read: BoxRead,
    write: BoxWrite,
    client: Arc<Client>,
    id: u64,
) -> (Operation, Operation) {
    let send = Operation::SendH3 {
        outgoing,
        write,
        client: client.clone(),
        id,
    };
    let recv = Operation::RecvH3 {
        incoming,
        read,
        client,
        id,
    };
    (send, recv)
}

fn h2_operations(
    incoming: StackSend,
    outgoing: StackRecv,
    read: BoxRead,
    write: BoxWrite,
    mtu: usize,
) -> (Operation, Operation) {
    let send = Operation::SendH2 { outgoing, write };
    let recv = Operation::RecvH2 {
        incoming,
        read,
        mtu,
    };
    (send, recv)
}

async fn drain(read: &mut (impl tokio::io::AsyncRead + Unpin)) -> io::Result<()> {
    loop {
        let _kind = capsule::varint(read).await?;
        let len = capsule::varint(read).await?;
        capsule::skip(read, len).await?;
    }
}

async fn send_h3(mut outgoing: StackRecv, client: &Client, id: u64) -> io::Result<()> {
    let mut pool: PacketBufPool = PacketBufPool::new(0);
    loop {
        for packet in outgoing.recv(&mut pool).await? {
            let mut packet = packet.into_bytes();
            if !capsule::decrement_hop(&mut packet) {
                continue;
            }
            let Some(limit) = client.quic.conn.max_datagram_size() else {
                return Err(io::Error::other("MASQUE peer disabled QUIC datagrams"));
            };
            if packet.len() + datagram::header_len(id)? > limit {
                continue;
            }
            datagram::encode(id, packet.buf_mut())?;
            let bytes = packet.buf_mut().split().freeze();
            match client.quic.conn.send_datagram(bytes) {
                Ok(()) | Err(quinn::SendDatagramError::TooLarge) => {}
                Err(err) => return Err(io::Error::other(err)),
            }
        }
    }
}

async fn recv_h3(mut incoming: StackSend, client: &Client, id: u64) -> io::Result<()> {
    let pool: PacketBufPool = PacketBufPool::new(0);
    loop {
        let packet = client
            .quic
            .conn
            .read_datagram()
            .await
            .map_err(io::Error::other)?;
        let Ok(Some(payload)) = datagram::decode(id, &packet) else {
            continue;
        };
        let mut packet = pool.get();
        packet.buf_mut().resize(payload.len(), 0);
        packet.copy_from_slice(payload);
        if let Ok(packet) = packet.try_into_ip() {
            incoming.send(packet).await?;
        }
    }
}

async fn send_h2(
    mut outgoing: StackRecv,
    write: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> io::Result<()> {
    let mut pool: PacketBufPool = PacketBufPool::new(0);
    loop {
        for packet in outgoing.recv(&mut pool).await? {
            let mut packet = packet.into_bytes();
            if capsule::decrement_hop(&mut packet) {
                capsule::encode(0, packet.buf_mut())?;
                tokio::io::AsyncWriteExt::write_all(write, &packet).await?;
                tokio::io::AsyncWriteExt::flush(write).await?;
            }
        }
    }
}

async fn recv_h2(
    mut incoming: StackSend,
    read: &mut (impl tokio::io::AsyncRead + Unpin),
    mtu: usize,
) -> io::Result<()> {
    let pool: PacketBufPool = PacketBufPool::new(0);
    loop {
        let kind = capsule::varint(read).await?;
        let len = capsule::varint(read).await?;
        if kind != 0 || len > mtu as u64 {
            capsule::skip(read, len).await?;
            continue;
        }
        let mut packet = pool.get();
        let len = usize::try_from(len).map_err(io::Error::other)?;
        packet.buf_mut().resize(len, 0);
        read.read_exact(&mut packet).await?;
        if let Ok(packet) = packet.try_into_ip() {
            incoming.send(packet).await?;
        }
    }
}
