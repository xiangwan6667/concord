use std::io::{self, IoSlice};
use std::task::{Context, Poll, ready};

use crate::options::TunOptions;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "macos")]
mod apple;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
mod other;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod queued;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use self::windows::{set_windows_dns, wintun_path};

pub const MAX_BATCH: usize = 64;

pub trait Device: Send + Sync + 'static {
    /// Packets one batch call may move, at most `MAX_BATCH`.
    const BATCH: usize = 1;

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>>;

    fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>>;

    /// Where a received packet starts in its slot; the lengths reported exclude it.
    fn rx_offset(&self) -> usize {
        0
    }

    /// Sent TCP and UDP packets carry only the pseudo-header checksum, and received ones
    /// may carry a partial one.
    fn checksum_offload(&self) -> bool {
        false
    }

    /// One device per queue, each run by its own stack.
    fn into_queues(self) -> Vec<Self>
    where
        Self: Sized,
    {
        vec![self]
    }

    fn prepare(self) -> io::Result<Self>
    where
        Self: Sized,
    {
        Ok(self)
    }

    fn socket_owner(&self) -> Option<std::sync::Arc<dyn concord_netstack::SocketOwner>> {
        None
    }

    /// The queue's own poller, for sockets whose readiness the driver takes over.
    fn socket_watcher(
        &self,
    ) -> Option<std::sync::Arc<dyn concord_common::SocketWatcher + Send + Sync>> {
        None
    }

    fn poll_io(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn set_busy(&self, _busy: bool) -> io::Result<bool> {
        Ok(false)
    }

    fn poll_park(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    /// The most TCP payload one frame may carry for `poll_send_segmented`, or 0.
    fn segment_limit(&self) -> usize {
        0
    }

    /// Sends a TCP frame the device cuts into segments of `segment` payload bytes.
    fn poll_send_segmented(
        &self,
        cx: &mut Context<'_>,
        packet: &[u8],
        _segment: u16,
    ) -> Poll<io::Result<usize>> {
        self.poll_send(cx, packet)
    }

    /// Like `poll_send_segmented` for a packet in `parts`, without waiting.
    fn try_send_parts(&self, _parts: &[IoSlice<'_>], _segment: u16) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Reads packets into consecutive `stride`-sized slots of `buf`; a length of 0 marks a
    /// packet that did not fit.
    fn poll_recv_batch(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        stride: usize,
        lens: &mut [usize],
    ) -> Poll<io::Result<usize>> {
        recv_one(self, cx, buf, stride, lens)
    }

    /// How many packets the driver hands `poll_send_batch` at once, at most `MAX_BATCH`.
    fn send_batch(&self) -> usize {
        Self::BATCH
    }

    /// How many leading `packets` the call consumed, sent or counted in `failed`.
    fn poll_send_batch(
        &self,
        cx: &mut Context<'_>,
        packets: &[&[u8]],
        failed: &mut usize,
    ) -> Poll<usize> {
        send_one(self, cx, packets, failed)
    }
}

fn recv_one<D: Device + ?Sized>(
    dev: &D,
    cx: &mut Context<'_>,
    buf: &mut [u8],
    stride: usize,
    lens: &mut [usize],
) -> Poll<io::Result<usize>> {
    let (Some(slot), Some(len)) = (buf.get_mut(..stride), lens.first_mut()) else {
        return Poll::Ready(Ok(0));
    };
    *len = ready!(dev.poll_recv(cx, slot))?;
    Poll::Ready(Ok(1))
}

fn send_one<D: Device + ?Sized>(
    dev: &D,
    cx: &mut Context<'_>,
    packets: &[&[u8]],
    failed: &mut usize,
) -> Poll<usize> {
    let Some(packet) = packets.first() else {
        return Poll::Ready(0);
    };
    if ready!(dev.poll_send(cx, packet)).is_err() {
        *failed += 1;
    }
    Poll::Ready(1)
}

enum DeviceIo {
    Tokio(tun_rs::AsyncDevice),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Queued {
        device: std::sync::Arc<tun_rs::SyncDevice>,
        reactor: std::sync::Arc<crate::reactor::Reactor>,
        ready: std::sync::Arc<concord_netstack::SocketReady>,
        _registration: Box<dyn Send + Sync>,
    },
}

impl DeviceIo {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self {
            Self::Tokio(device) => device.poll_recv(cx, buf),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Queued { device, ready, .. } => loop {
                ready!(ready.poll_read_ready(cx))?;
                match ready.try_read(|| device.recv(buf)) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    result => return Poll::Ready(result),
                }
            },
        }
    }

    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            Self::Tokio(device) => device.poll_send(cx, buf),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Queued { device, ready, .. } => loop {
                ready!(ready.poll_write_ready(cx))?;
                match ready.try_write(|| device.send(buf)) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    result => return Poll::Ready(result),
                }
            },
        }
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for DeviceIo {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        match self {
            Self::Tokio(device) => device.as_raw_fd(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Queued { device, .. } => device.as_raw_fd(),
        }
    }
}

pub struct TunDevice {
    inner: DeviceIo,
    name: String,
    index: Option<u32>,
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "offload is Linux-only")
    )]
    vnet: bool,
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "offload is Linux-only")
    )]
    segment_limit: usize,
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "multi-queue is Linux-only")
    )]
    queues: usize,
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "offload is Linux-only")
    )]
    udp_merge: std::sync::atomic::AtomicBool,
}

impl TunDevice {
    /// Whether [`create`](Self::create) turns on offload where the kernel supports it.
    pub const OFFLOADS: bool = cfg!(target_os = "linux");

    /// Creates the interface with the first address of each family; further addresses are
    /// not configured.
    #[cfg(not(target_os = "android"))]
    pub fn create(options: &TunOptions) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        match Self::build(options, true) {
            Ok(device) => return Ok(device),
            Err(err) => {
                tracing::warn!("tun offload unavailable, reading packets one by one: {err}")
            }
        }
        Self::build(options, false)
    }

    #[cfg(not(target_os = "android"))]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(unused_variables, reason = "offload is Linux-only")
    )]
    fn build(options: &TunOptions, offload: bool) -> io::Result<Self> {
        let mut builder = tun_rs::DeviceBuilder::new().mtu(options.effective_mtu() as u16);
        #[cfg(target_os = "linux")]
        let queues = tokio::runtime::Handle::try_current().map_or_else(
            |_| std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
            |runtime| runtime.metrics().num_workers(),
        );
        #[cfg(target_os = "linux")]
        {
            builder = builder.offload(offload).multi_queue(queues > 1);
        }
        if let Some(name) = options.device.as_deref().filter(|name| !name.is_empty()) {
            builder = builder.name(name);
        }
        #[cfg(windows)]
        {
            builder = builder.wintun_file(wintun_path(options)?);
            if options.auto_route {
                builder = builder.metric(0);
            }
        }
        if let Some(first) = options.inet4_address.first()
            && let std::net::IpAddr::V4(addr) = first.addr()
        {
            builder = builder.ipv4(addr, first.len(), None);
        }
        if let Some(first) = options.inet6_address.first()
            && let std::net::IpAddr::V6(addr) = first.addr()
        {
            builder = builder.ipv6(addr, first.len());
        }
        let device = builder.build_async()?;
        #[cfg(windows)]
        set_windows_dns(&device, options)?;
        #[cfg_attr(
            not(target_os = "linux"),
            allow(unused_mut, reason = "offload is Linux-only")
        )]
        let mut tun = Self::wrap(device);
        #[cfg(target_os = "linux")]
        if offload {
            use std::os::fd::AsRawFd;

            crate::vnet::restrict_to_tcp(tun.inner.as_raw_fd())?;
            tun.vnet = true;
            if tun.inner.tcp_gso() {
                tun.segment_limit = crate::vnet::SEGMENT_LIMIT;
            }
        }
        #[cfg(target_os = "linux")]
        {
            tun.queues = queues;
        }
        Ok(tun)
    }

    #[cfg(target_os = "android")]
    pub fn create(_options: &TunOptions) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the VpnService creates the interface; adopt its descriptor",
        ))
    }

    /// Adopts the descriptor of a `VpnService` interface. The descriptor is closed on every
    /// failure path, including the ones before tun-rs takes it over.
    #[cfg(unix)]
    pub fn adopt(fd: std::os::fd::OwnedFd) -> io::Result<Self> {
        use std::os::fd::IntoRawFd;

        #[allow(unsafe_code, reason = "tun-rs takes ownership of a raw descriptor")]
        // SAFETY: `fd` is an open descriptor owned here, and tun-rs closes it if adoption fails.
        let inner = unsafe { tun_rs::AsyncDevice::from_fd(fd.into_raw_fd()) }?;
        Ok(Self::wrap(inner))
    }

    fn wrap(inner: tun_rs::AsyncDevice) -> Self {
        #[cfg(not(target_os = "android"))]
        let (name, index) = (inner.name().unwrap_or_default(), inner.if_index().ok());
        #[cfg(target_os = "android")]
        let (name, index) = (String::new(), None);
        TunDevice {
            inner: DeviceIo::Tokio(inner),
            name,
            index,
            vnet: false,
            segment_limit: 0,
            queues: 1,
            udp_merge: std::sync::atomic::AtomicBool::new(true),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn index(&self) -> Option<u32> {
        self.index
    }
}
