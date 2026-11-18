//! Small types and traits shared across layers. `addr` and `meta` have no async
//! dependency, so `concord-config` and `concord-rules` can use them without tokio.

pub mod addr;
pub mod backoff;
pub mod clock;
pub mod meta;
pub mod options;
pub mod sync;

#[cfg(feature = "io")]
pub mod conn;
#[cfg(feature = "io")]
pub mod dns_relay;
#[cfg(feature = "io")]
pub mod error;
#[cfg(feature = "io")]
pub mod event;
#[cfg(feature = "io")]
pub mod flow;
#[cfg(feature = "io")]
pub mod intercept;
#[cfg(feature = "io")]
pub mod layered;
#[cfg(feature = "io")]
pub mod outbound;
#[cfg(feature = "io")]
mod owned_tcp;
#[cfg(feature = "io")]
pub mod packet;
#[cfg(feature = "io")]
pub mod stream;
#[cfg(feature = "io")]
pub mod stream_buffer;
#[cfg(feature = "io")]
pub mod task;
#[cfg(feature = "io")]
pub mod timeout;

/// The core's own name: the process of the connections it opens itself and the implementation it
/// reports to hosts.
pub const CORE_NAME: &str = "concord";

/// What end users see this core called: the MITM CA's subject and the Android TUN device. The
/// embedding app sets `CONCORD_PRODUCT_NAME` when it builds Concord.
pub const PRODUCT_NAME: &str = match option_env!("CONCORD_PRODUCT_NAME") {
    Some(name) => name,
    None => "Concord",
};

pub use addr::{Address, Host, IpVersion, Network, ip4p_target};
pub use clock::ClockOffset;
pub use meta::{
    DnsMode, FlowKey, FlowMeta, InboundInfo, InboundKind, ProcessInfo, RouteState, UdpFlow,
};
pub use options::{CoreOptions, FindProcessMode, LogLevel, TunnelMode};

#[cfg(feature = "io")]
pub use conn::{ConnMeta, ConnRecord};
#[cfg(feature = "io")]
pub use error::{CoreError, io_error, no_retry};
#[cfg(feature = "io")]
pub use event::{
    Change, CoreEvent, DelayResult, DnsRecord, EventSink, Fetch, GeneralChange, Initiator,
    LogRecord, NullSink, Origin, Refresh, ResourceKind, ResourcePhase, ResourceUpdate, RouteStamp,
    RouteView, SUPERSEDED, StateChange, TrafficDelta,
};
#[cfg(feature = "io")]
pub use flow::{
    FlowHandler, IcmpAnswer, Replies, ReplyOut, ReplySource, SocketWatch, SocketWatcher, UdpReply,
};
#[cfg(feature = "io")]
pub use outbound::{
    DialCx, DialEnv, HostResolver, LookupIps, NodeDialer, Outbound, OutboundInfo, OutboundKind,
    SockOpts, SocketFactory,
};
#[cfg(feature = "io")]
pub use owned_tcp::OwnedTcp;
#[cfg(feature = "io")]
pub use packet::{
    Datagram, PacketBuf, PacketSession, RecvBatch, UdpPayload, recv_packet, send_packet,
};
#[cfg(feature = "io")]
pub use stream::{
    Attached, BoxRead, BoxStream, BoxWrite, DirectIo, PeekedStream, RawSocket, Stream,
    split_with_lock,
};
#[cfg(feature = "io")]
pub use task::Tasks;
