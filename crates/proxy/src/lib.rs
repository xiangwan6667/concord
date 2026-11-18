#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod addr_codec;
mod anytls;
mod build;
pub mod builtin;
mod capabilities;
mod ctx;
mod dgram;
mod direct;
mod dns;
mod gost_relay;
mod http;
mod hysteria;
mod hysteria2;
mod lazy;
mod link;
mod masque;
mod mieru;
mod miu;
mod node;
mod quic;
mod reject;
mod rematch;
mod session_slot;
mod shadowquic;
mod smux;
mod snell;
mod socks5;
mod ss;
mod ssh;
mod ssr;
mod stack;
mod tlsmap;
mod trojan;
mod tuic;
mod udprelay;
mod uot;
mod util;
mod vless;
mod vmess;
mod wireguard;

#[cfg(test)]
mod testing;

pub use build::build_outbound;
pub use capabilities::capabilities;
pub use ctx::{BuildCtx, BuildError, Clock};
