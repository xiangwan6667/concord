use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;

use tokio_util::sync::CancellationToken;

use crate::addr::{Host, Network};
use crate::meta::{DnsMode, InboundInfo};

#[derive(Clone, Debug)]
pub struct ConnMeta {
    pub network: Network,
    pub inbound: InboundInfo,
    pub src: SocketAddr,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: u16,
    pub host: Host,
    pub sniff_host: Host,
    pub dns_mode: Option<DnsMode>,
    pub uid: Option<u32>,
    pub process: String,
    pub process_path: String,
    pub remote_destination: String,
    pub src_geoip: Option<Vec<String>>,
    pub dst_geoip: Option<Vec<String>>,
    pub src_asn: String,
    pub dst_asn: String,
    pub rematch_name: String,
    pub special_rules: String,
    pub special_proxy: String,
}

static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub struct ConnRecord {
    pub id: String,
    /// Counts up from 1 in this process, which the typed API uses as the connection id.
    pub seq: u64,
    pub start: SystemTime,
    pub meta: ConnMeta,
    /// Exit first, as on the wire.
    pub chains: Box<[Arc<str>]>,
    pub provider_chains: Box<[Arc<str>]>,
    pub rule: Arc<str>,
    pub rule_payload: Arc<str>,
    /// Decided by the exit's kind, not its name.
    pub direct: bool,
    pub upload: AtomicU64,
    pub download: AtomicU64,
    pub cancel: CancellationToken,
    /// Decided after the dial: a held connection is marked as it is listed.
    pub mitm: AtomicBool,
    pub mitm_refused: AtomicBool,
    closed: AtomicBool,
}

impl ConnRecord {
    #[allow(clippy::too_many_arguments, reason = "one literal at each call site")]
    pub fn new(
        meta: ConnMeta,
        chains: Box<[Arc<str>]>,
        provider_chains: Box<[Arc<str>]>,
        rule: Arc<str>,
        rule_payload: Arc<str>,
        direct: bool,
        upload: u64,
    ) -> Self {
        ConnRecord {
            id: uuid::Uuid::new_v4().to_string(),
            seq: NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
            start: SystemTime::now(),
            meta,
            chains,
            provider_chains,
            rule,
            rule_payload,
            direct,
            upload: AtomicU64::new(upload),
            download: AtomicU64::new(0),
            cancel: CancellationToken::new(),
            mitm: AtomicBool::new(false),
            mitm_refused: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.cancel.cancel();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}
