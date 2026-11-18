use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{SystemTime, UNIX_EPOCH};

use concord_common::sync::lock;
use concord_common::{ConnRecord, CoreEvent as EngineEvent, EventSink, TrafficDelta};
use concord_engine::Engine as EngineCore;
use concord_proto::StreamPolicy;
use concord_proto::types::{ConnectionDelta, CoreEvent, DnsEntry, LogEntry, LogLevel, RouteStamp};
use futures_util::stream::Stream;

use crate::convert;
use crate::logging::LogGate;
use crate::stream::{Delivery, PolicyQueue, QueueStream, policy_of};

const LOG_CAPACITY: usize = 1024;
const DNS_CAPACITY: usize = 1024;
const EVENT_CAPACITY: usize = 1024;
const CONN_CAPACITY: usize = 8192;

type Hook = Box<dyn Fn(bool) + Send + Sync>;

/// The subscribers of one kind of event. The first subscriber and the last one
/// leaving each run `hook`, which is how production starts and stops.
pub struct Topic<S> {
    subs: Mutex<Vec<Weak<S>>>,
    count: AtomicUsize,
    any: Arc<AtomicUsize>,
    hook: Option<Hook>,
}

impl<S> Topic<S> {
    fn new(any: Arc<AtomicUsize>, hook: Option<Hook>) -> Arc<Self> {
        Arc::new(Topic {
            subs: Mutex::new(Vec::new()),
            count: AtomicUsize::new(0),
            any,
            hook,
        })
    }

    pub fn active(&self) -> bool {
        self.count.load(Ordering::Relaxed) > 0
    }

    pub fn subscribers(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn join(self: &Arc<Self>, sub: &Arc<S>) -> Membership<S> {
        {
            let mut subs = lock(&self.subs);
            subs.push(Arc::downgrade(sub));
            self.any.fetch_add(1, Ordering::SeqCst);
            if self.count.fetch_add(1, Ordering::SeqCst) == 0
                && let Some(hook) = &self.hook
            {
                hook(true);
            }
        }
        Membership {
            topic: self.clone(),
            sub: sub.clone(),
        }
    }

    fn leave(&self, sub: &Arc<S>) {
        let mut subs = lock(&self.subs);
        subs.retain(|held| held.upgrade().is_some_and(|held| !Arc::ptr_eq(&held, sub)));
        self.any.fetch_sub(1, Ordering::SeqCst);
        if self.count.fetch_sub(1, Ordering::SeqCst) == 1
            && let Some(hook) = &self.hook
        {
            hook(false);
        }
    }

    fn each(&self, mut visit: impl FnMut(&S)) {
        let live: Vec<Arc<S>> = lock(&self.subs).iter().filter_map(Weak::upgrade).collect();
        for sub in &live {
            visit(sub);
        }
    }
}

/// Holds a subscription in its topic until dropped.
pub struct Membership<S> {
    topic: Arc<Topic<S>>,
    sub: Arc<S>,
}

impl<S> Drop for Membership<S> {
    fn drop(&mut self) {
        self.topic.leave(&self.sub);
    }
}

type Filter<T> = Box<dyn Fn(&T) -> bool + Send + Sync>;

pub struct QueueSub<T> {
    queue: Arc<PolicyQueue<T>>,
    accept: Option<Filter<T>>,
}

impl<T> QueueSub<T> {
    fn push(&self, item: T) {
        if self.accept.as_ref().is_none_or(|accept| accept(&item)) {
            self.queue.push(item);
        }
    }
}

fn unix_millis(at: SystemTime) -> i64 {
    at.duration_since(UNIX_EPOCH).map_or(0, |elapsed| {
        i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
    })
}

#[derive(Default)]
struct ConnPending {
    opened: Vec<Arc<ConnRecord>>,
    closed: Vec<u64>,
    counters: HashMap<u64, (u64, u64)>,
    overflowed: bool,
    resync_sent: bool,
    waker: Option<Waker>,
}

/// The changes to the connection table since a `connection.watch` last looked.
/// Counters coalesce by id; opens and closes are queued up to a bound, past
/// which the subscriber is told to resync rather than lose one silently.
pub struct ConnSub {
    pending: Mutex<ConnPending>,
    counters: bool,
}

impl ConnSub {
    pub fn new(counters: bool) -> Arc<Self> {
        Arc::new(ConnSub {
            pending: Mutex::default(),
            counters,
        })
    }

    fn change(&self, apply: impl FnOnce(&mut ConnPending)) {
        let waker = {
            let mut pending = lock(&self.pending);
            if pending.overflowed {
                return;
            }
            apply(&mut pending);
            if pending.opened.len() + pending.closed.len() + pending.counters.len() > CONN_CAPACITY
            {
                pending.overflowed = true;
                pending.opened.clear();
                pending.closed.clear();
                pending.counters.clear();
            }
            pending.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn opened(&self, record: Arc<ConnRecord>) {
        self.change(|pending| pending.opened.push(record));
    }

    fn closed(&self, seq: u64) {
        self.change(|pending| pending.closed.push(seq));
    }

    fn counters(&self, deltas: &[TrafficDelta]) {
        if !self.counters {
            return;
        }
        self.change(|pending| {
            for delta in deltas {
                pending
                    .counters
                    .insert(delta.seq, (delta.upload, delta.download));
            }
        });
    }

    fn poll_delta(&self, cx: &mut Context<'_>) -> Poll<Option<Delivery<ConnectionDelta>>> {
        let taken = {
            let mut pending = lock(&self.pending);
            if pending.overflowed {
                if pending.resync_sent {
                    return Poll::Ready(None);
                }
                pending.resync_sent = true;
                return Poll::Ready(Some(Delivery::Resync));
            }
            if pending.opened.is_empty() && pending.closed.is_empty() && pending.counters.is_empty()
            {
                pending.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            (
                std::mem::take(&mut pending.opened),
                std::mem::take(&mut pending.closed),
                std::mem::take(&mut pending.counters),
            )
        };
        let (opened, mut closed, mut counters) = taken;
        closed.sort_unstable();
        closed.dedup();
        for seq in &closed {
            counters.remove(seq);
        }
        for record in &opened {
            counters.remove(&record.seq);
        }
        let opened = opened
            .iter()
            .map(|record| convert::connection_info(record))
            .collect::<Vec<_>>();
        let mut counters: Vec<_> = counters
            .into_iter()
            .map(
                |(id, (upload, download))| concord_proto::types::ConnectionCounter {
                    id,
                    upload,
                    download,
                },
            )
            .collect();
        counters.sort_unstable_by_key(|counter| counter.id);
        Poll::Ready(Some(Delivery::Event {
            data: ConnectionDelta {
                opened,
                closed,
                counters,
            },
            dropped: 0,
        }))
    }
}

pub struct ConnStream {
    sub: Arc<ConnSub>,
    _membership: Membership<ConnSub>,
}

impl Stream for ConnStream {
    type Item = Delivery<ConnectionDelta>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.sub.poll_delta(cx)
    }
}

/// Fans the engine's events out to the subscriptions that exist. An event no one
/// subscribed to is dropped before anything is encoded, and `enabled` is false
/// while there is no subscription at all, which is what lets the engine skip
/// building events.
pub struct EventBus {
    any: Arc<AtomicUsize>,
    gate: Arc<LogGate>,
    log: Arc<Topic<QueueSub<LogEntry>>>,
    dns: Arc<Topic<QueueSub<DnsEntry>>>,
    route: Arc<Topic<QueueSub<RouteStamp>>>,
    events: Arc<Topic<QueueSub<CoreEvent>>>,
    conn: Arc<Topic<ConnSub>>,
    engine: Arc<OnceLock<Weak<EngineCore>>>,
}

impl EventBus {
    pub fn new() -> Arc<Self> {
        let any = Arc::new(AtomicUsize::new(0));
        let gate = LogGate::new();
        let engine: Arc<OnceLock<Weak<EngineCore>>> = Arc::new(OnceLock::new());
        let log_gate = gate.clone();
        let route_engine = engine.clone();
        Arc::new(EventBus {
            log: Topic::new(
                any.clone(),
                Some(Box::new(move |on| log_gate.set_streaming(on))),
            ),
            dns: Topic::new(any.clone(), None),
            route: Topic::new(
                any.clone(),
                Some(Box::new(move |on| {
                    if let Some(engine) = route_engine.get().and_then(Weak::upgrade) {
                        engine.watch_route(on);
                    }
                })),
            ),
            events: Topic::new(any.clone(), None),
            conn: Topic::new(any.clone(), None),
            any,
            gate,
            engine,
        })
    }

    pub fn gate(&self) -> &Arc<LogGate> {
        &self.gate
    }

    pub(crate) fn attach(&self, engine: &Arc<EngineCore>) {
        let _ = self.engine.set(Arc::downgrade(engine));
    }

    pub fn subscribers(&self) -> usize {
        self.any.load(Ordering::SeqCst)
    }

    fn queue_stream<T: Clone + Send + Sync + 'static>(
        topic: &Arc<Topic<QueueSub<T>>>,
        policy: StreamPolicy,
        capacity: usize,
        accept: Option<Filter<T>>,
    ) -> QueueStream<T, Membership<QueueSub<T>>> {
        let queue = PolicyQueue::new(policy, capacity);
        let sub = Arc::new(QueueSub {
            queue: queue.clone(),
            accept,
        });
        let membership = topic.join(&sub);
        QueueStream::new(queue, membership)
    }

    pub fn watch_log(
        &self,
        min: LogLevel,
    ) -> QueueStream<LogEntry, Membership<QueueSub<LogEntry>>> {
        Self::queue_stream(
            &self.log,
            policy_of("log.watch"),
            LOG_CAPACITY,
            Some(Box::new(move |entry: &LogEntry| entry.level >= min)),
        )
    }

    pub fn watch_dns(&self) -> QueueStream<DnsEntry, Membership<QueueSub<DnsEntry>>> {
        Self::queue_stream(&self.dns, policy_of("dns.watch"), DNS_CAPACITY, None)
    }

    pub fn watch_route(&self) -> QueueStream<RouteStamp, Membership<QueueSub<RouteStamp>>> {
        Self::queue_stream(&self.route, policy_of("route.watch"), 1, None)
    }

    pub fn watch_events(
        &self,
        delays: bool,
        state: bool,
    ) -> QueueStream<CoreEvent, Membership<QueueSub<CoreEvent>>> {
        Self::queue_stream(
            &self.events,
            policy_of("events.watch"),
            EVENT_CAPACITY,
            Some(Box::new(move |event: &CoreEvent| match event {
                CoreEvent::Delay { .. } => delays,
                CoreEvent::StateChanged { .. } => state,
                _ => true,
            })),
        )
    }

    pub fn watch_connections(&self, counters: bool) -> ConnStream {
        let sub = ConnSub::new(counters);
        let membership = self.conn.join(&sub);
        ConnStream {
            sub,
            _membership: membership,
        }
    }

    pub fn publish_fatal(&self, message: String) {
        self.events.each(|sub| {
            sub.push(CoreEvent::Fatal {
                message: message.clone(),
            })
        });
    }

    pub fn topic_counts(&self) -> [usize; 5] {
        [
            self.log.subscribers(),
            self.dns.subscribers(),
            self.route.subscribers(),
            self.events.subscribers(),
            self.conn.subscribers(),
        ]
    }
}

impl EventSink for EventBus {
    fn enabled(&self) -> bool {
        self.any.load(Ordering::Relaxed) > 0
    }

    fn publish(&self, event: EngineEvent) {
        match event {
            EngineEvent::Log(record) => {
                if self.log.active() {
                    let entry = LogEntry {
                        level: convert::log_level(record.level),
                        time: unix_millis(SystemTime::now()),
                        text: record.payload,
                    };
                    self.log.each(|sub| sub.push(entry.clone()));
                }
            }
            EngineEvent::Dns(record) => {
                if self.dns.active() {
                    let entry = convert::dns_entry(&record);
                    self.dns.each(|sub| sub.push(entry.clone()));
                }
            }
            EngineEvent::Request(record) => {
                if self.conn.active() {
                    self.conn.each(|sub| sub.opened(record.clone()));
                }
            }
            EngineEvent::RequestTraffic(deltas) => {
                if self.conn.active() {
                    self.conn.each(|sub| sub.counters(&deltas));
                }
            }
            EngineEvent::RouteChanged(view) => {
                if self.route.active() {
                    let stamp = convert::route_stamp(view);
                    self.route.each(|sub| sub.push(stamp.clone()));
                }
            }
            EngineEvent::Delay(result) => self.publish_event(CoreEvent::Delay {
                name: result.name,
                url: result.url,
                value: result.value,
            }),
            EngineEvent::Resource(update) => {
                self.publish_event(convert::resource_event(update));
            }
            EngineEvent::DialerLoop(name) => self.publish_event(CoreEvent::DialerLoop {
                name: name.to_string(),
            }),
            EngineEvent::State(change) => self.publish_event(convert::state_event(change)),
        }
    }

    fn closed(&self, seq: u64) {
        if self.conn.active() {
            self.conn.each(|sub| sub.closed(seq));
        }
    }
}

impl EventBus {
    fn publish_event(&self, event: CoreEvent) {
        if self.events.active() {
            self.events.each(|sub| sub.push(event.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use concord_common::{
        ConnMeta, DnsMode, Host, InboundInfo, InboundKind, Network as CommonNetwork,
    };
    use futures_util::{FutureExt, StreamExt};

    use super::*;

    fn record() -> Arc<ConnRecord> {
        let meta = ConnMeta {
            network: CommonNetwork::Tcp,
            inbound: InboundInfo::new(InboundKind::Socks5),
            src: "127.0.0.1:1000".parse().unwrap(),
            dst_ip: None,
            dst_port: 443,
            host: Host::from("example.com"),
            sniff_host: Host::default(),
            dns_mode: Some(DnsMode::Normal),
            uid: None,
            process: String::new(),
            process_path: String::new(),
            remote_destination: String::new(),
            src_geoip: None,
            dst_geoip: None,
            src_asn: String::new(),
            dst_asn: String::new(),
            rematch_name: String::new(),
            special_rules: String::new(),
            special_proxy: String::new(),
        };
        Arc::new(ConnRecord::new(
            meta,
            vec![Arc::from("DIRECT")].into_boxed_slice(),
            Box::new([]),
            Arc::from("MATCH"),
            Arc::from(""),
            true,
            0,
        ))
    }

    fn delta(seq: u64, upload: u64) -> TrafficDelta {
        TrafficDelta {
            seq,
            id: String::new(),
            upload,
            download: 0,
        }
    }

    fn pull(stream: &mut ConnStream) -> Option<Delivery<ConnectionDelta>> {
        stream.next().now_or_never().flatten()
    }

    #[test]
    fn nothing_is_enabled_until_someone_subscribes() {
        let bus = EventBus::new();
        assert!(!bus.enabled());
        let stream = bus.watch_connections(true);
        assert!(bus.enabled());
        drop(stream);
        assert!(!bus.enabled());
        assert_eq!(bus.subscribers(), 0);
    }

    #[test]
    fn connection_changes_coalesce_until_the_consumer_pulls() {
        let bus = EventBus::new();
        let mut stream = bus.watch_connections(true);
        assert!(pull(&mut stream).is_none(), "nothing happened yet");
        let (first, second) = (record(), record());
        bus.publish(EngineEvent::Request(first.clone()));
        bus.publish(EngineEvent::Request(second.clone()));
        bus.publish(EngineEvent::RequestTraffic(vec![
            delta(first.seq, 10),
            delta(second.seq, 5),
        ]));
        bus.publish(EngineEvent::RequestTraffic(vec![delta(first.seq, 40)]));
        bus.closed(second.seq);

        let Some(Delivery::Event { data, .. }) = pull(&mut stream) else {
            panic!("a change was pending");
        };

        assert_eq!(
            data.opened.len(),
            2,
            "a connection that closed before the pull is still reported, so a client keeping a history sees it"
        );
        assert_eq!(data.opened[0].id, first.seq);
        assert_eq!(data.opened[1].id, second.seq);
        assert_eq!(data.closed, [second.seq]);
        assert_eq!(
            data.counters.len(),
            0,
            "an opened entry carries its counters and a closed one needs none"
        );
        assert!(pull(&mut stream).is_none());

        bus.publish(EngineEvent::RequestTraffic(vec![
            delta(first.seq, 90),
            delta(first.seq, 91),
        ]));
        let Some(Delivery::Event { data, .. }) = pull(&mut stream) else {
            panic!("counters were pending");
        };
        assert_eq!(data.counters.len(), 1, "only the changed id, once");
        assert_eq!(data.counters[0].upload, 91);
    }

    #[test]
    fn a_stream_without_counters_hears_of_opens_and_closes_only() {
        let bus = EventBus::new();
        let mut stream = bus.watch_connections(false);
        let first = record();
        bus.publish(EngineEvent::RequestTraffic(vec![delta(first.seq, 10)]));
        assert!(
            pull(&mut stream).is_none(),
            "a counter alone does not wake it"
        );
        bus.publish(EngineEvent::Request(first.clone()));
        bus.publish(EngineEvent::RequestTraffic(vec![delta(first.seq, 40)]));
        bus.closed(first.seq);
        let Some(Delivery::Event { data, .. }) = pull(&mut stream) else {
            panic!("an open and a close were pending");
        };
        assert_eq!(data.opened.len(), 1);
        assert_eq!(data.closed, [first.seq]);
        assert!(data.counters.is_empty());
    }

    #[test]
    fn a_closed_id_that_repeats_is_sent_once() {
        let bus = EventBus::new();
        let mut stream = bus.watch_connections(true);
        bus.closed(5);
        bus.closed(5);
        let Some(Delivery::Event { data, .. }) = pull(&mut stream) else {
            panic!("a close was pending");
        };
        assert_eq!(data.closed, [5]);
    }

    #[test]
    fn too_many_pending_changes_end_in_a_resync_and_nothing_is_dropped_silently() {
        let bus = EventBus::new();
        let mut stream = bus.watch_connections(true);
        for seq in 0..=CONN_CAPACITY as u64 {
            bus.closed(seq);
        }
        assert!(matches!(pull(&mut stream), Some(Delivery::Resync)));
        bus.closed(1);
        assert!(
            pull(&mut stream).is_none(),
            "the stream ends after the resync"
        );
    }

    #[test]
    fn events_nobody_subscribed_to_are_dropped_before_they_cost_anything() {
        let bus = EventBus::new();
        bus.publish(EngineEvent::Request(record()));
        let mut stream = bus.watch_connections(true);
        assert!(
            pull(&mut stream).is_none(),
            "a connection from before the subscription is the snapshot's job"
        );
    }

    #[test]
    fn an_events_subscriber_without_delays_gets_the_rest_and_a_fatal_reaches_everyone() {
        let bus = EventBus::new();
        let mut plain = bus.watch_events(false, false);
        let mut full = bus.watch_events(true, false);
        bus.publish(EngineEvent::Delay(concord_common::DelayResult {
            url: "u".into(),
            name: "n".into(),
            value: 3,
        }));
        bus.publish(EngineEvent::Resource(concord_common::ResourceUpdate {
            kind: concord_common::ResourceKind::ProxyProvider,
            name: Arc::from("p"),
            phase: concord_common::ResourcePhase::Updated,
        }));
        bus.publish_fatal("down".into());

        let kinds = |stream: &mut QueueStream<CoreEvent, Membership<QueueSub<CoreEvent>>>| {
            let mut out = Vec::new();
            while let Some(Some(Delivery::Event { data, .. })) = stream.next().now_or_never() {
                out.push(match data {
                    CoreEvent::Delay { .. } => "delay",
                    CoreEvent::ResourceUpdate { .. } => "loaded",
                    CoreEvent::Fatal { .. } => "fatal",
                    _ => "other",
                });
            }
            out
        };
        assert_eq!(kinds(&mut plain), ["loaded", "fatal"]);
        assert_eq!(kinds(&mut full), ["delay", "loaded", "fatal"]);
    }

    #[test]
    fn leaving_a_topic_a_holder_poisoned_still_turns_its_gate_off() {
        let bus = EventBus::new();
        let stream = bus.watch_log(LogLevel::Info);
        concord_test_support::poison(&bus.log.subs);
        drop(stream);
        assert!(!bus.gate.wants(concord_common::LogLevel::Error));
        assert!(!bus.enabled());
        assert_eq!(bus.subscribers(), 0);
        let again = bus.watch_log(LogLevel::Info);
        assert!(bus.gate.wants(concord_common::LogLevel::Error));
        drop(again);
    }

    #[test]
    fn the_log_gate_streams_while_a_log_subscription_lives() {
        let bus = EventBus::new();
        assert!(!bus.gate.wants(concord_common::LogLevel::Error));
        let first = bus.watch_log(LogLevel::Info);
        let second = bus.watch_log(LogLevel::Info);
        assert!(bus.gate.wants(concord_common::LogLevel::Error));
        drop(first);
        assert!(bus.gate.wants(concord_common::LogLevel::Error));
        drop(second);
        assert!(!bus.gate.wants(concord_common::LogLevel::Error));
    }
}
