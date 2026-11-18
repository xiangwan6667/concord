mod build;
mod select;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, DialEnv, FlowMeta, InboundInfo, InboundKind, Network,
    NodeDialer, Outbound, OutboundKind, PacketSession,
};
use futures_util::future::join_all;
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use crate::check::{Check, Supervisor};
use crate::error::GroupError;
use crate::first_write::FirstWrite;
use crate::group::{Group, Pick, Policy, Touch};
use crate::node::{Ghost, Item, Leaf, Node};
use crate::provider::{self, ProxyProvider};
use crate::shared::Shared;

pub use self::select::{SelectOutcome, Staged};

pub(crate) enum Entry {
    Leaf(Arc<Leaf>),
    Group(Arc<Group>),
    Ghost(Arc<Ghost>),
}

pub(crate) enum Found {
    Node(Node),
    Ghost(Arc<Ghost>),
}

pub enum Resolved {
    Route {
        leaf: Arc<dyn Outbound>,
        chain: Box<[Arc<str>]>,
        provider_chain: Box<[Arc<str>]>,
        exit_group: Option<Arc<str>>,
        udp: bool,
    },
    Rematch(Arc<dyn Outbound>),
    Pass,
    PassRule,
    Rejected(Arc<str>),
    Unknown,
}

pub fn load_balancer_exit(group: &str) -> String {
    format!("{group:?} LoadBalance ")
}

pub fn node_exit(info: &concord_common::OutboundInfo) -> String {
    format!(
        "{:?} {} {}",
        info.name.as_ref(),
        info.kind.wire_name(),
        info.addr
    )
}

pub struct Outbounds {
    pub(crate) shared: Arc<Shared>,
    env: ArcSwap<DialEnv>,
    me: Weak<Outbounds>,
    table: HashMap<Arc<str>, Entry>,
    groups: Vec<Arc<Group>>,
    builtin_global: bool,
    node_order: Vec<Arc<str>>,
    providers: Vec<Arc<ProxyProvider>>,
    checks: Vec<Arc<Check>>,
    supervisor: Mutex<Supervisor>,
    last_picks: Mutex<HashMap<Arc<str>, String>>,
    background: AtomicBool,
}

pub(crate) fn dummy_flow(dst: Address, network: Network) -> FlowMeta {
    FlowMeta {
        dscp: 0,
        network,
        inbound: InboundInfo::new(InboundKind::Inner),
        src: SocketAddr::from(([0, 0, 0, 0], 0)),
        dst,
    }
}

type Dialed = (Arc<dyn Outbound>, Box<[Arc<str>]>, bool);

impl Outbounds {
    pub fn env(&self) -> Arc<DialEnv> {
        self.env.load_full()
    }

    /// `config.update` changes these without a rebuild; a dial under way keeps
    /// what it started with.
    pub fn set_dial_flags(&self, tcp_concurrent: bool, ipv6: bool) {
        let mut env = (*self.env.load_full()).clone();
        env.tcp_concurrent = tcp_concurrent;
        env.ipv6 = ipv6;
        self.env.store(Arc::new(env));
    }

    pub(crate) fn node_order(&self) -> &[Arc<str>] {
        &self.node_order
    }

    pub(crate) fn table(&self) -> &HashMap<Arc<str>, Entry> {
        &self.table
    }

    pub(crate) fn builtin_global(&self) -> bool {
        self.builtin_global
    }

    pub fn groups(&self) -> &[Arc<Group>] {
        &self.groups
    }

    pub fn providers(&self) -> Vec<Arc<ProxyProvider>> {
        self.providers.clone()
    }

    pub fn provider(&self, name: &str) -> Option<Arc<ProxyProvider>> {
        self.providers
            .iter()
            .find(|provider| provider.name().as_ref() == name)
            .cloned()
    }

    pub(crate) fn checks(&self) -> &[Arc<Check>] {
        &self.checks
    }

    /// Provider nodes shadow the profile's own on a name clash.
    pub(crate) fn lookup(&self, name: &str) -> Option<Found> {
        for provider in &self.providers {
            let snapshot = provider.nodes();
            if let Some(leaf) = snapshot.get(name) {
                return Some(Found::Node(Node::Leaf(leaf.clone())));
            }
            if let Some(ghost) = snapshot.ghost(name) {
                return Some(Found::Ghost(ghost.clone()));
            }
        }
        match self.table.get(name)? {
            Entry::Leaf(leaf) => Some(Found::Node(Node::Leaf(leaf.clone()))),
            Entry::Group(group) => Some(Found::Node(Node::Group(group.clone()))),
            Entry::Ghost(ghost) => Some(Found::Ghost(ghost.clone())),
        }
    }

    pub fn node(&self, name: &str) -> Option<Node> {
        match self.lookup(name)? {
            Found::Node(node) => Some(node),
            Found::Ghost(_) => None,
        }
    }

    pub fn group(&self, name: &str) -> Option<Arc<Group>> {
        match self.lookup(name)? {
            Found::Node(Node::Group(group)) => Some(group),
            _ => None,
        }
    }

    pub fn resolve(
        &self,
        name: &str,
        flow: &FlowMeta,
        host: Option<&str>,
        touch: Touch,
    ) -> Resolved {
        match self.lookup(name) {
            Some(Found::Node(node)) => self.walk(node, flow, host, touch),
            Some(Found::Ghost(ghost)) => Resolved::Rejected(Arc::from(format!(
                "proxy {} is not supported by this core: {}",
                ghost.name, ghost.reason
            ))),
            None => Resolved::Unknown,
        }
    }

    pub(crate) fn walk(
        &self,
        start: Node,
        flow: &FlowMeta,
        host: Option<&str>,
        touch: Touch,
    ) -> Resolved {
        let mut path: Vec<Arc<str>> = Vec::new();
        let mut exit_group = None;
        let (mut udp, mut decided) = (true, false);
        let mut node = start;
        // Cycles are refused at load, as mihomo does, so a walk visits each entry at most once.
        for _ in 0..=self.table.len() {
            match node {
                Node::Leaf(leaf) => {
                    match leaf.info().kind {
                        OutboundKind::Pass => return Resolved::Pass,
                        OutboundKind::PassRule => return Resolved::PassRule,
                        OutboundKind::Rematch => return Resolved::Rematch(leaf.outbound().clone()),
                        _ => {}
                    }
                    if !decided {
                        udp = leaf.info().udp;
                    }
                    let mut chain = vec![leaf.name().clone()];
                    let mut provider_chain =
                        vec![leaf.provider().cloned().unwrap_or_else(|| Arc::from(""))];
                    for group in path.iter().rev() {
                        chain.push(group.clone());
                        provider_chain.push(Arc::from(""));
                    }
                    return Resolved::Route {
                        leaf: leaf.outbound().clone(),
                        chain: chain.into(),
                        provider_chain: provider_chain.into(),
                        exit_group,
                        udp,
                    };
                }
                Node::Group(group) => {
                    path.push(group.name().clone());
                    if !decided {
                        if group.blocks_udp() {
                            udp = false;
                            decided = true;
                        } else if group.is_load_balance() {
                            decided = true;
                        }
                    }
                    if group.is_load_balance() {
                        exit_group.get_or_insert_with(|| group.name().clone());
                    }
                    match group.pick(flow, host, touch) {
                        Pick::Node(next) => node = next,
                        Pick::Rejected { reason, .. } => return Resolved::Rejected(reason),
                    }
                }
            }
        }
        Resolved::Rejected(Arc::from("proxy groups are nested too deep"))
    }

    /// `"name" Type addr`, the identity a probe reports as the exit. A load
    /// balancer stands for its members, so it is the exit itself.
    pub fn exit_identity(&self, resolved: &Resolved) -> Option<String> {
        if let Resolved::Rematch(leaf) = resolved {
            return Some(node_exit(leaf.info()));
        }
        let Resolved::Route {
            leaf, exit_group, ..
        } = resolved
        else {
            return None;
        };
        Some(match exit_group {
            Some(group) => load_balancer_exit(group),
            None => node_exit(leaf.info()),
        })
    }

    /// `exitOfChains`: chains run from the hop that dialed out to the outermost
    /// group, so they are read from the end to meet the balancer a route stops at.
    pub fn exit_of_chains(&self, chains: &[String]) -> Option<String> {
        for name in chains.iter().skip(1).rev() {
            if let Some(group) = self.group(name)
                && matches!(group.policy(), Policy::LoadBalance(_))
            {
                return Some(load_balancer_exit(name));
            }
        }
        match self.node(chains.first()?)? {
            Node::Leaf(leaf) => Some(node_exit(leaf.info())),
            Node::Group(group) => Some(format!(
                "{:?} {} ",
                group.name().as_ref(),
                group.type_name()
            )),
        }
    }

    pub(crate) fn pick_snapshot(&self) -> HashMap<Arc<str>, String> {
        let flow = dummy_flow(Address::new("", 0), Network::Tcp);
        self.groups
            .iter()
            .filter(|group| group.is_selectable())
            .map(|group| (group.name().clone(), group.now(&flow)))
            .collect()
    }

    /// Counts a Moved when any pick differs from the last one seen.
    pub fn refresh_picks(&self) {
        let picks = self.pick_snapshot();
        let changed = {
            let mut last = lock(&self.last_picks);
            let changed = *last != picks;
            *last = picks;
            changed
        };
        if changed {
            self.shared.route.moved();
        }
    }

    pub fn reset_sessions(&self) {
        for entry in self.table.values() {
            if let Entry::Leaf(leaf) = entry {
                leaf.outbound().reset_sessions();
            }
        }
        for provider in &self.providers {
            for item in provider.nodes().items() {
                if let Item::Live(Node::Leaf(leaf)) = item {
                    leaf.outbound().reset_sessions();
                }
            }
        }
    }

    /// The mapping a provider node was built from. Nodes of the profile itself
    /// are the engine's to read from `config.yaml`.
    pub async fn definition(&self, name: &str) -> Option<Map<String, Value>> {
        let provider = match self.lookup(name)? {
            Found::Node(Node::Leaf(leaf)) => leaf.provider().cloned()?,
            Found::Ghost(ghost) => ghost.provider.clone()?,
            Found::Node(Node::Group(_)) => return None,
        };
        self.provider(&provider)?
            .definition(name)
            .await
            .ok()
            .flatten()
    }

    /// `answered` holds back the outcome of each provider's first load; see
    /// `provider::run`.
    pub fn start_background(
        self: &Arc<Self>,
        stop: CancellationToken,
        answered: CancellationToken,
    ) {
        if self.background.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        let refresher_stop = stop.child_token();
        let refresher_owner = weak.clone();
        tokio::spawn(async move {
            loop {
                let Some(outbounds) = refresher_owner.upgrade() else {
                    return;
                };
                let notified = outbounds.shared.clone();
                drop(outbounds);
                tokio::select! {
                    _ = refresher_stop.cancelled() => return,
                    _ = notified.refresh.notified() => {}
                }
                match refresher_owner.upgrade() {
                    Some(outbounds) => outbounds.refresh_picks(),
                    None => return,
                }
            }
        });
        for provider in &self.providers {
            tokio::spawn(provider::run(
                Arc::downgrade(provider),
                stop.child_token(),
                answered.clone(),
            ));
        }
        lock(&self.supervisor).reconcile(&self.checks, &weak, &stop);
    }

    pub fn reconcile_checks(self: &Arc<Self>, stop: &CancellationToken) {
        lock(&self.supervisor).reconcile(&self.checks, &Arc::downgrade(self), stop);
    }

    /// Counts a failed dial against the groups it went through, which test
    /// their members after enough failures. A fallback or load balancer only
    /// counts TCP, as mihomo's `ListenPacketContext` of those never reports.
    pub fn note_dial_failed(
        &self,
        chain: &[Arc<str>],
        leaf_kind: OutboundKind,
        network: Network,
        err: &io::Error,
    ) {
        for (position, name) in chain.iter().enumerate().skip(1) {
            let Some(Entry::Group(group)) = self.table.get(name) else {
                continue;
            };
            let counts = match group.policy() {
                Policy::UrlTest { .. } => true,
                Policy::Fallback | Policy::LoadBalance(_) => network == Network::Tcp,
                _ => false,
            };
            if !counts {
                continue;
            }
            let child = (position == 1).then_some(leaf_kind);
            if group.dial_failed(child, err)
                && let Some(outbounds) = self.me.upgrade()
            {
                let group = group.clone();
                tokio::spawn(async move {
                    join_all(group.checks().map(|check| check.check(&outbounds))).await;
                    group.finish_checking();
                });
            }
        }
    }

    /// Counts a dialed stream's first write for the groups it went through,
    /// once, when the stream still holds its protocol header back: a success
    /// clears their failure count, a failure counts like a failed dial.
    pub fn watch_first_write(
        &self,
        chain: &[Arc<str>],
        leaf_kind: OutboundKind,
        stream: BoxStream,
    ) -> BoxStream {
        let counted = chain.iter().skip(1).any(|name| {
            matches!(
                self.table.get(name),
                Some(Entry::Group(group)) if matches!(
                    group.policy(),
                    Policy::UrlTest { .. } | Policy::Fallback | Policy::LoadBalance(_)
                )
            )
        });
        if !counted || !stream.needs_handshake() {
            return stream;
        }
        let me = self.me.clone();
        let chain = chain.to_vec();
        Box::new(FirstWrite::new(
            stream,
            Box::new(move |result| {
                let Some(outbounds) = me.upgrade() else {
                    return;
                };
                match result {
                    Ok(()) => outbounds.note_dial_succeeded(&chain),
                    Err(err) => outbounds.note_dial_failed(&chain, leaf_kind, Network::Tcp, err),
                }
            }),
        ))
    }

    pub(crate) fn note_dial_succeeded(&self, chain: &[Arc<str>]) {
        for name in chain.iter().skip(1) {
            if let Some(Entry::Group(group)) = self.table.get(name) {
                group.dial_succeeded();
            }
        }
    }

    fn dial_target(
        &self,
        name: &str,
        cx: &DialCx<'_>,
        dst: &Address,
        network: Network,
    ) -> io::Result<Dialed> {
        let flow = dummy_flow(dst.clone(), network);
        match self.resolve(name, &flow, dst.domain(), Touch::Yes) {
            Resolved::Route {
                leaf, chain, udp, ..
            } => {
                let leaf_name = leaf.info().name.clone();
                if cx.enter(&leaf_name).is_err() {
                    self.shared.report_loop(&leaf_name);
                    return Err(CoreError::DialerLoop(leaf_name.to_string()).into());
                }
                Ok((leaf, chain, udp))
            }
            Resolved::Rematch(leaf) => {
                let chain = vec![leaf.info().name.clone()].into();
                Ok((leaf, chain, true))
            }
            Resolved::Pass | Resolved::PassRule => {
                Err(io::Error::other(GroupError::CannotDial(name.to_owned())))
            }
            Resolved::Rejected(_) => Err(CoreError::QuarantinedNode(name.to_string()).into()),
            Resolved::Unknown => Err(CoreError::UnknownNode(name.to_string()).into()),
        }
    }

    fn report_if_loop(&self, err: &io::Error) {
        if let Some(CoreError::DialerLoop(name)) = CoreError::of(err) {
            self.shared.report_loop(&Arc::from(name.as_str()));
        }
    }
}

#[async_trait]
impl NodeDialer for Outbounds {
    async fn dial_via(&self, name: &str, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let (leaf, chain, _) = self.dial_target(name, cx, dst, Network::Tcp)?;
        let kind = leaf.info().kind;
        match leaf.connect(cx, dst).await {
            Ok(stream) => Ok(self.watch_first_write(&chain, kind, stream)),
            Err(err) => {
                self.report_if_loop(&err);
                self.note_dial_failed(&chain, kind, Network::Tcp, &err);
                Err(err)
            }
        }
    }

    async fn associate_via(
        &self,
        name: &str,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let (leaf, chain, udp) = self.dial_target(name, cx, hint, Network::Udp)?;
        if !udp {
            return Err(CoreError::UdpUnsupported(name.to_string()).into());
        }
        let result = leaf.associate(cx, hint).await;
        if let Err(err) = &result {
            self.report_if_loop(err);
            self.note_dial_failed(&chain, leaf.info().kind, Network::Udp, err);
        }
        result
    }
}
