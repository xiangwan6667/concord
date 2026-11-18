use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{Address, BoxStream, CoreError, DialCx, NodeDialer, PacketSession};
use concord_config::ConfigError;
use concord_config::filter::{Matcher, compile_pattern};
use concord_config::group::{GroupDef, GroupKind, LbStrategy};
use concord_config::profile::Profile;

use super::{Entry, Outbounds};
use crate::check::{Check, CheckParams, Source, Supervisor};
use crate::deps::{Builtin, DEFAULT_TEST_TIMEOUT, GroupDeps};
use crate::error::GroupError;
use crate::group::{Group, GroupParts, Policy};
use crate::health::StatusRanges;
use crate::node::{Ghost, Item, Leaf, Node};
use crate::provider::ProxyProvider;
use crate::shared::Shared;
use crate::strategy::Strategy;

const DEFAULT_MAX_FAILED_TIMES: u32 = 5;

struct WeakNodes(Weak<Outbounds>);

#[async_trait]
impl NodeDialer for WeakNodes {
    async fn dial_via(&self, name: &str, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        match self.0.upgrade() {
            Some(outbounds) => outbounds.dial_via(name, cx, dst).await,
            None => Err(CoreError::UnknownNode(name.to_string()).into()),
        }
    }

    async fn associate_via(
        &self,
        name: &str,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        match self.0.upgrade() {
            Some(outbounds) => outbounds.associate_via(name, cx, hint).await,
            None => Err(CoreError::UnknownNode(name.to_string()).into()),
        }
    }
}

fn compile_parts(text: &str, sep: char) -> Result<Vec<Matcher>, ConfigError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(sep)
        .map(|part| compile_pattern(part, false))
        .collect()
}

fn policy_of(def: &GroupDef) -> Policy {
    match def.kind {
        GroupKind::Select => Policy::Select {
            default_selected: Arc::from(def.default_selected.as_str()),
        },
        GroupKind::UrlTest => Policy::UrlTest {
            tolerance: def.tolerance,
        },
        GroupKind::Fallback => Policy::Fallback,
        GroupKind::LoadBalance => {
            let in_user = def.hash_key == "in-user";
            Policy::LoadBalance(match def.strategy {
                LbStrategy::ConsistentHashing => Strategy::ConsistentHashing { in_user },
                LbStrategy::RoundRobin => Strategy::RoundRobin(Mutex::new(0)),
                LbStrategy::StickySessions => Strategy::StickySessions {
                    in_user,
                    cache: Mutex::new(Default::default()),
                },
            })
        }
    }
}

struct EmptyFallback {
    leaf: Arc<Leaf>,
    explicit: bool,
}

struct Builder<'a> {
    profile: &'a Profile,
    shared: &'a Arc<Shared>,
    table: HashMap<Arc<str>, Entry>,
    providers: &'a [Arc<ProxyProvider>],
    quarantined: Arc<HashSet<String>>,
    building: Vec<String>,
}

impl Builder<'_> {
    fn group(&mut self, name: &str) -> Result<Arc<Group>, GroupError> {
        if let Some(Entry::Group(group)) = self.table.get(name) {
            return Ok(group.clone());
        }
        if self.building.iter().any(|building| building == name) {
            return Err(GroupError::Cycle(self.building.clone()));
        }
        let profile = self.profile;
        let Some(def) = profile.groups.iter().find(|def| def.name == name) else {
            return Err(ConfigError::new(format!("proxy group {name} not found")).into());
        };
        self.building.push(name.to_string());
        let group = self.build_group(def)?;
        self.building.pop();
        self.table
            .insert(group.name().clone(), Entry::Group(group.clone()));
        Ok(group)
    }

    fn own_members(&mut self, def: &GroupDef) -> Result<Vec<Item>, GroupError> {
        let mut own: Vec<Item> = Vec::new();
        for name in &def.proxies {
            let node = match self.table.get(name.as_str()) {
                Some(Entry::Leaf(leaf)) => Node::Leaf(leaf.clone()),
                Some(Entry::Ghost(_)) => continue,
                Some(Entry::Group(group)) => Node::Group(group.clone()),
                None if self.profile.groups.iter().any(|group| &group.name == name) => {
                    Node::Group(self.group(name)?)
                }
                None => {
                    return Err(GroupError::NotFound {
                        group: def.name.clone(),
                        name: name.clone(),
                    });
                }
            };
            own.push(Item::Live(node));
        }
        Ok(own)
    }

    fn resolve_providers(&self, def: &GroupDef) -> Result<Vec<Arc<ProxyProvider>>, GroupError> {
        let mut uses = Vec::with_capacity(def.use_providers.len());
        for name in &def.use_providers {
            let provider = self
                .providers
                .iter()
                .find(|provider| provider.name().as_ref() == name.as_str());
            uses.push(provider.cloned().ok_or_else(|| GroupError::NotFound {
                group: def.name.clone(),
                name: name.clone(),
            })?);
        }
        Ok(uses)
    }

    fn refuse_provider_name(&self, def: &GroupDef) -> Result<(), GroupError> {
        if !def.proxies.is_empty()
            && self
                .providers
                .iter()
                .any(|provider| provider.name().as_ref() == def.name.as_str())
        {
            return Err(GroupError::DuplicateProvider {
                group: def.name.clone(),
            });
        }
        Ok(())
    }

    fn empty_fallback(&self, def: &GroupDef) -> Result<EmptyFallback, GroupError> {
        let fallback_leaf = match self.table.get(def.empty_fallback.as_str()) {
            Some(Entry::Leaf(leaf)) => Some(leaf.clone()),
            _ => None,
        };
        let explicit_fallback = def.explicit_empty_fallback && fallback_leaf.is_some();
        let empty_fallback = match fallback_leaf {
            Some(leaf) => leaf,
            None => match self.table.get("COMPATIBLE") {
                Some(Entry::Leaf(leaf)) => leaf.clone(),
                _ => return Err(ConfigError::new("COMPATIBLE is missing").into()),
            },
        };
        Ok(EmptyFallback {
            leaf: empty_fallback,
            explicit: explicit_fallback,
        })
    }

    fn build_group(&mut self, def: &GroupDef) -> Result<Arc<Group>, GroupError> {
        let own = self.own_members(def)?;
        let uses = self.resolve_providers(def)?;
        self.refuse_provider_name(def)?;

        let shared = self.shared.clone();
        let url = if let Some(explicit_url) = &def.explicit_url {
            explicit_url.clone()
        } else {
            uses.iter()
                .map(|provider| provider.health_check_url().to_string())
                .find(|url| !url.is_empty())
                .unwrap_or_else(|| shared.default_url())
        };
        let expected = StatusRanges::parse(&def.expected_status).unwrap_or_default();

        let empty_fallback = self.empty_fallback(def)?;
        let policy = policy_of(def);

        let own_check = if own.is_empty() {
            None
        } else {
            let nodes = own
                .iter()
                .filter_map(|item| match item {
                    Item::Live(node) => Some(node.clone()),
                    Item::Ghost(_) => None,
                })
                .collect();
            Some(Check::new(
                CheckParams {
                    id: format!("group:{}", def.name),
                    url: url.clone(),
                    timeout_ms: def.timeout,
                    interval_secs: def.interval,
                    lazy: def.lazy,
                    expected: expected.clone(),
                },
                Source::Static(nodes),
            ))
        };
        if let Some(explicit_url) = &def.explicit_url
            && !uses.is_empty()
        {
            let interval =
                if !own.is_empty() && def.kind != GroupKind::Select && def.interval_is_zero {
                    0
                } else {
                    def.interval
                };
            for provider in &uses {
                provider
                    .check()
                    .register_extra(explicit_url, &expected, &def.filter, interval);
            }
        }

        Ok(Group::new(GroupParts {
            name: Arc::from(def.name.as_str()),
            policy,
            url,
            expected_text: def.expected_status.clone(),
            expected,
            disable_udp: def.disable_udp,
            hidden: def.hidden,
            icon: def.icon.clone(),
            empty_fallback: empty_fallback.leaf,
            explicit_fallback: empty_fallback.explicit,
            refused: self.profile.refused_groups.contains(&def.name),
            quarantined: self.quarantined.clone(),
            own,
            uses,
            use_position: def.use_position.clone(),
            filter: compile_parts(&def.filter, '`')
                .map_err(|err| err.prefixed(&format!("{}: filter: ", def.name)))?,
            exclude_filter: compile_parts(&def.exclude_filter, '`')
                .map_err(|err| err.prefixed(&format!("{}: exclude-filter: ", def.name)))?,
            exclude_type: if def.exclude_type.is_empty() {
                Vec::new()
            } else {
                def.exclude_type.split('|').map(str::to_string).collect()
            },
            own_check,
            test_timeout: if def.timeout > 0 {
                Duration::from_millis(u64::from(def.timeout))
            } else {
                DEFAULT_TEST_TIMEOUT
            },
            max_failed: if def.max_failed_times > 0 {
                def.max_failed_times
            } else {
                DEFAULT_MAX_FAILED_TIMES
            },
            shared,
        }))
    }
}

impl Outbounds {
    /// Takes the proxy definitions out of `profile`, freeing each as its node is built.
    pub fn build(profile: &mut Profile, deps: GroupDeps) -> Result<Arc<Outbounds>, GroupError> {
        let shared = Shared::new(&deps);
        let factory = deps.factory.clone();
        let mut table: HashMap<Arc<str>, Entry> = HashMap::new();
        let mut node_order: Vec<Arc<str>> = Vec::new();
        for (name, which) in [
            ("DIRECT", Builtin::Direct),
            ("REJECT", Builtin::Reject),
            ("REJECT-DROP", Builtin::RejectDrop),
            ("COMPATIBLE", Builtin::Compatible),
            ("PASS", Builtin::Pass),
            ("PASS-RULE", Builtin::PassRule),
        ] {
            let name: Arc<str> = Arc::from(name);
            table.insert(
                name.clone(),
                Entry::Leaf(Leaf::new(factory.builtin(which), None)),
            );
            node_order.push(name);
        }
        for def in std::mem::take(&mut profile.proxies) {
            let name: Arc<str> = Arc::from(def.name.as_str());
            if table.contains_key(&name) {
                return Err(
                    ConfigError::new(format!("proxy {} is the duplicate name", def.name)).into(),
                );
            }
            match factory.build_def(&def) {
                Ok(outbound) => {
                    table.insert(name.clone(), Entry::Leaf(Leaf::new(outbound, None)));
                }
                Err(failure) => {
                    let message = format!("{}: {}", def.name, failure.message);
                    profile
                        .report
                        .warn("proxy_quarantined", format!("proxies.{name}"), message);
                    table.insert(
                        name.clone(),
                        Entry::Ghost(ghost(&def.name, def.kind.type_name(), &failure.message)),
                    );
                }
            }
            node_order.push(name);
        }
        let profile: &Profile = profile;
        for item in profile
            .quarantined
            .iter()
            .filter(|item| item.provider.is_none())
        {
            let name: Arc<str> = Arc::from(item.name.as_str());
            table.insert(
                name,
                Entry::Ghost(ghost(&item.name, &item.kind, &item.reason)),
            );
        }

        let mut providers = Vec::with_capacity(profile.proxy_providers.len());
        for def in &profile.proxy_providers {
            providers.push(ProxyProvider::new(def, shared.clone())?);
        }

        let mut builder = Builder {
            profile,
            shared: &shared,
            table,
            providers: &providers,
            quarantined: Arc::new(profile.quarantined_names.clone()),
            building: Vec::new(),
        };
        let mut groups = Vec::with_capacity(profile.groups.len());
        for def in &profile.groups {
            groups.push(builder.group(&def.name)?);
        }
        let table = builder.table;
        let mut checks: Vec<Arc<Check>> = Vec::new();
        for group in &groups {
            checks.extend(group.own_check().cloned());
        }
        checks.extend(providers.iter().map(|provider| provider.check().clone()));

        let outbounds = Arc::new_cyclic(|weak: &Weak<Outbounds>| {
            let nodes: Arc<dyn NodeDialer> = Arc::new(WeakNodes(weak.clone()));
            Outbounds {
                env: ArcSwap::from_pointee((deps.env)(nodes)),
                me: weak.clone(),
                shared,
                table,
                groups,
                builtin_global: profile.groups.iter().any(|def| def.builtin_global),
                node_order,
                providers,
                checks,
                supervisor: Mutex::new(Supervisor::default()),
                last_picks: Mutex::new(HashMap::new()),
                background: AtomicBool::new(false),
            }
        });
        *lock(&outbounds.last_picks) = outbounds.pick_snapshot();
        Ok(outbounds)
    }
}

fn ghost(name: &str, kind: &str, reason: &str) -> Arc<Ghost> {
    Arc::new(Ghost {
        name: Arc::from(name),
        kind: Arc::from(kind),
        reason: Arc::from(reason),
        provider: None,
    })
}
