use std::sync::Arc;
use std::time::Duration;

use concord_common::{Address, Network};

use super::{Found, Outbounds, dummy_flow};
use crate::group::{Emptiness, Group, Policy};
use crate::node::Node;
use crate::selection::Probing;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SelectOutcome {
    pub message: String,
    pub changed: bool,
}

pub struct Staged {
    target: Arc<Group>,
    proxy: String,
    before: String,
    probing: Option<Probing>,
}

impl Outbounds {
    pub fn selections(&self) -> Vec<(String, String)> {
        self.shared.selections.entries()
    }

    /// The saved pick of `group`, empty when it has none.
    pub fn selection(&self, group: &str) -> String {
        self.shared
            .selections
            .get(group)
            .map(|proxy| proxy.to_string())
            .unwrap_or_default()
    }

    pub async fn select(&self, group: &str, proxy: &str) -> SelectOutcome {
        match self.stage_selection(group, proxy) {
            Ok(staged) => {
                self.probe_selection(&staged).await;
                self.settle_selection(staged)
            }
            Err(failed) => failed,
        }
    }

    /// Stores the pick, as mihomo's `Set` does before it tests a fallback
    /// member (`fallback.go:139-145`); `settle_selection` tells whether routing
    /// moved once `probe_selection` has run. A fallback member believed dead is
    /// marked under test before it is stored, so routing in between cannot drop
    /// the pick before the test decides.
    pub fn stage_selection(&self, group: &str, proxy: &str) -> Result<Staged, SelectOutcome> {
        let fail = |message: &str| SelectOutcome {
            message: message.to_string(),
            changed: false,
        };
        let target = match self.lookup(group) {
            Some(Found::Node(Node::Group(target))) => target,
            Some(_) => return Err(fail("Group is not selectable")),
            None => return Err(fail("Not found group")),
        };
        if !target.is_selectable() {
            return Err(fail("Group is not selectable"));
        }
        let before = target.now(&dummy_flow(Address::new("", 0), Network::Tcp));
        let store = &self.shared.selections;
        let mut probing = None;
        if proxy.is_empty() {
            if matches!(target.policy(), Policy::Select { .. }) {
                store.set(group, "");
            } else {
                store.remove(group);
            }
        } else {
            let members = target.members();
            let listed = members.find(proxy).is_some()
                || (members.emptiness() == Emptiness::Fallback
                    && target.empty_fallback().name().as_ref() == proxy);
            if !listed {
                return Err(fail("proxy not exist"));
            }
            if matches!(target.policy(), Policy::Fallback)
                && members
                    .find(proxy)
                    .is_some_and(|node| !node.health().alive_for(target.url()))
            {
                probing = Some(store.probing(target.name()));
            }
            store.set(group, proxy);
        }
        Ok(Staged {
            target,
            proxy: proxy.to_string(),
            before,
            probing,
        })
    }

    /// A fallback member believed dead is tested before traffic is routed to
    /// it. Holds no lock, so a slow probe never delays another change.
    pub async fn probe_selection(&self, staged: &Staged) {
        let target = &staged.target;
        if staged.probing.is_some()
            && let Some(node) = target.members().find(&staged.proxy)
        {
            self.url_test_node(node, target.url(), target.expected(), PROBE_TIMEOUT)
                .await;
        }
    }

    pub fn settle_selection(&self, staged: Staged) -> SelectOutcome {
        let Staged {
            target,
            before,
            probing,
            ..
        } = staged;
        drop(probing);
        let changed = target.now(&dummy_flow(Address::new("", 0), Network::Tcp)) != before;
        self.refresh_picks();
        SelectOutcome {
            message: String::new(),
            changed,
        }
    }
}
