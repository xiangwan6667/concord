use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use concord_common::sync::lock;
use tokio::sync::Notify;

type Map = HashMap<Arc<str>, Arc<str>>;

/// Picks by group name, so a pick survives a provider swapping the nodes behind
/// it. The engine owns one for every config it will ever run.
#[derive(Default)]
pub struct SelectionStore {
    map: ArcSwap<Map>,
    revoked: Mutex<Vec<Arc<str>>>,
    revoked_ready: Notify,
    probing: Mutex<HashSet<Arc<str>>>,
}

/// Marks a group's new pick as under test until dropped.
pub struct Probing {
    store: Arc<SelectionStore>,
    group: Arc<str>,
}

impl Drop for Probing {
    fn drop(&mut self) {
        {
            let mut probing = lock(&self.store.probing);
            probing.remove(&self.group);
        }
    }
}

impl SelectionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The saved names are not checked against any group's members.
    pub fn replace_all(&self, picks: impl IntoIterator<Item = (String, String)>) {
        let map: Map = picks
            .into_iter()
            .filter(|(_, proxy)| !proxy.is_empty())
            .map(|(group, proxy)| (Arc::from(group), Arc::from(proxy)))
            .collect();
        self.map.store(Arc::new(map));
    }

    pub fn get(&self, group: &str) -> Option<Arc<str>> {
        self.map.load().get(group).cloned()
    }

    /// Every non-empty pick, by group name.
    pub fn entries(&self) -> Vec<(String, String)> {
        let mut entries: Vec<(String, String)> = self
            .map
            .load()
            .iter()
            .filter(|(_, proxy)| !proxy.is_empty())
            .map(|(group, proxy)| (group.to_string(), proxy.to_string()))
            .collect();
        entries.sort();
        entries
    }

    pub fn set(&self, group: &str, proxy: &str) {
        self.map.rcu(|map| {
            let mut next = Map::clone(map);
            next.insert(Arc::from(group), Arc::from(proxy));
            next
        });
    }

    pub fn remove(&self, group: &str) -> bool {
        let mut removed = false;
        self.map.rcu(|map| {
            let mut next = Map::clone(map);
            removed = next.remove(group).is_some();
            next
        });
        removed
    }

    /// While the guard lives, routing steers around the group's pick if its node
    /// is dead but keeps it, so the test decides.
    pub fn probing(self: &Arc<Self>, group: &Arc<str>) -> Probing {
        {
            let mut probing = lock(&self.probing);
            probing.insert(group.clone());
        }
        Probing {
            store: Arc::clone(self),
            group: group.clone(),
        }
    }

    pub fn is_probing(&self, group: &str) -> bool {
        lock(&self.probing).contains(group)
    }

    /// Drops a pick routing gave up on, and queues it for `take_revoked`, so the
    /// engine reports a change no caller asked for.
    pub fn revoke(&self, group: &Arc<str>) -> bool {
        let removed = self.remove(group);
        if removed {
            {
                let mut revoked = lock(&self.revoked);
                revoked.push(group.clone());
            }
            self.revoked_ready.notify_one();
        }
        removed
    }

    pub async fn take_revoked(&self) -> Vec<Arc<str>> {
        loop {
            let taken = std::mem::take(&mut *lock(&self.revoked));
            if !taken.is_empty() {
                return taken;
            }
            self.revoked_ready.notified().await;
        }
    }

    pub fn snapshot(&self) -> HashMap<String, String> {
        self.map
            .load()
            .iter()
            .map(|(group, proxy)| (group.to_string(), proxy.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_all_drops_the_previous_picks_and_checks_nothing() {
        let store = SelectionStore::new();
        store.set("a", "x");
        store.replace_all([("b".to_string(), "a name nobody has".to_string())]);
        assert_eq!(store.get("a"), None);
        assert_eq!(store.get("b").as_deref(), Some("a name nobody has"));
    }

    #[test]
    fn a_probe_ends_after_a_holder_poisoned_the_set() {
        let store = Arc::new(SelectionStore::new());
        let group: Arc<str> = Arc::from("g");
        let probing = store.probing(&group);
        concord_test_support::poison(&store.probing);
        assert!(store.is_probing("g"));
        drop(probing);
        assert!(!store.is_probing("g"));
    }

    #[test]
    fn remove_says_whether_there_was_a_pick() {
        let store = SelectionStore::new();
        store.set("g", "n");
        assert!(store.remove("g"));
        assert!(!store.remove("g"));
        assert!(store.snapshot().is_empty());
    }
}
