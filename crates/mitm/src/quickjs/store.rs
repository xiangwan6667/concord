use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_platform::HomeDir;

use crate::ca::AUTHORITY_DIR;

const MAX_VALUE: usize = 4 << 20;
const MAX_SIZE: usize = 8 << 20;
const FLUSH_DELAY: Duration = Duration::from_millis(10);
const FILE_NAME: &str = "store.json";

#[derive(Default)]
struct Inner {
    loaded: bool,
    values: HashMap<String, String>,
    size: usize,
    dirty: bool,
    scheduled: bool,
}

/// What `$persistentStore` keeps: cookies and tokens, so the file is readable
/// by its owner only.
pub struct Store {
    home: Arc<HomeDir>,
    inner: Mutex<Inner>,
    flushing: Mutex<()>,
}

impl Store {
    pub fn new(home: Arc<HomeDir>) -> Arc<Store> {
        Arc::new(Store {
            home,
            inner: Mutex::default(),
            flushing: Mutex::new(()),
        })
    }

    fn path() -> String {
        format!("{AUTHORITY_DIR}/{FILE_NAME}")
    }

    fn load(&self, inner: &mut Inner) {
        if inner.loaded {
            return;
        }
        inner.loaded = true;
        if let Ok(data) = self.home.read(Self::path()) {
            match serde_json::from_slice::<HashMap<String, String>>(&data) {
                Ok(values) => inner.values = values,
                Err(err) => {
                    tracing::warn!("[MITM] the script store is unreadable and starts over: {err}")
                }
            }
        }
        inner.size = inner
            .values
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum();
    }

    pub fn read(&self, key: &str) -> Option<String> {
        let mut inner = lock(&self.inner);
        self.load(&mut inner);
        inner.values.get(key).cloned()
    }

    pub fn write(self: &Arc<Self>, key: &str, value: &str) -> bool {
        if value.len() > MAX_VALUE {
            tracing::warn!(
                "[MITM] a script stored {} bytes under {key:?}, over the {} MB a value may take",
                value.len(),
                MAX_VALUE >> 20
            );
            return false;
        }
        let mut inner = lock(&self.inner);
        self.load(&mut inner);
        let previous = inner.values.get(key).map_or(0, |old| key.len() + old.len());
        let size = inner.size + key.len() + value.len() - previous;
        if size > MAX_SIZE {
            tracing::warn!("[MITM] the script store is full at {} MB", MAX_SIZE >> 20);
            return false;
        }
        inner.values.insert(key.to_string(), value.to_string());
        inner.size = size;
        self.schedule(&mut inner);
        true
    }

    pub fn remove(self: &Arc<Self>, key: &str) -> bool {
        let mut inner = lock(&self.inner);
        self.load(&mut inner);
        if let Some(previous) = inner.values.remove(key) {
            inner.size -= key.len() + previous.len();
            self.schedule(&mut inner);
        }
        true
    }

    fn schedule(self: &Arc<Self>, inner: &mut Inner) {
        inner.dirty = true;
        if inner.scheduled {
            return;
        }
        inner.scheduled = true;
        let store = self.clone();
        let spawned = std::thread::Builder::new()
            .name("mitm-store".to_string())
            .spawn(move || {
                std::thread::sleep(FLUSH_DELAY);
                store.flush();
            });
        if spawned.is_err() {
            inner.scheduled = false;
        }
    }

    pub fn flush(&self) {
        let _serialized = lock(&self.flushing);
        let data = {
            let mut inner = lock(&self.inner);
            inner.scheduled = false;
            if !inner.dirty {
                return;
            }
            inner.dirty = false;
            serde_json::to_vec(&inner.values)
        };
        let written = data.map_err(std::io::Error::other).and_then(|data| {
            self.home.create_dir_all(AUTHORITY_DIR)?;
            self.home.write_private(Self::path(), &data)
        });
        if let Err(err) = written {
            tracing::warn!("[MITM] saving the script store: {err}");
            lock(&self.inner).dirty = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_persist_across_stores_and_obey_the_limits() {
        let dir = tempfile::tempdir().unwrap();
        let home = Arc::new(HomeDir::new(dir.path()));
        let store = Store::new(home.clone());
        assert!(store.write("k", "v"));
        assert!(!store.write("big", &"x".repeat(MAX_VALUE + 1)));
        store.flush();
        let again = Store::new(home);
        assert_eq!(again.read("k").as_deref(), Some("v"));
        assert!(again.remove("k"));
        again.flush();
        assert_eq!(
            Store::new(Arc::new(HomeDir::new(dir.path()))).read("k"),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_store_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(Arc::new(HomeDir::new(dir.path())));
        store.write("k", "v");
        store.flush();
        let mode = std::fs::metadata(dir.path().join("mitm/store.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
