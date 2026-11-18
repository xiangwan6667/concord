use std::sync::Arc;

use concord_common::ConnRecord;

use super::Engine;

impl Engine {
    pub fn traffic_now(&self, only_proxy: bool) -> (i64, i64) {
        as_signed(self.table.now(only_proxy))
    }

    pub fn traffic_total(&self, only_proxy: bool) -> (i64, i64) {
        as_signed(self.table.total(only_proxy))
    }

    pub fn traffic_reset(&self) {
        self.table.reset();
    }

    pub fn connections(&self) -> Vec<Arc<ConnRecord>> {
        self.table.snapshot()
    }

    pub fn connection_id(&self, seq: u64) -> Option<String> {
        self.table.id_of(seq)
    }

    pub fn connection_count(&self) -> usize {
        self.table.len()
    }

    pub fn close_all_connections(&self) {
        self.table.close_all();
    }
}

fn as_signed((up, down): (u64, u64)) -> (i64, i64) {
    (
        i64::try_from(up).unwrap_or(i64::MAX),
        i64::try_from(down).unwrap_or(i64::MAX),
    )
}
