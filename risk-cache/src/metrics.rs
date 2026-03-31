use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub expired: AtomicU64,
}

impl CacheMetrics {
    pub fn inc_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_expired(&self) {
        self.expired.fetch_add(1, Ordering::Relaxed);
    }
}
