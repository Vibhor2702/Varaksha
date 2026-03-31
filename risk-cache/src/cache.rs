use dashmap::{DashMap, mapref::entry::Entry};
use log::info;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cleaner::spawn_cleaner;
use crate::entry::RiskEntry;
use crate::metrics::CacheMetrics;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct RiskCache {
    inner: DashMap<String, RiskEntry>,
    metrics: CacheMetrics,
    ttl_seconds: u64,
    size: AtomicU64,
}

impl RiskCache {
    /// Create a new cache with a configurable TTL (seconds).
    /// Tier defaults: Cloud=180, OnPrem=300, Edge=60.
    pub fn new(ttl_seconds: u64) -> Self {
        let map: DashMap<String, RiskEntry> = DashMap::new();
        spawn_cleaner(map.clone(), ttl_seconds);
        Self {
            inner: map,
            metrics: CacheMetrics::default(),
            ttl_seconds,
            size: AtomicU64::new(0),
        }
    }

    /// Retrieve graph risk delta for a hashed VPA.
    /// Returns (0.0, "cold") when absent or expired.
    pub fn get(&self, vpa_hash: &str) -> (f32, String) {
        if let Some(entry) = self.inner.get(vpa_hash) {
            let now = unix_now();
            if now.saturating_sub(entry.updated_at) > self.ttl_seconds {
                drop(entry);
                self.inner.remove(vpa_hash);
                self.size.fetch_sub(1, Ordering::Relaxed);
                self.metrics.inc_expired();
                return (0.0, "cold".to_string());
            }
            self.metrics.inc_hit();
            return (entry.risk_score, entry.reason.clone());
        }
        self.metrics.inc_miss();
        (0.0, "cold".to_string())
    }

    /// Insert or overwrite a risk delta entry.
    pub fn upsert(&self, vpa_hash: String, risk_score: f32, reason: String, audit_reason: String) {
        let entry = RiskEntry {
            risk_score,
            reason: reason.clone(),
            audit_reason,
            updated_at: unix_now(),
        };

        match self.inner.entry(vpa_hash.clone()) {
            Entry::Occupied(mut occupied) => {
                occupied.insert(entry);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(entry);
                self.size.fetch_add(1, Ordering::Relaxed);
            }
        }
        info!("cache_upsert score={:.4} reason={}", risk_score, reason);
    }

    /// Remove a VPA hash from the cache (DPDP §12(b) right to erasure).
    /// Returns true if an entry existed and was removed.
    pub fn remove(&self, vpa_hash: &str) -> bool {
        let removed = self.inner.remove(vpa_hash).is_some();
        if removed {
            self.size.fetch_sub(1, Ordering::Relaxed);
        }
        removed
    }

    pub fn snapshot(&self, limit: usize) -> Vec<(String, RiskEntry)> {
        self.inner
            .iter()
            .take(limit)
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed) as usize
    }

    pub fn metrics(&self) -> &CacheMetrics {
        &self.metrics
    }
}
