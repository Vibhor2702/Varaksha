use dashmap::DashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

use crate::entry::RiskEntry;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Spawns a background task that removes expired entries every 60 seconds.
/// `ttl_seconds` is the maximum age of an entry before it is evicted.
pub fn spawn_cleaner(map: DashMap<String, RiskEntry>, ttl_seconds: u64) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;

            let now = unix_now();

            let expired: Vec<String> = map
                .iter()
                .filter(|e| now.saturating_sub(e.value().updated_at) > ttl_seconds)
                .map(|e| e.key().clone())
                .collect();

            for key in expired {
                map.remove(&key);
            }
        }
    });
}
