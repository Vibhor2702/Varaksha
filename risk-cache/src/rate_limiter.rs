//! Per-key sliding window rate limiter backed by DashMap.
//!
//! NPCI UPI Security Framework requires velocity controls at every scoring layer.
//! This is the Rust-level check — separate from any upstream DDoS protection.
//!
//! Key = SHA-256 hashed device_id for /inference, client IP for /update_cache.
//! On breach: caller receives HTTP 429 with a Retry-After header. No score is returned.
//!
//! Tier defaults (from PolicyConfig):
//!   Cloud   → 100 req / 60 s per key
//!   OnPrem  → 500 req / 60 s per key
//!   Edge    → 20  req / 300 s per key

use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct RateLimiter {
    /// (request_count_in_window, window_start_unix_secs)
    windows: DashMap<String, (u64, u64)>,
    max_requests: u64,
    window_seconds: u64,
}

impl RateLimiter {
    pub fn new(max_requests: u64, window_seconds: u64) -> Self {
        Self {
            windows: DashMap::new(),
            max_requests,
            window_seconds,
        }
    }

    /// Returns `true` if the request is within limits, `false` if the rate limit is exceeded.
    /// Always records the request when within limits.
    ///
    /// The window slides: when the current time is more than `window_seconds` past the
    /// stored `window_start`, the counter resets and a fresh window begins.
    pub fn check_and_record(&self, key: &str) -> bool {
        let now = unix_now_secs();

        let mut entry = self.windows.entry(key.to_string()).or_insert((0, now));

        let (count, window_start) = entry.value_mut();

        // Reset window if expired.
        if now.saturating_sub(*window_start) >= self.window_seconds {
            *count = 0;
            *window_start = now;
        }

        if *count >= self.max_requests {
            return false;
        }

        *count += 1;
        true
    }

    /// How many seconds remain in the current window for `key`.
    /// Used to populate the Retry-After response header.
    pub fn retry_after(&self, key: &str) -> u64 {
        let now = unix_now_secs();
        if let Some(entry) = self.windows.get(key) {
            let (_, window_start) = *entry;
            let elapsed = now.saturating_sub(window_start);
            return self.window_seconds.saturating_sub(elapsed);
        }
        self.window_seconds
    }
}
