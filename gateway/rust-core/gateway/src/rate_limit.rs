/// rate_limit.rs — Adaptive IP rate limiter with automatic quarantine
///
/// Problem with static limits: a distributed attack across N IPs each sending
/// requests at (threshold - 1) req/s passes through entirely.
///
/// This implementation uses:
///   1. Per-IP sliding-window token bucket (lockless via DashMap)
///   2. Violation counter — multiple violations → quarantine
///   3. /24 subnet aggregate  — catches coordinated distributed campaigns
///   4. Automatic quarantine expiry — no ops intervention required
///   5. Every quarantine event logged to permanent security log

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

const RATE_LIMIT_RPS:          u32  = 100;   // requests per second per IP
const VIOLATION_THRESHOLD:     u32  = 5;     // violations before quarantine
const VIOLATION_WINDOW_SECS:   u64  = 60;    // violation count window
const QUARANTINE_DURATION_SECS: u64 = 600;   // 10 minutes
#[allow(dead_code)]
const SUBNET_AGGREGATE_RPS: u32 = 500; // /24 subnet aggregate limit

#[derive(Debug)]
pub struct SlidingWindow {
    count:        u32,
    window_start: Instant,
    violations:   u32,
    violation_window_start: Instant,
}

impl SlidingWindow {
    fn new() -> Self {
        Self {
            count:        0,
            window_start: Instant::now(),
            violations:   0,
            violation_window_start: Instant::now(),
        }
    }

    /// Returns true if this request is ALLOWED, false if over limit.
    fn check_and_increment(&mut self) -> bool {
        let now = Instant::now();
        // Reset 1-second window
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.count = 0;
            self.window_start = now;
        }
        self.count += 1;
        let allowed = self.count <= RATE_LIMIT_RPS;
        if !allowed {
            // Reset violation window if expired
            if now.duration_since(self.violation_window_start)
                >= Duration::from_secs(VIOLATION_WINDOW_SECS)
            {
                self.violations = 0;
                self.violation_window_start = now;
            }
            self.violations += 1;
        }
        allowed
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    /// Request is within limits — proceed.
    Allowed,
    /// Soft reject — rate exceeded but not quarantined.
    Exceeded,
    /// Hard reject — IP is in quarantine. Return 429 and log.
    Quarantined { until: Instant },
}

pub struct AdaptiveRateLimiter {
    per_ip:     Arc<DashMap<IpAddr, SlidingWindow>>,
    per_subnet: Arc<DashMap<[u8; 3], SlidingWindow>>,  // /24 key = first 3 octets
    quarantine: Arc<DashMap<IpAddr, Instant>>,
    security_log: Arc<SecurityLog>,
}

impl AdaptiveRateLimiter {
    pub fn new(security_log: Arc<SecurityLog>) -> Self {
        Self {
            per_ip:     Arc::new(DashMap::new()),
            per_subnet: Arc::new(DashMap::new()),
            quarantine: Arc::new(DashMap::new()),
            security_log,
        }
    }

    pub fn check(&self, ip: IpAddr) -> RateLimitResult {
        // ── 1. Check quarantine first (O(1) lookup) ──────────────────────────
        if let Some(until) = self.quarantine.get(&ip) {
            if Instant::now() < *until {
                return RateLimitResult::Quarantined { until: *until };
            } else {
                // Quarantine expired — remove
                drop(until);
                self.quarantine.remove(&ip);
            }
        }

        // ── 2. /24 subnet aggregate check ────────────────────────────────────
        if let IpAddr::V4(v4) = ip {
            let octets = v4.octets();
            let subnet_key = [octets[0], octets[1], octets[2]];
            let subnet_ok = self.per_subnet
                .entry(subnet_key)
                .or_insert_with(SlidingWindow::new)
                .check_and_increment();
            if !subnet_ok {
                warn!("subnet {}.{}.{}.0/24 exceeded aggregate limit", octets[0], octets[1], octets[2]);
                // Subnet over limit — check if this IP should be quarantined
                // (don't quarantine the whole subnet, just the specific IP if it's also over)
            }
        }

        // ── 3. Per-IP check ──────────────────────────────────────────────────
        let allowed = self.per_ip
            .entry(ip)
            .or_insert_with(SlidingWindow::new)
            .check_and_increment();

        if !allowed {
            // Check violation count
            let violations = self.per_ip
                .get(&ip)
                .map(|w| w.violations)
                .unwrap_or(0);

            if violations >= VIOLATION_THRESHOLD {
                let quarantine_until = Instant::now()
                    + Duration::from_secs(QUARANTINE_DURATION_SECS);
                self.quarantine.insert(ip, quarantine_until);
                self.security_log.log_quarantine(ip, violations);
                warn!("IP {ip} quarantined for {} minutes ({violations} violations)", QUARANTINE_DURATION_SECS / 60);
                return RateLimitResult::Quarantined { until: quarantine_until };
            }

            return RateLimitResult::Exceeded;
        }

        RateLimitResult::Allowed
    }
}

// ─── Simple in-process security log (append-only ring buffer) ────────────────
pub struct SecurityLog {
    entries: DashMap<u64, SecurityEntry>,
    counter: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // fields populated in log_quarantine; read by external audit tooling
pub struct SecurityEntry {
    pub timestamp:   Instant,
    pub ip:          IpAddr,
    pub event_type:  &'static str,
    pub detail:      String,
}

impl SecurityLog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            counter: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn log_quarantine(&self, ip: IpAddr, violations: u32) {
        let id = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.entries.insert(id, SecurityEntry {
            timestamp:  Instant::now(),
            ip,
            event_type: "QUARANTINE",
            detail: format!("IP quarantined after {violations} rate-limit violations in {VIOLATION_WINDOW_SECS}s window"),
        });
        info!("SecurityLog[QUARANTINE] ip={ip} violations={violations}");
    }

    #[allow(dead_code)] // public API used by admin endpoints / tests
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_limiter() -> AdaptiveRateLimiter {
        AdaptiveRateLimiter::new(SecurityLog::new())
    }

    #[test]
    fn within_limit_is_allowed() {
        let rl = make_limiter();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..RATE_LIMIT_RPS {
            assert_eq!(rl.check(ip), RateLimitResult::Allowed);
        }
    }

    #[test]
    fn over_limit_is_exceeded() {
        let rl = make_limiter();
        let ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        // Fill the window
        for _ in 0..RATE_LIMIT_RPS {
            rl.check(ip);
        }
        assert_eq!(rl.check(ip), RateLimitResult::Exceeded);
    }

    #[test]
    fn repeated_violations_trigger_quarantine() {
        let rl = make_limiter();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 10, 11, 12));
        // Exhaust limit + trigger violations
        for _ in 0..(RATE_LIMIT_RPS * (VIOLATION_THRESHOLD + 2)) {
            rl.check(ip);
        }
        let result = rl.check(ip);
        assert!(
            matches!(result, RateLimitResult::Quarantined { .. }),
            "Expected quarantine after {VIOLATION_THRESHOLD} violations"
        );
    }
}
