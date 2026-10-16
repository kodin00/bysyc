//! Per-IP sliding-window rate limiter for the auth endpoints.
//!
//! In-memory and process-local: each server instance keeps its own buckets,
//! so the effective limit is `AUTH_RATE_PER_MIN` *per replica*. Behind Caddy
//! the real client IP comes from `X-Forwarded-For` (see `auth::client_ip`);
//! the limiter keys on that, so a brute-force run is bounded per source IP.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sliding window length — the "per minute" in `AUTH_RATE_PER_MIN`.
const WINDOW: Duration = Duration::from_secs(60);

pub struct RateLimiter {
    per_min: usize,
    inner: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(per_min: usize) -> Self {
        Self {
            per_min,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Record a hit from `ip`; return whether it's under the limit.
    /// `true` = allowed (the hit was recorded), `false` = rate limited (the
    /// hit was rejected and not recorded). Stale timestamps are pruned on
    /// every call so a quiet IP's bucket can't outlive the window.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - WINDOW;
        let mut map = self.inner.lock().expect("rate limiter mutex poisoned");
        let bucket = map.entry(ip).or_default();
        // Drop timestamps that fell outside the sliding window.
        while let Some(&front) = bucket.front() {
            if front <= cutoff {
                bucket.pop_front();
            } else {
                break;
            }
        }
        if bucket.len() >= self.per_min {
            false
        } else {
            bucket.push_back(now);
            true
        }
    }
}
