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

/// Upper bound on tracked IP buckets. A flood of distinct source IPs can't
/// grow the map without limit: at capacity, inserting a new bucket evicts
/// the one with the oldest front timestamp (a linear scan under the lock;
/// this path is cold, since reaching the cap means >65k active sources).
const MAX_BUCKETS: usize = 65_536;

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
    /// every call so a quiet IP's bucket can't outlive the window; a bucket
    /// that empties out is dropped from the map, and the total bucket count
    /// is bounded by [`MAX_BUCKETS`] (oldest-front eviction when full).
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - WINDOW;
        let mut map = self.inner.lock().expect("rate limiter mutex poisoned");

        // Prune stale timestamps for this IP; drop the bucket if it empties
        // so quiet IPs don't linger in the map. The mutable borrow of `map`
        // through `bucket` ends at the block edge so the `remove` below
        // reborrow is clean.
        let emptied = if let Some(bucket) = map.get_mut(&ip) {
            while let Some(&front) = bucket.front() {
                if front <= cutoff {
                    bucket.pop_front();
                } else {
                    break;
                }
            }
            bucket.is_empty()
        } else {
            false
        };
        if emptied {
            map.remove(&ip);
        }

        let (len, has_bucket) = match map.get(&ip) {
            Some(b) => (b.len(), true),
            None => (0, false),
        };
        if len >= self.per_min {
            return false;
        }

        // About to record a hit. If this IP has no bucket, make room under
        // the cap by evicting the bucket whose oldest timestamp is earliest.
        if !has_bucket && map.len() >= MAX_BUCKETS {
            let evict = {
                let (k, _) = map
                    .iter()
                    .min_by_key(|(_, b)| b.front())
                    .expect("map non-empty when len >= MAX_BUCKETS");
                *k
            };
            map.remove(&evict);
        }

        map.entry(ip).or_default().push_back(now);
        true
    }
}
