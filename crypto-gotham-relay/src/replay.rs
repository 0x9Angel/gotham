// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Bounded LRU + TTL replay cache.
//!
//! Each entry is keyed by the packet's `γ` MAC (16 B). Inserts return
//! [`ReplayCheck::Replay`] if the key was already present; otherwise the
//! key is recorded and [`ReplayCheck::Fresh`] is returned.
//!
//! TTL eviction is amortised: every insert sweeps expired entries from
//! the FIFO head. Hot path remains O(1) amortised. The hard `max_size`
//! cap is enforced via FIFO eviction of the oldest entry when full.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Outcome of a [`ReplayCache::check_and_insert`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReplayCheck {
    /// Key was not in the cache. It has now been inserted.
    Fresh,
    /// Key was already in the cache — the packet is a replay and must be
    /// dropped silently.
    Replay,
}

/// Bounded LRU + TTL cache of `γ` MACs.
pub struct ReplayCache {
    map: HashMap<[u8; 16], Instant>,
    queue: VecDeque<([u8; 16], Instant)>,
    ttl: Duration,
    max_size: usize,
}

impl ReplayCache {
    /// Create a new cache with at most `max_size` entries and per-entry
    /// `ttl`. Recommended defaults: `max_size = 1_000_000`, `ttl = 5 min`.
    #[must_use]
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            map: HashMap::with_capacity(max_size / 8),
            queue: VecDeque::with_capacity(max_size / 8),
            ttl,
            max_size,
        }
    }

    /// Sweep expired entries from the FIFO head until the next entry is
    /// younger than `ttl`.
    fn sweep_expired(&mut self, now: Instant) {
        while let Some(&(_, ts)) = self.queue.front() {
            if now.duration_since(ts) > self.ttl {
                if let Some((k, _)) = self.queue.pop_front() {
                    self.map.remove(&k);
                }
            } else {
                break;
            }
        }
    }

    /// Test-friendly variant of [`Self::check_and_insert`] taking an
    /// explicit `now`. Production callers should use the convenience
    /// wrapper.
    pub fn check_and_insert_at(&mut self, key: [u8; 16], now: Instant) -> ReplayCheck {
        self.sweep_expired(now);
        if self.map.contains_key(&key) {
            return ReplayCheck::Replay;
        }
        // Enforce the hard cap by evicting the oldest entry if full.
        if self.map.len() >= self.max_size {
            if let Some((old_k, _)) = self.queue.pop_front() {
                self.map.remove(&old_k);
            }
        }
        self.map.insert(key, now);
        self.queue.push_back((key, now));
        ReplayCheck::Fresh
    }

    /// Check whether `key` is a replay. If not, record it and return
    /// [`ReplayCheck::Fresh`].
    pub fn check_and_insert(&mut self, key: [u8; 16]) -> ReplayCheck {
        self.check_and_insert_at(key, Instant::now())
    }

    /// Current number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if the cache currently holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    #[test]
    fn fresh_then_replay() {
        let mut cache = ReplayCache::new(100, Duration::from_secs(60));
        let key = k(1);
        assert_eq!(cache.check_and_insert(key), ReplayCheck::Fresh);
        assert_eq!(cache.check_and_insert(key), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert(key), ReplayCheck::Replay);
    }

    #[test]
    fn different_keys_independent() {
        let mut cache = ReplayCache::new(100, Duration::from_secs(60));
        for i in 0..50u8 {
            assert_eq!(cache.check_and_insert(k(i)), ReplayCheck::Fresh);
        }
        for i in 0..50u8 {
            assert_eq!(cache.check_and_insert(k(i)), ReplayCheck::Replay);
        }
    }

    #[test]
    fn ttl_eviction() {
        let mut cache = ReplayCache::new(100, Duration::from_secs(1));
        let now = Instant::now();
        assert_eq!(cache.check_and_insert_at(k(1), now), ReplayCheck::Fresh);
        // 0.5 s later: still in cache.
        let later = now + Duration::from_millis(500);
        assert_eq!(cache.check_and_insert_at(k(1), later), ReplayCheck::Replay);
        // 2 s later: TTL expired, entry evicted, fresh again.
        let much_later = now + Duration::from_secs(2);
        assert_eq!(
            cache.check_and_insert_at(k(1), much_later),
            ReplayCheck::Fresh
        );
    }

    #[test]
    fn capacity_enforced_via_fifo_eviction() {
        let mut cache = ReplayCache::new(3, Duration::from_secs(3600));
        let now = Instant::now();
        cache.check_and_insert_at(k(1), now);
        cache.check_and_insert_at(k(2), now);
        cache.check_and_insert_at(k(3), now);
        assert_eq!(cache.len(), 3);
        // Inserting a 4th evicts the oldest (k(1)).
        cache.check_and_insert_at(k(4), now);
        assert_eq!(cache.len(), 3);
        // k(2), k(3), k(4) are still in the cache (we check k(1) last so
        // the act of testing replay status doesn't mutate it).
        assert_eq!(cache.check_and_insert_at(k(2), now), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert_at(k(3), now), ReplayCheck::Replay);
        assert_eq!(cache.check_and_insert_at(k(4), now), ReplayCheck::Replay);
        // k(1) was evicted at step 4 — re-insertion is Fresh (and would
        // itself evict k(2), but we don't probe further here).
        assert_eq!(cache.check_and_insert_at(k(1), now), ReplayCheck::Fresh);
    }

    #[test]
    fn empty_cache_is_empty() {
        let cache = ReplayCache::new(10, Duration::from_secs(60));
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }
}
