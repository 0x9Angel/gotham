// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::time::{Duration, Instant};

const WIRE_BYTES_PER_PACKET: u64 = 2064;

const QUOTA_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ThrottleReason {
    Rate,
    DailyQuota,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    Throttled(ThrottleReason),
}

impl RateDecision {
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateDecision::Allow)
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    max_pps: f64,
    burst: f64,
    tokens: f64,
    last_refill: Instant,

    max_bytes_per_day: u64,
    bytes_used: u64,
    window_start: Instant,
}

impl RateLimiter {
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(0.0, 0)
    }

    #[must_use]
    pub fn new(max_pps: f64, max_bytes_per_day: u64) -> Self {
        let max_pps = max_pps.max(0.0);
        let burst = if max_pps > 0.0 { max_pps * 2.0 } else { 0.0 };
        Self {
            max_pps,
            burst,
            tokens: burst,
            last_refill: Instant::now(),
            max_bytes_per_day,
            bytes_used: 0,
            window_start: Instant::now(),
        }
    }

    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.max_pps == 0.0 && self.max_bytes_per_day == 0
    }

    #[must_use]
    pub fn bytes_used_today(&self) -> u64 {
        self.bytes_used
    }

    pub fn check(&mut self, packet_len: usize) -> RateDecision {
        self.check_at(packet_len, Instant::now())
    }

    pub fn check_at(&mut self, _packet_len: usize, now: Instant) -> RateDecision {
        let mut bytes_used = self.bytes_used;
        let mut window_start = self.window_start;
        if self.max_bytes_per_day > 0 {
            if now.saturating_duration_since(window_start) >= QUOTA_WINDOW {
                bytes_used = 0;
                window_start = now;
            }
            if bytes_used.saturating_add(WIRE_BYTES_PER_PACKET) > self.max_bytes_per_day {
                return RateDecision::Throttled(ThrottleReason::DailyQuota);
            }
        }

        let mut tokens = self.tokens;
        if self.max_pps > 0.0 {
            let elapsed = now
                .saturating_duration_since(self.last_refill)
                .as_secs_f64();
            tokens = (tokens + elapsed * self.max_pps).min(self.burst);
            if tokens < 1.0 {
                return RateDecision::Throttled(ThrottleReason::Rate);
            }
        }

        if self.max_pps > 0.0 {
            self.tokens = tokens - 1.0;
            self.last_refill = now;
        }
        if self.max_bytes_per_day > 0 {
            self.bytes_used = bytes_used.saturating_add(WIRE_BYTES_PER_PACKET);
            self.window_start = window_start;
        }
        RateDecision::Allow
    }
}

pub struct PerSourceLimiter {
    buckets: std::collections::HashMap<std::net::IpAddr, (RateLimiter, Instant)>,
    max_entries: usize,
    max_pps: f64,
    max_bytes_per_day: u64,
}

impl PerSourceLimiter {
    #[must_use]
    pub fn new(max_pps: f64, max_bytes_per_day: u64, max_entries: usize) -> Self {
        Self {
            buckets: std::collections::HashMap::new(),
            max_entries: max_entries.max(1),
            max_pps,
            max_bytes_per_day,
        }
    }

    pub fn check(&mut self, src: std::net::IpAddr, packet_len: usize) -> RateDecision {
        self.check_at(src, packet_len, Instant::now())
    }

    pub fn check_at(
        &mut self,
        src: std::net::IpAddr,
        packet_len: usize,
        now: Instant,
    ) -> RateDecision {
        if !self.buckets.contains_key(&src) && self.buckets.len() >= self.max_entries {
            if let Some(victim) = self
                .buckets
                .iter()
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(ip, _)| *ip)
            {
                self.buckets.remove(&victim);
            }
        }
        let entry = self
            .buckets
            .entry(src)
            .or_insert_with(|| (RateLimiter::new(self.max_pps, self.max_bytes_per_day), now));
        entry.1 = now;
        entry.0.check_at(packet_len, now)
    }

    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_never_throttles() {
        let mut rl = RateLimiter::unlimited();
        assert!(rl.is_unlimited());
        let now = Instant::now();
        for _ in 0..1_000_000 {
            assert_eq!(rl.check_at(2048, now), RateDecision::Allow);
        }
    }

    #[test]
    fn rate_bucket_blocks_after_burst_then_refills() {
        let mut rl = RateLimiter::new(10.0, 0);
        let t0 = Instant::now();
        for i in 0..20 {
            assert_eq!(
                rl.check_at(2048, t0),
                RateDecision::Allow,
                "burst packet {i}"
            );
        }
        assert_eq!(
            rl.check_at(2048, t0),
            RateDecision::Throttled(ThrottleReason::Rate)
        );
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(rl.check_at(2048, t1), RateDecision::Allow);
    }

    #[test]
    fn rate_throttle_consumes_nothing() {
        let mut rl = RateLimiter::new(1.0, 0);
        let t0 = Instant::now();
        assert!(rl.check_at(2048, t0).is_allowed());
        assert!(rl.check_at(2048, t0).is_allowed());
        for _ in 0..100 {
            assert_eq!(
                rl.check_at(2048, t0),
                RateDecision::Throttled(ThrottleReason::Rate)
            );
        }
    }

    #[test]
    fn daily_quota_blocks_then_resets_after_window() {
        let budget = WIRE_BYTES_PER_PACKET * 3;
        let mut rl = RateLimiter::new(0.0, budget);
        let t0 = Instant::now();
        for i in 0..3 {
            assert_eq!(
                rl.check_at(2048, t0),
                RateDecision::Allow,
                "quota packet {i}"
            );
        }
        assert_eq!(
            rl.check_at(2048, t0),
            RateDecision::Throttled(ThrottleReason::DailyQuota)
        );
        assert_eq!(rl.bytes_used_today(), budget);
        let almost = t0 + QUOTA_WINDOW - Duration::from_secs(1);
        assert_eq!(
            rl.check_at(2048, almost),
            RateDecision::Throttled(ThrottleReason::DailyQuota)
        );
        let next_day = t0 + QUOTA_WINDOW;
        assert_eq!(rl.check_at(2048, next_day), RateDecision::Allow);
        assert_eq!(rl.bytes_used_today(), WIRE_BYTES_PER_PACKET);
    }

    #[test]
    fn quota_accounts_wire_bytes_not_packet_len() {
        let budget = WIRE_BYTES_PER_PACKET;
        let mut rl = RateLimiter::new(0.0, budget);
        let t0 = Instant::now();
        assert_eq!(rl.check_at(1, t0), RateDecision::Allow);
        assert_eq!(
            rl.check_at(1, t0),
            RateDecision::Throttled(ThrottleReason::DailyQuota)
        );
    }

    #[test]
    fn both_guards_active_either_can_throttle() {
        let mut rl = RateLimiter::new(1000.0, WIRE_BYTES_PER_PACKET * 2);
        let t0 = Instant::now();
        assert!(rl.check_at(2048, t0).is_allowed());
        assert!(rl.check_at(2048, t0).is_allowed());
        assert_eq!(
            rl.check_at(2048, t0),
            RateDecision::Throttled(ThrottleReason::DailyQuota)
        );
        let mut rl2 = RateLimiter::new(2.0, u64::MAX);
        assert!(rl2.check_at(2048, t0).is_allowed());
        assert!(rl2.check_at(2048, t0).is_allowed());
        assert!(rl2.check_at(2048, t0).is_allowed());
        assert!(rl2.check_at(2048, t0).is_allowed());
        assert_eq!(
            rl2.check_at(2048, t0),
            RateDecision::Throttled(ThrottleReason::Rate)
        );
    }

    #[test]
    fn a_flood_from_one_source_does_not_shed_another() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut lim = PerSourceLimiter::new(10.0, 0, 64);
        let t0 = Instant::now();
        let flooder = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let victim = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));

        let mut throttled = 0;
        for _ in 0..200 {
            if !lim.check_at(flooder, 2048, t0).is_allowed() {
                throttled += 1;
            }
        }
        assert!(throttled > 0, "the flooder must hit its own limit");

        for _ in 0..10 {
            assert!(
                lim.check_at(victim, 2048, t0).is_allowed(),
                "a second source must not pay for the first one's flood"
            );
        }
    }

    #[test]
    fn the_source_table_is_bounded_and_evicts_the_longest_idle() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut lim = PerSourceLimiter::new(10.0, 0, 4);
        let t0 = Instant::now();

        for i in 0..5u8 {
            lim.check_at(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, i)),
                2048,
                t0 + Duration::from_millis(u64::from(i)),
            );
        }
        assert_eq!(lim.tracked(), 4, "the table must stay at its bound");

        let oldest = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0));
        assert!(
            lim.check_at(oldest, 2048, t0 + Duration::from_millis(10))
                .is_allowed(),
            "an evicted source starts fresh, which only forgives a quiet one"
        );
        assert_eq!(lim.tracked(), 4);
    }
}
