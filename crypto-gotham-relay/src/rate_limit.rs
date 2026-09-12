// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Inbound rate limiting for a volunteer-operated relay.
//!
//! Two independent guards protect the operator's machine and connection:
//!
//! 1. **Packets-per-second** — a classic token bucket (smooth rate +
//!    bounded burst). Caps CPU spent on Sphinx unwrap and shields the box
//!    from a flood. `0` disables it.
//! 2. **Daily byte quota** — a hard wire-byte budget over a rolling 24 h
//!    window. The real protection for metered / capped connections
//!    (mobile, Freebox data plans, …). `0` disables it.
//!
//! The limiter is *global* for the node (not per-source): in a mixnet the
//! only visible source is the previous hop, so a per-node ceiling is what
//! actually protects the operator's resources. Per-source fairness is a
//! v0.2 consideration.
//!
//! Like [`crate::replay::ReplayCache`], time is injectable
//! ([`RateLimiter::check_at`]) so the logic is deterministically testable
//! without a clock; production code calls [`RateLimiter::check`].

use std::time::{Duration, Instant};

/// Wire bytes per Gotham packet (2048 B Sphinx + 16 B Noise AEAD tag).
/// Used to account the daily quota in terms of bytes actually crossing
/// the operator's NIC, not just the plaintext packet size.
const WIRE_BYTES_PER_PACKET: u64 = 2064;

/// Length of the daily-quota accounting window.
const QUOTA_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Why a packet was throttled (for counter metrics — never per-packet
/// identifiers).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ThrottleReason {
    /// Token bucket empty — packet rate exceeded `max_pps`.
    Rate,
    /// Rolling 24 h wire-byte budget exhausted.
    DailyQuota,
}

/// Result of a rate-limit check.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RateDecision {
    /// Packet is within limits and has been accounted.
    Allow,
    /// Packet must be dropped; nothing was accounted.
    Throttled(ThrottleReason),
}

impl RateDecision {
    /// Did this decision allow the packet?
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateDecision::Allow)
    }
}

/// Token-bucket packets/sec limiter + rolling daily byte quota.
#[derive(Debug)]
pub struct RateLimiter {
    /// Refill rate (tokens/sec). `0.0` ⇒ pps limiting disabled.
    max_pps: f64,
    /// Bucket capacity (max burst). Ignored when `max_pps == 0`.
    burst: f64,
    /// Current tokens available.
    tokens: f64,
    /// Last time the bucket was refilled.
    last_refill: Instant,

    /// Daily wire-byte budget. `0` ⇒ quota disabled.
    max_bytes_per_day: u64,
    /// Wire bytes consumed in the current window.
    bytes_used: u64,
    /// Start of the current 24 h window.
    window_start: Instant,
}

impl RateLimiter {
    /// A limiter that never throttles (preserves pre-rate-limit behaviour).
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(0.0, 0)
    }

    /// Build a limiter.
    ///
    /// * `max_pps` — sustained packets/sec ceiling (`0.0` = unlimited).
    ///   Burst capacity is `2 × max_pps` so short spikes are absorbed.
    /// * `max_bytes_per_day` — rolling 24 h wire-byte budget
    ///   (`0` = unlimited).
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

    /// `true` if neither guard is active (no throttling will ever occur).
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.max_pps == 0.0 && self.max_bytes_per_day == 0
    }

    /// Wire bytes consumed in the current 24 h window (for metrics).
    #[must_use]
    pub fn bytes_used_today(&self) -> u64 {
        self.bytes_used
    }

    /// Production entry point — checks against the wall clock.
    pub fn check(&mut self, packet_len: usize) -> RateDecision {
        self.check_at(packet_len, Instant::now())
    }

    /// Deterministic, clock-injectable check. Accounts a single inbound
    /// packet of `packet_len` plaintext bytes (the wire cost is derived
    /// from the fixed packet size, not `packet_len`, so a short/oversized
    /// frame can't game the quota).
    ///
    /// Only mutates state when the decision is [`RateDecision::Allow`]: a
    /// throttled packet consumes neither a token nor quota, so a sustained
    /// flood is rejected at constant cost.
    pub fn check_at(&mut self, _packet_len: usize, now: Instant) -> RateDecision {
        // Compute every would-be update on locals first, return on any
        // Throttle WITHOUT touching `self`, then commit only on Allow — so a
        // throttled packet never resets the quota window or refills the
        // bucket (the invariant a flood relies on for constant-cost rejection).

        // ── Daily quota (checked first; cheaper and the harder cap) ──────
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

        // ── Packets/sec token bucket ─────────────────────────────────────
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

        // Both guards passed — commit (consume a token + account bytes).
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

/// Per-source token buckets, bounded.
///
/// F-55 — the node-global limiter is a single bucket consulted once per
/// packet, so one flooder's traffic and everyone else's come out of the SAME
/// budget. That is precisely the lever an n-1 attack needs: fill the bucket
/// and third-party packets are shed, leaving the attacker's own flow alone in
/// the mix. Attributing the budget to a source removes it — a flood can then
/// only shed the flooder.
///
/// The map itself is an attack surface, so it is bounded: an adversary with
/// many addresses would otherwise grow it without limit. When full, the
/// longest-idle entry is evicted, which is safe because evicting a bucket only
/// forgives past usage for a source that has been quiet.
///
/// This is a SECOND limiter, not a replacement: the node-global one stays as
/// the outer ceiling on what this relay will carry in total.
pub struct PerSourceLimiter {
    buckets: std::collections::HashMap<std::net::IpAddr, (RateLimiter, Instant)>,
    max_entries: usize,
    max_pps: f64,
    max_bytes_per_day: u64,
}

impl PerSourceLimiter {
    /// Build a per-source limiter: `max_pps` and `max_bytes_per_day` per
    /// SOURCE, and at most `max_entries` sources tracked at once.
    #[must_use]
    pub fn new(max_pps: f64, max_bytes_per_day: u64, max_entries: usize) -> Self {
        Self {
            buckets: std::collections::HashMap::new(),
            max_entries: max_entries.max(1),
            max_pps,
            max_bytes_per_day,
        }
    }

    /// Account one packet from `src`. Same semantics as [`RateLimiter::check`].
    pub fn check(&mut self, src: std::net::IpAddr, packet_len: usize) -> RateDecision {
        self.check_at(src, packet_len, Instant::now())
    }

    /// Deterministic, clock-injectable form — the tests drive this one.
    pub fn check_at(
        &mut self,
        src: std::net::IpAddr,
        packet_len: usize,
        now: Instant,
    ) -> RateDecision {
        if !self.buckets.contains_key(&src) && self.buckets.len() >= self.max_entries {
            // Evict the longest idle. Doing this BEFORE inserting keeps the
            // map at its bound even under a churn of one-packet sources.
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

    /// How many sources are currently tracked. For tests and metrics.
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
        // 10 pps ⇒ burst capacity 20.
        let mut rl = RateLimiter::new(10.0, 0);
        let t0 = Instant::now();
        // The first 20 packets (full bucket) at the same instant pass.
        for i in 0..20 {
            assert_eq!(
                rl.check_at(2048, t0),
                RateDecision::Allow,
                "burst packet {i}"
            );
        }
        // The 21st (no time elapsed → no refill) is throttled.
        assert_eq!(
            rl.check_at(2048, t0),
            RateDecision::Throttled(ThrottleReason::Rate)
        );
        // After 1 s, ~10 tokens refilled → at least one passes again.
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(rl.check_at(2048, t1), RateDecision::Allow);
    }

    #[test]
    fn rate_throttle_consumes_nothing() {
        // 1 pps, burst 2. Exhaust the bucket, then hammer it: every
        // throttled call must stay throttled (no token leaked) until time
        // advances.
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
        // Budget = 3 packets' worth of wire bytes.
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
        // 4th exceeds the daily budget.
        assert_eq!(
            rl.check_at(2048, t0),
            RateDecision::Throttled(ThrottleReason::DailyQuota)
        );
        assert_eq!(rl.bytes_used_today(), budget);
        // Just before the window rolls over: still blocked.
        let almost = t0 + QUOTA_WINDOW - Duration::from_secs(1);
        assert_eq!(
            rl.check_at(2048, almost),
            RateDecision::Throttled(ThrottleReason::DailyQuota)
        );
        // After 24 h the window resets and traffic flows again.
        let next_day = t0 + QUOTA_WINDOW;
        assert_eq!(rl.check_at(2048, next_day), RateDecision::Allow);
        assert_eq!(rl.bytes_used_today(), WIRE_BYTES_PER_PACKET);
    }

    #[test]
    fn quota_accounts_wire_bytes_not_packet_len() {
        // A short frame can't understate its quota cost: accounting uses
        // the fixed wire size regardless of the reported length.
        let budget = WIRE_BYTES_PER_PACKET; // exactly one packet
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
        // Generous pps, tight quota: the quota bites first.
        let mut rl = RateLimiter::new(1000.0, WIRE_BYTES_PER_PACKET * 2);
        let t0 = Instant::now();
        assert!(rl.check_at(2048, t0).is_allowed());
        assert!(rl.check_at(2048, t0).is_allowed());
        assert_eq!(
            rl.check_at(2048, t0),
            RateDecision::Throttled(ThrottleReason::DailyQuota)
        );
        // And a throttled-by-quota packet must not have spent a token: the
        // bucket is still essentially full.
        // (Indirectly: switch to a fresh limiter where pps is the tight one.)
        let mut rl2 = RateLimiter::new(2.0, u64::MAX);
        assert!(rl2.check_at(2048, t0).is_allowed());
        assert!(rl2.check_at(2048, t0).is_allowed());
        assert!(rl2.check_at(2048, t0).is_allowed()); // burst = 2×pps = 4
        assert!(rl2.check_at(2048, t0).is_allowed());
        assert_eq!(
            rl2.check_at(2048, t0),
            RateDecision::Throttled(ThrottleReason::Rate)
        );
    }

    /// F-55 — one flooder must not spend everyone else's budget.
    ///
    /// That shared budget is the n-1 lever: fill the node-global bucket and
    /// third-party packets are shed, leaving the attacker's own flow alone in
    /// the mix, which is exactly the condition an n-1 attack needs.
    #[test]
    fn a_flood_from_one_source_does_not_shed_another() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut lim = PerSourceLimiter::new(10.0, 0, 64);
        let t0 = Instant::now();
        let flooder = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let victim = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));

        // The flooder empties its own bucket (capacity is 2x max_pps).
        let mut throttled = 0;
        for _ in 0..200 {
            if !lim.check_at(flooder, 2048, t0).is_allowed() {
                throttled += 1;
            }
        }
        assert!(throttled > 0, "the flooder must hit its own limit");

        // …and the victim, at the same instant, is untouched.
        for _ in 0..10 {
            assert!(
                lim.check_at(victim, 2048, t0).is_allowed(),
                "a second source must not pay for the first one's flood"
            );
        }
    }

    /// The map is itself an attack surface, so it is bounded.
    #[test]
    fn the_source_table_is_bounded_and_evicts_the_longest_idle() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut lim = PerSourceLimiter::new(10.0, 0, 4);
        let t0 = Instant::now();

        // Five distinct sources against a table of four.
        for i in 0..5u8 {
            lim.check_at(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, i)),
                2048,
                t0 + Duration::from_millis(u64::from(i)),
            );
        }
        assert_eq!(lim.tracked(), 4, "the table must stay at its bound");

        // The evicted one is the longest idle — the first seen here.
        let oldest = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0));
        assert!(
            lim.check_at(oldest, 2048, t0 + Duration::from_millis(10))
                .is_allowed(),
            "an evicted source starts fresh, which only forgives a quiet one"
        );
        assert_eq!(lim.tracked(), 4);
    }
}
