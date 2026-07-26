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
}
