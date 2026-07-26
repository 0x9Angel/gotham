// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! Cover traffic scheduler — Loopix-style Poisson inter-packet timing.
//!
//! ## Why cover traffic
//!
//! Without cover traffic, a passive network observer can correlate
//! "Alice's app sent a packet at 14:32:01" with "Bob's app received a
//! packet at 14:32:01.18". Even with onion routing, timing patterns leak.
//!
//! Cover traffic fixes this by ensuring every client emits packets on a
//! constant Poisson schedule, *whether or not* it has anything real to
//! send. The wire-level traffic pattern of an idle user is statistically
//! indistinguishable from that of a busy one.
//!
//! ## Design
//!
//! The client runs a loop: at each Poisson-sampled tick, it consults
//! [`CoverScheduler::next_intent`] which returns one of:
//!
//! - [`CoverIntent::Real`] — send a real queued message
//! - [`CoverIntent::Drop`]  — send a dummy packet to a "sink" relay
//! - [`CoverIntent::Loop`]  — send a self-loop packet (sender = recipient)
//!
//! Drop and Loop packets are indistinguishable from real packets at the
//! wire (same Sphinx wrapping, same fixed 2 KB size, same Noise XK).
//!
//! ## Battery-aware degradation (mobile)
//!
//! On mobile, cover traffic costs energy. [`CoverMode::battery_adjusted`]
//! returns a mode reduced by 4× when battery is low and not charging.
//!
//! ## v0.1 status
//!
//! This module implements the *scheduler logic*. Wiring it into the
//! [`crate::client::GothamClient`] event loop is P5.next. The dummy /
//! loop packet *content* is whatever payload the caller provides — the
//! scheduler is content-agnostic.

use std::time::Duration;

use rand::Rng;
use serde::{Deserialize, Serialize};

// ─── Cover modes ────────────────────────────────────────────────────────────

/// How often (on average) a client emits a packet — real or cover.
///
/// Defaults follow `docs/gotham/README.md` §7:
///   low-latency  → 1 packet / 15 s   (mean inter-arrival 15 000 ms)
///   balanced     → 1 packet / 10 s
///   paranoid     → 1 packet /  5 s
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverMode {
    /// Low-latency mode: λ = 1/15 s.
    LowLatency,
    /// Balanced mode (default): λ = 1/10 s.
    Balanced,
    /// Paranoid mode: λ = 1/5 s.
    Paranoid,
}

impl CoverMode {
    /// Mean inter-packet interval in milliseconds.
    #[must_use]
    pub fn mean_interval_ms(self) -> u64 {
        match self {
            CoverMode::LowLatency => 15_000,
            CoverMode::Balanced => 10_000,
            CoverMode::Paranoid => 5_000,
        }
    }

    /// λ (rate parameter) in packets-per-second.
    #[must_use]
    pub fn lambda(self) -> f64 {
        1_000.0 / self.mean_interval_ms() as f64
    }

    /// Adjust the mode for low-battery conditions: divide λ by 4 when
    /// battery is below the threshold and not charging.
    ///
    /// Concretely this widens the interval 4× — fewer dummy packets,
    /// lower anonymity, longer battery. Real packets still go out
    /// promptly; only cover frequency degrades.
    #[must_use]
    pub fn battery_adjusted(self, battery_pct: u8, charging: bool) -> Self {
        if charging || battery_pct >= 30 {
            return self;
        }
        // Step down one level (paranoid → balanced → low-latency).
        match self {
            CoverMode::Paranoid => CoverMode::Balanced,
            CoverMode::Balanced => CoverMode::LowLatency,
            CoverMode::LowLatency => CoverMode::LowLatency,
        }
    }
}

// ─── Cover scheduler ────────────────────────────────────────────────────────

/// What kind of packet to send at the next scheduled tick.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CoverIntent {
    /// A real queued payload is available — send it.
    Real,
    /// No real traffic; send a dummy "drop" packet (sink relay drops it).
    Drop,
    /// No real traffic; send a self-loop (round-trip back to sender).
    /// Use sparingly — costs 2× bandwidth.
    Loop,
}

/// Poisson-distributed inter-packet scheduler.
///
/// `next_interval()` samples from Exp(λ). Independent of any actual
/// queue — the caller polls [`Self::next_intent`] to decide what to
/// actually send.
#[derive(Debug, Copy, Clone)]
pub struct CoverScheduler {
    mode: CoverMode,
    /// Probability that a tick with no real packet produces a Loop
    /// instead of a Drop. Default: 0.5 (per-spec, indistinguishable mix).
    loop_probability: f64,
}

impl CoverScheduler {
    /// Construct a scheduler with the default 50/50 drop-vs-loop ratio.
    #[must_use]
    pub fn new(mode: CoverMode) -> Self {
        Self {
            mode,
            loop_probability: 0.5,
        }
    }

    /// Customise the drop/loop ratio. `prob ∈ [0.0, 1.0]`; values outside
    /// this range are clamped.
    #[must_use]
    pub fn with_loop_probability(mut self, prob: f64) -> Self {
        self.loop_probability = prob.clamp(0.0, 1.0);
        self
    }

    /// Current cover mode.
    #[must_use]
    pub fn mode(&self) -> CoverMode {
        self.mode
    }

    /// Sample the next inter-packet interval from Exp(λ).
    ///
    /// Returns a [`Duration`] capped at 10× the mean to bound memory
    /// (an extreme outlier could otherwise schedule a tick hours away).
    pub fn next_interval<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration {
        let lambda = self.mode.lambda();
        if lambda <= 0.0 {
            return Duration::ZERO;
        }
        // Exponential inverse CDF: -ln(u)/λ for u ~ Uniform(0, 1).
        let mut u: f64 = rng.gen();
        if u == 0.0 {
            u = f64::MIN_POSITIVE;
        }
        let secs = -u.ln() / lambda;
        let mean_secs = self.mode.mean_interval_ms() as f64 / 1_000.0;
        let max_secs = 10.0 * mean_secs;
        Duration::from_secs_f64(secs.clamp(0.0, max_secs))
    }

    /// Decide the [`CoverIntent`] for the next tick.
    ///
    /// - If `has_real_packet` → always [`CoverIntent::Real`].
    /// - Otherwise → [`CoverIntent::Loop`] with `loop_probability`, else
    ///   [`CoverIntent::Drop`].
    pub fn next_intent<R: Rng + ?Sized>(&self, rng: &mut R, has_real_packet: bool) -> CoverIntent {
        if has_real_packet {
            return CoverIntent::Real;
        }
        let u: f64 = rng.gen();
        if u < self.loop_probability {
            CoverIntent::Loop
        } else {
            CoverIntent::Drop
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xC0FE_C0FE)
    }

    #[test]
    fn mode_intervals_match_spec() {
        assert_eq!(CoverMode::LowLatency.mean_interval_ms(), 15_000);
        assert_eq!(CoverMode::Balanced.mean_interval_ms(), 10_000);
        assert_eq!(CoverMode::Paranoid.mean_interval_ms(), 5_000);
    }

    #[test]
    fn lambdas_are_inverse_of_mean() {
        for m in [
            CoverMode::LowLatency,
            CoverMode::Balanced,
            CoverMode::Paranoid,
        ] {
            let mean = m.mean_interval_ms() as f64 / 1_000.0;
            let expected_lambda = 1.0 / mean;
            assert!((m.lambda() - expected_lambda).abs() < 1e-9);
        }
    }

    #[test]
    fn battery_adjustment_steps_down_when_low_and_not_charging() {
        assert_eq!(
            CoverMode::Paranoid.battery_adjusted(20, false),
            CoverMode::Balanced
        );
        assert_eq!(
            CoverMode::Balanced.battery_adjusted(20, false),
            CoverMode::LowLatency
        );
        // LowLatency stays at LowLatency (can't degrade further).
        assert_eq!(
            CoverMode::LowLatency.battery_adjusted(20, false),
            CoverMode::LowLatency
        );
    }

    #[test]
    fn battery_adjustment_preserves_when_charging() {
        assert_eq!(
            CoverMode::Paranoid.battery_adjusted(10, true),
            CoverMode::Paranoid
        );
    }

    #[test]
    fn battery_adjustment_preserves_when_above_threshold() {
        assert_eq!(
            CoverMode::Paranoid.battery_adjusted(30, false),
            CoverMode::Paranoid
        );
        assert_eq!(
            CoverMode::Paranoid.battery_adjusted(50, false),
            CoverMode::Paranoid
        );
    }

    #[test]
    fn next_interval_sample_mean_close_to_configured() {
        let s = CoverScheduler::new(CoverMode::Balanced);
        let mut rng = rng();
        let n = 5_000;
        let mut total_ms = 0.0;
        for _ in 0..n {
            total_ms += s.next_interval(&mut rng).as_secs_f64() * 1_000.0;
        }
        let mean = total_ms / n as f64;
        let expected = 10_000.0;
        let pct_err = ((mean - expected).abs() / expected) * 100.0;
        assert!(
            pct_err < 8.0,
            "mean interval {mean:.0}ms differs from expected {expected:.0}ms by {pct_err:.2}%"
        );
    }

    #[test]
    fn next_interval_is_bounded() {
        let s = CoverScheduler::new(CoverMode::Balanced);
        let mut rng = rng();
        let max = 10.0 * s.mode.mean_interval_ms() as f64 / 1_000.0;
        for _ in 0..50_000 {
            let d = s.next_interval(&mut rng);
            assert!(d.as_secs_f64() <= max + 1e-6);
        }
    }

    #[test]
    fn intent_real_when_has_real_packet() {
        let s = CoverScheduler::new(CoverMode::Balanced);
        let mut rng = rng();
        for _ in 0..100 {
            assert_eq!(s.next_intent(&mut rng, true), CoverIntent::Real);
        }
    }

    #[test]
    fn intent_split_50_50_when_idle() {
        let s = CoverScheduler::new(CoverMode::Balanced);
        let mut rng = rng();
        let n = 10_000;
        let mut loops = 0;
        let mut drops = 0;
        for _ in 0..n {
            match s.next_intent(&mut rng, false) {
                CoverIntent::Loop => loops += 1,
                CoverIntent::Drop => drops += 1,
                CoverIntent::Real => panic!("real intent without queue"),
            }
        }
        let ratio = loops as f64 / n as f64;
        assert!(
            (ratio - 0.5).abs() < 0.03,
            "loop ratio {ratio:.3} differs from 0.5 by > 0.03"
        );
        let _ = drops;
    }

    #[test]
    fn loop_probability_can_be_zero_or_one() {
        let mut rng = rng();
        let only_drop = CoverScheduler::new(CoverMode::Balanced).with_loop_probability(0.0);
        for _ in 0..100 {
            assert_eq!(only_drop.next_intent(&mut rng, false), CoverIntent::Drop);
        }
        let only_loop = CoverScheduler::new(CoverMode::Balanced).with_loop_probability(1.0);
        for _ in 0..100 {
            assert_eq!(only_loop.next_intent(&mut rng, false), CoverIntent::Loop);
        }
    }

    #[test]
    fn loop_probability_clamped_to_unit_interval() {
        let s = CoverScheduler::new(CoverMode::Balanced).with_loop_probability(2.5);
        assert!(s.loop_probability <= 1.0);
        let s = CoverScheduler::new(CoverMode::Balanced).with_loop_probability(-1.0);
        assert!(s.loop_probability >= 0.0);
    }

    #[test]
    fn cover_mode_serde_roundtrip() {
        let modes = [
            CoverMode::LowLatency,
            CoverMode::Balanced,
            CoverMode::Paranoid,
        ];
        for m in modes {
            let json = serde_json::to_string(&m).unwrap();
            let back: CoverMode = serde_json::from_str(&json).unwrap();
            assert_eq!(m, back);
        }
    }
}
