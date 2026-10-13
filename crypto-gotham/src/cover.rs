// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::time::Duration;

use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverMode {
    LowLatency,
    Balanced,
    Paranoid,
}

impl CoverMode {
    #[must_use]
    pub fn mean_interval_ms(self) -> u64 {
        match self {
            CoverMode::LowLatency => 15_000,
            CoverMode::Balanced => 10_000,
            CoverMode::Paranoid => 5_000,
        }
    }

    #[must_use]
    pub fn lambda(self) -> f64 {
        1_000.0 / self.mean_interval_ms() as f64
    }

    #[must_use]
    pub fn mean_hop_delay_micros(self) -> u64 {
        match self {
            CoverMode::LowLatency => 100_000,
            CoverMode::Balanced => 500_000,
            CoverMode::Paranoid => 2_000_000,
        }
    }

    #[must_use]
    pub fn battery_adjusted(self, battery_pct: u8, charging: bool) -> Self {
        if charging || battery_pct >= 30 {
            return self;
        }
        match self {
            CoverMode::Paranoid => CoverMode::Balanced,
            CoverMode::Balanced => CoverMode::LowLatency,
            CoverMode::LowLatency => CoverMode::LowLatency,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CoverIntent {
    Real,
    Drop,
    Loop,
}

#[derive(Debug, Copy, Clone)]
pub struct CoverScheduler {
    mode: CoverMode,
    loop_probability: f64,
}

impl CoverScheduler {
    #[must_use]
    pub fn new(mode: CoverMode) -> Self {
        Self {
            mode,
            loop_probability: 0.5,
        }
    }

    #[must_use]
    pub fn with_loop_probability(mut self, prob: f64) -> Self {
        self.loop_probability = prob.clamp(0.0, 1.0);
        self
    }

    #[must_use]
    pub fn mode(&self) -> CoverMode {
        self.mode
    }

    pub fn next_interval<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration {
        let lambda = self.mode.lambda();
        if lambda <= 0.0 {
            return Duration::ZERO;
        }
        let mut u: f64 = rng.gen();
        if u == 0.0 {
            u = f64::MIN_POSITIVE;
        }
        let secs = -u.ln() / lambda;
        let mean_secs = self.mode.mean_interval_ms() as f64 / 1_000.0;
        let max_secs = 10.0 * mean_secs;
        Duration::from_secs_f64(secs.clamp(0.0, max_secs))
    }

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

#[cfg(test)]
mod tests {
    #[test]
    fn the_mode_actually_changes_the_mix_delay() {
        let low = CoverMode::LowLatency.mean_hop_delay_micros();
        let bal = CoverMode::Balanced.mean_hop_delay_micros();
        let par = CoverMode::Paranoid.mean_hop_delay_micros();

        assert!(low < bal && bal < par, "the modes must be ordered");
        assert!(
            low >= 100_000,
            "below ~100 ms the delay is lost in network jitter and buys nothing"
        );
        assert!(
            par <= 30_000_000,
            "a hop delay above the relay clamp is a lie"
        );
    }

    #[test]
    fn end_to_end_latency_stays_usable() {
        let four_hops = |m: CoverMode| m.mean_hop_delay_micros() * 4 / 1_000;
        assert_eq!(four_hops(CoverMode::LowLatency), 400);
        assert_eq!(four_hops(CoverMode::Balanced), 2_000);
        assert_eq!(four_hops(CoverMode::Paranoid), 8_000);
    }

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
