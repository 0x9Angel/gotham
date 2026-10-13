// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::time::Duration;

use rand::Rng;

#[derive(Debug, Clone, Copy)]
pub struct PoissonScheduler {
    lambda: f64,
    mean_micros: u64,
}

impl PoissonScheduler {
    #[must_use]
    pub fn new(mean_delay_micros: u64) -> Self {
        let lambda = if mean_delay_micros == 0 {
            0.0
        } else {
            1_000_000.0 / mean_delay_micros as f64
        };
        Self {
            lambda,
            mean_micros: mean_delay_micros,
        }
    }

    pub fn next_delay<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration {
        if self.lambda == 0.0 {
            return Duration::ZERO;
        }
        let mut u: f64 = rng.gen();
        if u == 0.0 {
            u = f64::MIN_POSITIVE;
        }
        let secs = -u.ln() / self.lambda;
        let max_secs = 100.0 * self.mean_micros as f64 / 1_000_000.0;
        Duration::from_secs_f64(secs.clamp(0.0, max_secs))
    }

    #[must_use]
    pub fn mean_delay_micros(&self) -> u64 {
        self.mean_micros
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn zero_lambda_yields_zero_delay() {
        let s = PoissonScheduler::new(0);
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        for _ in 0..100 {
            assert_eq!(s.next_delay(&mut rng), Duration::ZERO);
        }
    }

    #[test]
    fn sample_mean_close_to_configured() {
        let mean_micros = 20_000u64;
        let s = PoissonScheduler::new(mean_micros);
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
        let n = 10_000;
        let mut total = 0.0f64;
        for _ in 0..n {
            let d = s.next_delay(&mut rng);
            total += d.as_secs_f64() * 1_000_000.0;
        }
        let observed_mean = total / n as f64;
        let pct_err = ((observed_mean - mean_micros as f64).abs() / mean_micros as f64) * 100.0;
        assert!(
            pct_err < 5.0,
            "Poisson sample mean {observed_mean:.0}µs differs from configured {mean_micros}µs by {pct_err:.2}%"
        );
    }

    #[test]
    fn delays_are_nonnegative() {
        let s = PoissonScheduler::new(10_000);
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        for _ in 0..1_000 {
            let _d = s.next_delay(&mut rng);
        }
    }

    #[test]
    fn outliers_are_clamped() {
        let mean = 1_000u64;
        let s = PoissonScheduler::new(mean);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for _ in 0..100_000 {
            let d = s.next_delay(&mut rng);
            assert!(
                d.as_secs_f64() <= 100.0 * mean as f64 / 1_000_000.0 + 1e-6,
                "delay exceeds 100× mean"
            );
        }
    }
}
