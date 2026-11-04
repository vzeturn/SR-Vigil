//! Beaconing detector (`docs/03 §6`): a pure function over connection timestamps.

/// Detector thresholds (`[beaconing]` in `config/default-policy.toml`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeaconConfig {
    pub window_ms: u64,
    pub min_samples: usize,
    pub max_cv: f64,
    pub min_interval_ms: f64,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            window_ms: 30 * 60 * 1000,
            min_samples: 6,
            max_cv: 0.15,
            min_interval_ms: 5_000.0,
        }
    }
}

/// `timestamps_ms`: new-connection times for one `(identity, dest_ip, dest_port)`, ascending.
/// Only samples within `window_ms` of the newest one are considered.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn is_beaconing(timestamps_ms: &[u64], cfg: &BeaconConfig) -> bool {
    let Some(&newest) = timestamps_ms.last() else {
        return false;
    };
    let window: Vec<u64> = timestamps_ms
        .iter()
        .copied()
        .filter(|t| newest - t <= cfg.window_ms)
        .collect();
    if window.len() < cfg.min_samples {
        return false;
    }
    let intervals: Vec<f64> = window.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < cfg.min_interval_ms {
        return false;
    }
    let var = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    var.sqrt() / mean < cfg.max_cv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(step: u64, n: u64) -> Vec<u64> {
        (0..n).map(|i| 1_000_000 + i * step).collect()
    }

    #[test]
    fn regular_interval_is_beaconing() {
        assert!(is_beaconing(&at(60_000, 6), &BeaconConfig::default()));
    }

    #[test]
    fn too_few_samples_is_not() {
        assert!(!is_beaconing(&at(60_000, 5), &BeaconConfig::default()));
    }

    #[test]
    fn sub_five_second_interval_is_not() {
        assert!(!is_beaconing(&at(1_000, 20), &BeaconConfig::default()));
    }

    #[test]
    fn irregular_traffic_is_not() {
        let t = [0, 1_000, 90_000, 100_000, 400_000, 410_000, 900_000].map(|x| x + 1_000_000);
        assert!(!is_beaconing(&t, &BeaconConfig::default()));
    }

    #[test]
    fn samples_outside_window_are_ignored() {
        let mut t = vec![0, 1_000, 2_000];
        t.extend(at(60_000, 6).iter().map(|x| x + 10_000_000));
        assert!(is_beaconing(&t, &BeaconConfig::default()));
        let sparse: Vec<u64> = (0..6).map(|i| i * 10 * 60_000).collect();
        assert!(
            !is_beaconing(&sparse, &BeaconConfig::default()),
            "only 4 fit in 30 min"
        );
    }
}
