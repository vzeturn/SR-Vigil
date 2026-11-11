//! Beaconing detector (`docs/03 §6`, `docs/24`): a pure function over connection timestamps,
//! plus a bounded tracker that feeds it from a stream of new outbound connections.

use std::collections::HashMap;
use std::hash::Hash;

/// Detector thresholds (`[beaconing]` in `config/default-policy.toml`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeaconConfig {
    pub window_ms: u64,
    pub min_samples: usize,
    pub max_cv: f64,
    pub min_interval_ms: f64,
    /// Jittered beacons (sleep ± random %) fail the CV test; they are caught by a robust rule
    /// that needs more samples: interquartile range of the intervals over their median at most
    /// `jitter_max_spread` (a uniform ± j jitter gives about j).
    pub jitter_min_samples: usize,
    pub jitter_max_spread: f64,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            window_ms: 30 * 60 * 1000,
            min_samples: 6,
            max_cv: 0.15,
            min_interval_ms: 5_000.0,
            jitter_min_samples: 12,
            jitter_max_spread: 0.6,
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
    is_regular(&intervals, cfg)
        || (window.len() >= cfg.jitter_min_samples && is_jittered(intervals, cfg))
}

/// Coefficient of variation below `max_cv` (a fixed sleep).
#[allow(clippy::cast_precision_loss)]
fn is_regular(intervals: &[f64], cfg: &BeaconConfig) -> bool {
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < cfg.min_interval_ms {
        return false;
    }
    let var = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    var.sqrt() / mean < cfg.max_cv
}

/// Tight interquartile spread around the median (a randomised sleep). Quartiles ignore the odd
/// missed or extra connection, which would wreck a mean-based test.
fn is_jittered(mut intervals: Vec<f64>, cfg: &BeaconConfig) -> bool {
    intervals.sort_by(f64::total_cmp);
    let n = intervals.len();
    let median = intervals[n / 2];
    median >= cfg.min_interval_ms
        && (intervals[3 * n / 4] - intervals[n / 4]) / median <= cfg.jitter_max_spread
}

/// Flows tracked at once; beyond this the stalest flow is dropped (bounded memory).
pub const MAX_FLOWS: usize = 4096;

#[derive(Debug, Default)]
struct Flow {
    times: Vec<u64>,
    reported: bool,
}

/// New-connection times per flow (`K` = identity, destination, port). Reports a flow once, when
/// it first looks like beaconing; a flow silent for a whole window is forgotten and may report again.
#[derive(Debug)]
pub struct BeaconTracker<K> {
    cfg: BeaconConfig,
    flows: HashMap<K, Flow>,
}

impl<K: Eq + Hash + Clone> BeaconTracker<K> {
    #[must_use]
    pub fn new(cfg: BeaconConfig) -> Self {
        Self {
            cfg,
            flows: HashMap::new(),
        }
    }

    /// Record a new connection of `key` at `at_ms` (non-decreasing). `Some(mean interval ms)` the
    /// first time the flow is beaconing.
    #[allow(clippy::cast_precision_loss)]
    pub fn observe(&mut self, key: K, at_ms: u64) -> Option<u64> {
        self.forget_older_than(at_ms);
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
            self.evict_stalest();
        }
        let window = self.cfg.window_ms;
        let flow = self.flows.entry(key).or_default();
        flow.times.retain(|t| at_ms.saturating_sub(*t) <= window);
        flow.times.push(at_ms);
        if flow.reported || !is_beaconing(&flow.times, &self.cfg) {
            return None;
        }
        flow.reported = true;
        let (first, last) = (flow.times[0], at_ms);
        Some((last - first) / (flow.times.len() as u64 - 1))
    }

    fn forget_older_than(&mut self, now_ms: u64) {
        let window = self.cfg.window_ms;
        self.flows.retain(|_, f| {
            f.times
                .last()
                .is_some_and(|t| now_ms.saturating_sub(*t) <= window)
        });
    }

    fn evict_stalest(&mut self) {
        let stalest = self
            .flows
            .iter()
            .min_by_key(|(_, f)| f.times.last().copied().unwrap_or(0))
            .map(|(k, _)| k.clone());
        if let Some(k) = stalest {
            self.flows.remove(&k);
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
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

    /// `step` ± `jitter` (fraction) from a fixed LCG, so the fixture is reproducible.
    fn jittered(step: u64, jitter: f64, n: usize) -> Vec<u64> {
        let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
        let mut t = 1_000_000;
        (0..n)
            .map(|_| {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let unit = (seed >> 11) as f64 / (1u64 << 53) as f64; // [0, 1)
                t += (step as f64 * (1.0 + jitter * (2.0 * unit - 1.0))) as u64;
                t
            })
            .collect()
    }

    #[test]
    fn jittered_beacon_is_caught_with_enough_samples() {
        let cfg = BeaconConfig::default();
        for jitter in [0.3, 0.5] {
            let t = jittered(60_000, jitter, 13);
            let gaps: Vec<f64> = t.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
            assert!(
                !is_regular(&gaps, &cfg),
                "±{jitter} must need the jitter rule"
            );
            assert!(is_beaconing(&t, &cfg), "±{jitter}");
            assert!(!is_beaconing(&t[..11], &cfg), "±{jitter} needs 12 samples");
        }
    }

    #[test]
    fn jittered_beacon_survives_one_missed_connection() {
        let mut t = jittered(60_000, 0.3, 21);
        t.remove(10);
        assert!(is_beaconing(&t, &BeaconConfig::default()));
    }

    #[test]
    fn bursty_traffic_with_many_samples_is_not() {
        let gaps = [
            3_000, 70_000, 5_000, 200_000, 8_000, 40_000, 6_000, 300_000, 4_000, 90_000, 7_000,
            150_000, 5_000, 60_000,
        ];
        let mut ts = 1_000_000;
        let t: Vec<u64> = gaps
            .iter()
            .map(|g| {
                ts += g;
                ts
            })
            .collect();
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

    #[test]
    fn tracker_reports_a_regular_flow_once() {
        let mut t = BeaconTracker::new(BeaconConfig::default());
        let hits: Vec<_> = at(60_000, 8)
            .into_iter()
            .filter_map(|ts| t.observe(("a.exe", "203.0.113.9", 443), ts))
            .collect();
        assert_eq!(hits, vec![60_000]);
    }

    #[test]
    fn tracker_keeps_flows_apart_and_ignores_irregular_ones() {
        let mut t = BeaconTracker::new(BeaconConfig::default());
        let irregular = [0, 1_000, 90_000, 100_000, 400_000, 410_000, 900_000];
        let mut hits = 0;
        for (i, ts) in at(60_000, 7).into_iter().enumerate() {
            let other = if i % 2 == 0 { "b.exe" } else { "c.exe" };
            hits += usize::from(t.observe((other, "203.0.113.9", 443), ts).is_some());
            let _ = t.observe(("d.exe", "203.0.113.9", 443), 1_000_000 + irregular[i]);
        }
        assert_eq!(hits, 0);
    }

    #[test]
    fn tracker_forgets_silent_flows_and_stays_bounded() {
        let mut t = BeaconTracker::new(BeaconConfig::default());
        for i in 0..(MAX_FLOWS as u64 + 10) {
            let _ = t.observe(i, 1_000 + i);
        }
        assert_eq!(t.len(), MAX_FLOWS);
        let _ = t.observe(u64::MAX, 1_000 + BeaconConfig::default().window_ms * 2);
        assert_eq!(t.len(), 1);
    }
}
