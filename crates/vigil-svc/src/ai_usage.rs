//! What the AI did and what it cost: a small per-day ledger kept in the settings table, plus the
//! periodic digest (docs/06 §11). Counters only; no payloads or identities are stored here.

use std::collections::BTreeMap;
use std::time::Duration as StdDuration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use vigil_store::ai as store;

use crate::state::Shared;

const LEDGER: &str = "ai.usage";
const DIGEST_AT: &str = "ai.digest_at";
const KEEP_DAYS: usize = 62;
/// Digest cadence; checked hourly so a sleeping laptop still gets it on wake.
pub const DIGEST_EVERY: Duration = Duration::hours(24);
pub const DIGEST_CHECK: StdDuration = StdDuration::from_secs(3600);
/// Rough list price per million tokens (input, output) in micro-dollars, for the "about $" readout.
const PRICE_IN_MICRO: u64 = 1_000_000;
const PRICE_OUT_MICRO: u64 = 5_000_000;

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Day {
    pub calls: u64,
    pub cached: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub allow: u64,
    pub block: u64,
    pub kill: u64,
    pub left_to_user: u64,
}

impl Day {
    fn add(&mut self, o: &Self) {
        self.calls += o.calls;
        self.cached += o.cached;
        self.tokens_in += o.tokens_in;
        self.tokens_out += o.tokens_out;
        self.allow += o.allow;
        self.block += o.block;
        self.kill += o.kill;
        self.left_to_user += o.left_to_user;
    }

    #[must_use]
    pub fn decisions(&self) -> u64 {
        self.allow + self.block + self.kill
    }

    /// Approximate spend in US dollars.
    #[allow(clippy::cast_precision_loss)] // display estimate only
    #[must_use]
    pub fn cost_usd(&self) -> f64 {
        (self.tokens_in * PRICE_IN_MICRO + self.tokens_out * PRICE_OUT_MICRO) as f64 / 1e12
    }

    fn to_json(self) -> Value {
        json!({
            "assessed": self.calls + self.cached, "calls": self.calls, "cached": self.cached,
            "tokens_in": self.tokens_in, "tokens_out": self.tokens_out,
            "allowed": self.allow, "blocked": self.block, "killed": self.kill,
            "left_to_user": self.left_to_user, "cost_usd": self.cost_usd(),
        })
    }
}

type Ledger = BTreeMap<String, Day>;

fn day_key(t: OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
}

impl Shared {
    fn ledger(&self) -> Ledger {
        self.with_store(|c| store::setting_get(c, LEDGER))
            .and_then(Result::ok)
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Add `f`'s changes to today's row (serialised by the store lock).
    pub(crate) fn ai_tally(&self, f: impl FnOnce(&mut Day)) {
        let mut l = self.ledger();
        f(l.entry(day_key(OffsetDateTime::now_utc())).or_default());
        while l.len() > KEEP_DAYS {
            l.pop_first();
        }
        if let Ok(b) = serde_json::to_vec(&l) {
            self.with_store(|c| store::setting_put(c, LEDGER, &b));
        }
    }

    /// Sum of the last `days` days, today included.
    fn ai_window(&self, days: i64) -> Day {
        let now = OffsetDateTime::now_utc();
        let from = day_key(now - Duration::days(days - 1));
        let mut sum = Day::default();
        for (_, d) in self.ledger().range(from..) {
            sum.add(d);
        }
        sum
    }

    /// `ai.activity`: today, last 7 days and last 30 days.
    pub fn ai_activity(&self) -> Value {
        json!({
            "today": self.ai_window(1).to_json(),
            "week": self.ai_window(7).to_json(),
            "month": self.ai_window(30).to_json(),
        })
    }

    /// Emit `event.ai_digest` for the last 24 h when there was activity and none was sent today.
    pub fn ai_digest_if_due(&self) {
        let now = OffsetDateTime::now_utc();
        let last = self
            .with_store(|c| store::setting_get(c, DIGEST_AT))
            .and_then(Result::ok)
            .flatten()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| {
                OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339).ok()
            });
        if last.is_some_and(|t| now - t < DIGEST_EVERY) {
            return;
        }
        let d = self.ai_window(1);
        if d.calls + d.cached == 0 {
            return;
        }
        if let Ok(s) = now.format(&time::format_description::well_known::Rfc3339) {
            self.with_store(|c| store::setting_put(c, DIGEST_AT, s.as_bytes()));
        }
        self.emit("ai", "event.ai_digest", d.to_json());
    }
}

/// Background loop for the digest.
pub async fn digest_loop(shared: std::sync::Arc<Shared>) {
    let mut t = tokio::time::interval(DIGEST_CHECK);
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        t.tick().await;
        shared.ai_digest_if_due();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_is_per_million_tokens() {
        let d = Day {
            tokens_in: 1_000_000,
            tokens_out: 1_000_000,
            ..Day::default()
        };
        assert!((d.cost_usd() - 6.0).abs() < 1e-9);
    }
}
