//! Runaway browser tabs (`docs/19 §4`): a tab burning a whole core for minutes is reported, and in
//! `enforce` mode stopped once it has stayed hot for a quarter of an hour.

use std::collections::HashMap;

use serde_json::json;
use vigil_core::profile::{HotStep, HotTab};

use crate::state::{ProcRow, Shared};

/// Tabs are sampled at most this often; shorter windows make the share too noisy.
const SAMPLE_MS: u64 = 10_000;

/// CPU history per tab process, keyed by pid and start time so a reused pid starts afresh.
#[derive(Default)]
pub struct HotTabs {
    last_ms: Option<u64>,
    tabs: HashMap<(u32, String), HotTab>,
}

impl Shared {
    /// Sample every tab's CPU time and act on the result. Returns the number of tabs stopped.
    pub fn tab_cpu_scan(&self, now_ms: u64) -> usize {
        let Some(control) = self.control() else {
            return 0;
        };
        let enforce = self.enforcing();
        let tabs: Vec<ProcRow> = self.all_rows().into_iter().filter(|r| r.tab).collect();
        let due = {
            let mut g = self
                .hot_tabs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if g.last_ms
                .is_some_and(|l| now_ms.saturating_sub(l) < SAMPLE_MS)
            {
                return 0;
            }
            g.last_ms = Some(now_ms);
            let mut seen = HashMap::with_capacity(tabs.len());
            let mut due = vec![];
            for tab in &tabs {
                let key = (tab.pid, tab.start_time.clone());
                let Some(ticks) = control.cpu_ticks(tab.pid) else {
                    continue;
                };
                let (next, step) = match g.tabs.get(&key) {
                    Some(h) => h.step(ticks, now_ms, enforce),
                    None => (HotTab::start(ticks, now_ms), HotStep::Quiet),
                };
                if step != HotStep::Quiet {
                    due.push((tab.clone(), step, next.hot_minutes()));
                }
                seen.insert(key, next);
            }
            g.tabs = seen;
            due
        };
        due.into_iter()
            .filter(|(tab, step, minutes)| self.act_on_hot_tab(tab, *step, *minutes))
            .count()
    }

    /// Report or stop one hot tab; `true` when it was stopped.
    fn act_on_hot_tab(&self, tab: &ProcRow, step: HotStep, minutes: u64) -> bool {
        let stopped = step == HotStep::Stop
            && self
                .kill_process(
                    &json!({ "pid": tab.pid, "start_time": tab.start_time, "tree": false, "block": false }),
                    "service",
                )
                .ok()
                .and_then(|v| v["ok"].as_bool())
                .unwrap_or(false);
        if step == HotStep::Stop && !stopped {
            return false;
        }
        tracing::warn!(pid = tab.pid, minutes, stopped, "browser tab running hot");
        self.emit(
            "enforcement",
            "event.tab_alert",
            json!({ "reason": "high_cpu", "action": if stopped { "stopped" } else { "warned" },
                    "browser": tab.name, "minutes": minutes }),
        );
        stopped
    }
}
