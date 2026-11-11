//! NET-003 unusual upload (`docs/15 §2`): bytes sent and received per (process, remote address)
//! over a fixed window, from the embedded `rules/upload.toml`. Runs on the ETW callback for every
//! send/receive event, so a note is a hash lookup and two additions.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;

use serde::Deserialize;

const SOURCE: &str = include_str!("../../../../rules/upload.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    window_secs: u64,
    min_sent_bytes: u64,
    min_ratio: u64,
}

fn rule() -> &'static Rule {
    static R: OnceLock<Rule> = OnceLock::new();
    R.get_or_init(|| toml::from_str(SOURCE).expect("rules/upload.toml is validated by tests"))
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start_ms: u64,
    sent: u64,
    recv: u64,
    reported: bool,
}

/// Totals sent and received at the moment an upload was reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upload {
    pub sent: u64,
    pub recv: u64,
}

/// Per (pid, address) byte totals. Bounded memory.
#[derive(Debug, Default)]
pub struct UploadTracker {
    windows: HashMap<(u32, IpAddr), Window>,
}

impl UploadTracker {
    /// Keys kept at most; past this, expired windows are dropped (all if none are).
    const MAX_KEYS: usize = 8192;

    /// Record `sent` and `recv` bytes between `pid` and `addr`; `Some` exactly once per window,
    /// when the totals first cross the thresholds.
    pub fn note(
        &mut self,
        pid: u32,
        addr: IpAddr,
        sent: u64,
        recv: u64,
        at_ms: u64,
    ) -> Option<Upload> {
        let r = rule();
        let window = r.window_secs * 1000;
        let expired = |w: &Window| at_ms.saturating_sub(w.start_ms) >= window;
        if self.windows.len() >= Self::MAX_KEYS {
            self.windows.retain(|_, w| !expired(w));
            if self.windows.len() >= Self::MAX_KEYS {
                self.windows.clear();
            }
        }
        let fresh = Window {
            start_ms: at_ms,
            sent: 0,
            recv: 0,
            reported: false,
        };
        let w = self.windows.entry((pid, addr)).or_insert(fresh);
        if expired(w) {
            *w = fresh;
        }
        w.sent = w.sent.saturating_add(sent);
        w.recv = w.recv.saturating_add(recv);
        let unusual = w.sent >= r.min_sent_bytes && w.sent >= w.recv.saturating_mul(r.min_ratio);
        if w.reported || !unusual {
            return None;
        }
        w.reported = true;
        Some(Upload {
            sent: w.sent,
            recv: w.recv,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1_000_000;

    fn addr() -> IpAddr {
        "93.184.216.34".parse().unwrap()
    }

    #[test]
    fn rule_parses() {
        assert!(rule().min_sent_bytes > 0 && rule().min_ratio > 1);
    }

    #[test]
    fn a_one_sided_upload_is_reported_once_per_window() {
        let mut t = UploadTracker::default();
        let step = rule().min_sent_bytes / 5;
        let hits: Vec<_> = (0..10).map(|i| t.note(1, addr(), step, 0, i)).collect();
        assert_eq!(hits.iter().filter(|h| h.is_some()).count(), 1);
        assert_eq!(hits[4].map(|u| u.sent), Some(step * 5));
        assert!(
            t.note(2, addr(), step, 0, 0).is_none(),
            "other pids count separately"
        );
        let later = rule().window_secs * 1000 + 10;
        assert!(
            t.note(1, addr(), step, 0, later).is_none(),
            "totals restart"
        );
        assert!(t.note(1, addr(), step * 4, 0, later).is_some());
    }

    #[test]
    fn a_balanced_exchange_is_not_an_upload() {
        let mut t = UploadTracker::default();
        let sent = rule().min_sent_bytes * 2;
        assert!(t.note(1, addr(), sent, sent / 2, 0).is_none());
        assert!(t.note(1, addr(), MB, 0, 1).is_none());
    }
}
