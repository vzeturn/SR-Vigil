//! Process starts from ETW Kernel-Process, handed to the observer so images that exit before the
//! next snapshot are still judged (`docs/15 §3`). Bounded: the oldest starts are dropped first.

use crate::state::Shared;

/// Starts kept between two observer ticks at most.
const MAX_STARTED: usize = 1024;

impl Shared {
    /// ETW reported `pid` (child of `parent`) starting `image` (a drive path).
    pub fn note_process_start(&self, pid: u32, parent: u32, image: String) {
        let mut q = self
            .started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if q.len() >= MAX_STARTED {
            q.pop_front();
        }
        q.push_back((pid, parent, image));
    }

    /// Starts since the last call, oldest first.
    #[must_use]
    pub fn take_started(&self) -> Vec<(u32, u32, String)> {
        self.started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::state::{Options, Shared};

    #[test]
    fn the_queue_keeps_the_newest_starts() {
        let s = Shared::new(Options {
            store: None,
            rules: serde_json::json!([]),
            trust: vec![],
            rule_pack_version: "1".into(),
            network_critical: vec![],
            never_kill: vec![],
        });
        for pid in 0..u32::try_from(super::MAX_STARTED).unwrap() + 5 {
            s.note_process_start(pid, 0, String::new());
        }
        let got = s.take_started();
        assert_eq!(got.len(), super::MAX_STARTED);
        assert_eq!(got[0].0, 5);
    }
}
