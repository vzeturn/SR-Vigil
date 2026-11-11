//! Suspicious network behaviour (`docs/24`): spot beaconing from connection metadata only, then
//! ask the user before anything about it reaches the AI advisor. Traffic content is never read.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use vigil_core::analysis::beacon::{BeaconConfig, BeaconTracker};
use vigil_core::audit::AuditKind;
use vigil_core::redact;
use vigil_ipc::proto::{INVALID_PARAMS, NOT_FOUND, RpcError};

use crate::state::{ConnRow, Shared, now};

/// Lower-cased image path, remote address, remote port.
type FlowKey = (String, String, u16);

#[derive(Debug, Clone)]
struct Threat {
    path: String,
    identity_id: Option<i64>,
    dest_ip: String,
    dest_port: u16,
    interval_secs: u64,
    detected_at: String,
}

impl Threat {
    fn to_json(&self, id: &str, ai_available: bool) -> Value {
        json!({
            "threat_id": id, "kind": "beaconing", "path": self.path,
            "identity_id": self.identity_id.map(|i| i.to_string()),
            "dest_ip": self.dest_ip, "dest_port": self.dest_port,
            "interval_secs": self.interval_secs, "detected_at": self.detected_at,
            "ai_available": ai_available,
        })
    }
}

/// Detection state; lives in [`Shared`].
pub(crate) struct Threats {
    tracker: BeaconTracker<FlowKey>,
    /// Programs seen beaconing this run (feeds BEH-002 on re-evaluation).
    flagged: HashSet<String>,
    /// Programs whose network pattern the user agreed to share with the advisor.
    consented: HashMap<String, redact::Dest>,
    pending: HashMap<String, Threat>,
    /// ETW delivers every connect, short ones included; the table poll then stops feeding the
    /// tracker so no connection is counted twice.
    etw: bool,
}

impl Default for Threats {
    fn default() -> Self {
        Self {
            tracker: BeaconTracker::new(BeaconConfig::default()),
            flagged: HashSet::new(),
            consented: HashMap::new(),
            pending: HashMap::new(),
            etw: false,
        }
    }
}

/// A routable Internet address: not loopback, private, link-local, multicast or unspecified.
pub(crate) fn is_public(addr: &str) -> bool {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast())
        }
        Ok(IpAddr::V6(v6)) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local())
        }
        Err(_) => false,
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn lock(t: &std::sync::Mutex<Threats>) -> std::sync::MutexGuard<'_, Threats> {
    t.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Shared {
    /// Feed brand-new connections to the beacon tracker (called by `sync_connections`). Ignored
    /// once the ETW feed is live ([`Self::use_etw_connects`]).
    pub(crate) fn track_beacons(&self, fresh: &[ConnRow]) {
        self.track_beacons_at(fresh, now_ms());
    }

    /// [`Self::track_beacons`] with an explicit clock (milliseconds since the Unix epoch).
    pub fn track_beacons_at(&self, fresh: &[ConnRow], at_ms: u64) {
        if lock(&self.threats).etw {
            return;
        }
        let outbound: Vec<(u32, &str, u16)> = fresh
            .iter()
            .filter(|c| c.direction == "outbound")
            .filter_map(|c| Some((c.pid, c.remote_addr.as_deref()?, c.remote_port?)))
            .collect();
        for (pid, ip, port) in outbound {
            self.track_flow(pid, ip, port, at_ms);
        }
    }

    /// Feed the tracker from ETW connect events (`true`) or from the table poll (`false`,
    /// the fallback when no trace runs), `docs/24 §3`.
    pub fn use_etw_connects(&self, on: bool) {
        lock(&self.threats).etw = on;
    }

    /// One outbound connect reported by ETW, short-lived ones included.
    pub(crate) fn track_connect(&self, pid: u32, dest: IpAddr, port: u16) {
        self.track_connect_at(pid, dest, port, now_ms());
    }

    /// [`Self::track_connect`] with an explicit clock.
    pub fn track_connect_at(&self, pid: u32, dest: IpAddr, port: u16, at_ms: u64) {
        self.track_flow(pid, &dest.to_string(), port, at_ms);
    }

    fn track_flow(&self, pid: u32, ip: &str, port: u16, at_ms: u64) {
        if !is_public(ip) {
            return;
        }
        let Some(row) = self.row_by_pid(pid) else {
            return;
        };
        let Some(path) = row.path.as_deref() else {
            return;
        };
        let key = (path.to_ascii_lowercase(), ip.to_owned(), port);
        let hit = lock(&self.threats).tracker.observe(key, at_ms);
        if let Some(every) = hit {
            let id = row.identity_id.as_deref().and_then(|i| i.parse().ok());
            self.on_beacon(path, id, row.verdict.as_deref(), (ip, port), every / 1000);
        }
    }

    fn on_beacon(
        &self,
        path: &str,
        identity_id: Option<i64>,
        verdict: Option<&str>,
        (ip, port): (&str, u16),
        interval_secs: u64,
    ) {
        if !lock(&self.threats)
            .flagged
            .insert(path.to_ascii_lowercase())
        {
            return;
        }
        self.queue_rejudge(path);
        self.audit(
            "service",
            AuditKind::Verdict,
            Some(path),
            &json!({ "signal": "BEH-002", "dest_ip": ip, "dest_port": port, "interval_secs": interval_secs }),
        );
        if verdict == Some("safe") {
            return;
        }
        let threat = Threat {
            path: path.to_owned(),
            identity_id,
            dest_ip: ip.to_owned(),
            dest_port: port,
            interval_secs,
            detected_at: now(),
        };
        let id = uuid::Uuid::new_v4().to_string();
        let payload = threat.to_json(&id, self.ai_settings().active());
        lock(&self.threats).pending.insert(id, threat);
        self.emit("enforcement", "event.threat_detected", payload);
    }

    /// Whether `path` has been seen beaconing during this run.
    #[must_use]
    pub fn is_beaconing(&self, path: &str) -> bool {
        lock(&self.threats)
            .flagged
            .contains(&path.to_ascii_lowercase())
    }

    /// The destination the user agreed to share for `path`, if any (consent gate for the advisor).
    pub(crate) fn consented_dest(&self, path: &str) -> Option<redact::Dest> {
        lock(&self.threats)
            .consented
            .get(&path.to_ascii_lowercase())
            .cloned()
    }

    /// `threat.list`: prompts not yet answered.
    #[must_use]
    pub fn threat_list(&self) -> Value {
        let ai = self.ai_settings().active();
        let g = lock(&self.threats);
        let items: Vec<Value> = g.pending.iter().map(|(id, t)| t.to_json(id, ai)).collect();
        json!({ "threats": items })
    }

    /// `threat.answer`: `analyze` (consent to AI analysis), `block` or `dismiss`.
    pub async fn threat_answer(&self, params: &Value) -> Result<Value, RpcError> {
        let bad = || RpcError::new(INVALID_PARAMS, "threat_id and action are required");
        let id = params["threat_id"].as_str().ok_or_else(bad)?;
        let action = params["action"].as_str().ok_or_else(bad)?;
        if !matches!(action, "analyze" | "block" | "dismiss") {
            return Err(bad());
        }
        let t = lock(&self.threats)
            .pending
            .get(id)
            .cloned()
            .ok_or_else(|| RpcError::new(NOT_FOUND, "no such prompt (already answered)"))?;
        self.audit(
            "user",
            AuditKind::Decision,
            Some(&t.path),
            &json!({ "threat": "beaconing", "answer": action }),
        );
        let out = match action {
            "analyze" => self.analyze_threat(&t).await?,
            "block" => self.block_threat(&t)?,
            _ => json!({}),
        };
        // After an analysis the prompt stays open: the user still chooses block or ignore.
        if action != "analyze" {
            lock(&self.threats).pending.remove(id);
        }
        Ok(out)
    }

    async fn analyze_threat(&self, t: &Threat) -> Result<Value, RpcError> {
        let exe = t
            .identity_id
            .ok_or_else(|| RpcError::new(NOT_FOUND, "program not evaluated yet"))?;
        lock(&self.threats).consented.insert(
            t.path.to_ascii_lowercase(),
            redact::Dest {
                ip: Some(t.dest_ip.clone()),
                dns: None,
                port: t.dest_port,
            },
        );
        self.ai_explain(&json!({ "identity_id": exe.to_string() }))
            .await
    }

    fn block_threat(&self, t: &Threat) -> Result<Value, RpcError> {
        let exe = t
            .identity_id
            .ok_or_else(|| RpcError::new(NOT_FOUND, "program not evaluated yet"))?;
        self.submit_decision(&json!({
            "action": "block", "scope": "forever", "apply_to": "file",
            "identity_id": exe.to_string(), "note": "Regular calls to one Internet address (beaconing)",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::is_public;

    #[test]
    fn only_routable_addresses_are_public() {
        for a in ["203.0.113.9", "8.8.8.8", "2001:4860:4860::8888"] {
            assert!(is_public(a), "{a}");
        }
        for a in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "x",
        ] {
            assert!(!is_public(a), "{a}");
        }
    }
}
