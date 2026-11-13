//! Enforcement glue between decisions and the platform filter engine (docs/04 §1-§7).
//!
//! The service talks to a [`FilterEngine`]; `vigil-win` provides the WFP implementation and tests
//! provide a fake. All policy (what to permit/deny, mode transitions) lives here and is portable.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::mpsc::UnboundedSender;
use vigil_core::audit::AuditKind;
use vigil_ipc::proto::{ENFORCEMENT_OFF, INVALID_STATE, RpcError};
use vigil_store::decisions::{self, Action, Decision, DestClass, NewPending};

use crate::state::Shared;

/// How long an "allow once" permit stays in place.
const ONCE_TTL: Duration = Duration::from_secs(60);
/// Cap on new pending items per minute (flood protection).
const PENDING_PER_MINUTE: usize = 20;

/// A blocked connection reported by the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropInfo {
    pub app_path: String,
    pub remote_addr: String,
    pub remote_port: u16,
}

/// Platform filter engine. Implementations must be idempotent: applying the same set twice is a no-op.
pub trait FilterEngine: Send + Sync {
    /// Make the persistent explicit denies exactly `denies`; with `inbound` each deny also refuses
    /// incoming connections (FR-017, `enforcement.block_inbound`).
    fn set_denies(&self, denies: &[PathBuf], inbound: bool) -> Result<(), String>;
    /// Make the persistent per-service outbound denies exactly `services` (`(name, service SID)`,
    /// FR-021). Engines without service filtering ignore it.
    fn set_service_denies(&self, _services: &[(String, String)]) -> Result<(), String> {
        Ok(())
    }
    /// Install loopback + `permits`, then the catch-all block; returns permit paths that could not
    /// be resolved (missing files). Permits no longer listed are removed.
    fn arm(&self, permits: &[PathBuf]) -> Result<Vec<PathBuf>, String>;
    /// Remove the catch-all and every permit (persistent denies stay).
    fn disarm(&self) -> Result<(), String>;
    /// Remove every Vigil filter, best effort; returns how many were removed.
    fn panic(&self) -> usize;
    /// Start forwarding blocked connections to `tx`.
    fn watch_drops(&self, tx: UnboundedSender<DropInfo>) -> Result<(), String>;
}

/// What the filter engine should hold for the current decisions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Desired {
    pub permits: BTreeSet<PathBuf>,
    pub denies: BTreeSet<PathBuf>,
    /// Denies also refuse incoming connections.
    pub inbound: bool,
    /// Services whose outbound network is blocked: `(name, service SID)` (FR-021).
    pub services: BTreeSet<(String, String)>,
}

/// Pure policy: a deny always beats a permit for the same path (case-insensitive).
#[must_use]
pub fn resolve(
    permits: impl IntoIterator<Item = String>,
    denies: impl IntoIterator<Item = String>,
) -> Desired {
    let denies: BTreeSet<String> = denies.into_iter().collect();
    let lower: BTreeSet<String> = denies.iter().map(|d| d.to_lowercase()).collect();
    Desired {
        permits: permits
            .into_iter()
            .filter(|p| !lower.contains(&p.to_lowercase()))
            .map(PathBuf::from)
            .collect(),
        denies: denies.into_iter().map(PathBuf::from).collect(),
        inbound: false,
        services: BTreeSet::new(),
    }
}

/// Expand `%VAR%` and single-segment `*` wildcards of a canonical system path into existing files.
#[must_use]
pub fn expand_system_path(pattern: &str) -> Vec<PathBuf> {
    let mut expanded = String::new();
    let mut rest = pattern;
    while let Some(start) = rest.find('%') {
        expanded.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        let Some(end) = tail.find('%') else {
            expanded.push_str(&rest[start..]);
            rest = "";
            break;
        };
        match std::env::var(&tail[..end]) {
            Ok(v) => expanded.push_str(&v),
            Err(_) => return Vec::new(),
        }
        rest = &tail[end + 1..];
    }
    expanded.push_str(rest);
    let mut current = vec![PathBuf::new()];
    for seg in expanded.split(['\\', '/']) {
        if seg.is_empty() {
            continue;
        }
        let mut next = Vec::new();
        for base in &current {
            if seg == "*" {
                if let Ok(rd) = std::fs::read_dir(base) {
                    next.extend(rd.flatten().map(|e| e.path()));
                }
            } else if base.as_os_str().is_empty() {
                next.push(PathBuf::from(format!("{seg}\\")));
            } else {
                next.push(base.join(seg));
            }
        }
        current = next;
    }
    current.into_iter().filter(|p| p.is_file()).collect()
}

fn classify(addr: &str) -> DestClass {
    match addr.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => DestClass::Loopback,
        Ok(IpAddr::V4(v4)) if v4.is_private() || v4.is_link_local() => DestClass::Private,
        Ok(IpAddr::V6(v6)) if v6.is_unique_local() || v6.is_unicast_link_local() => {
            DestClass::Private
        }
        _ => DestClass::Public,
    }
}

fn rpc_off(msg: &str) -> RpcError {
    RpcError::new(ENFORCEMENT_OFF, msg)
}

impl Shared {
    /// Attach (or clear) the filter engine. Without one, `enforce` cannot be active: a persisted
    /// `enforce` mode falls back to `observe`.
    pub fn attach_engine(&self, engine: Option<Arc<dyn FilterEngine>>) {
        let present = engine.is_some();
        *self.engine_slot() = engine;
        if !present && self.mode_and_health().0 == "enforce" {
            self.force_mode("observe", "no filter engine");
        }
        if present {
            if let Err(e) = self.resync_enforcement() {
                tracing::error!(error = %e, "initial enforcement sync failed");
                self.fail_enforcement(&e);
            }
        }
    }

    fn engine(&self) -> Option<Arc<dyn FilterEngine>> {
        self.engine_slot().clone()
    }

    /// Paths that must stay permitted for the machine to remain usable (docs/04 bootstrap list).
    fn bootstrap_permits(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for entry in self.network_critical_patterns() {
            out.extend(
                expand_system_path(&entry)
                    .into_iter()
                    .map(|p| p.display().to_string()),
            );
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                for name in ["vigil-svc.exe", "vigilctl.exe", "vigil-ui.exe", "Vigil.exe"] {
                    let p = dir.join(name);
                    if p.is_file() {
                        out.push(p.display().to_string());
                    }
                }
            }
        }
        out
    }

    /// Compute the filters the current decisions call for.
    pub fn desired(&self, armed: bool) -> Result<Desired, String> {
        let now = OffsetDateTime::now_utc();
        let (mut permits, mut denies) = (Vec::new(), Vec::new());
        let res = self.with_store(|c| -> Result<(), vigil_store::StoreError> {
            for d in decisions::list_active(c, now)? {
                let paths = decision_paths(c, &d)?;
                match d.action {
                    Action::Allow => permits.extend(paths),
                    Action::Block | Action::Kill => denies.extend(paths),
                }
            }
            if armed {
                permits.extend(vigil_store::repo::paths_with_verdict(c, "safe")?);
            }
            Ok(())
        });
        if let Some(r) = res {
            r.map_err(|e| e.to_string())?;
        }
        if armed {
            permits.extend(self.bootstrap_permits());
            permits.extend(self.live_once_permits());
        }
        Ok(Desired {
            inbound: self.settings()["enforcement"]["block_inbound"] == true,
            services: self
                .service_blocks()
                .into_iter()
                .map(|n| {
                    let sid = vigil_core::service::service_sid(&n);
                    (n, sid)
                })
                .collect(),
            ..resolve(permits, denies)
        })
    }

    /// Apply a freshly stored decision to the filter engine.
    /// Returns `(applied, warnings)`; with no engine the decision is recorded only.
    pub fn enforce_decision(&self, d: &Decision) -> (bool, Vec<String>) {
        let mut warnings = Vec::new();
        if self.engine().is_none() {
            warnings.push(
                "protection is not enabled; the decision is recorded only (enable protection with administrator rights)"
                    .to_owned(),
            );
            return (false, warnings);
        }
        if d.action == Action::Allow && d.scope == decisions::Scope::Once {
            self.add_once_permit(self.decision_path(d), Instant::now() + ONCE_TTL);
        }
        if d.action == Action::Allow && self.mode_and_health().0 != "enforce" {
            warnings.push("an allow takes effect once enforce mode is on".to_owned());
        }
        match self.resync_enforcement() {
            Ok(()) => (true, warnings),
            Err(e) => {
                tracing::error!(error = %e, "could not apply decision");
                warnings.push("the filter engine rejected the change; see the service log".into());
                (false, warnings)
            }
        }
    }

    fn decision_path(&self, d: &Decision) -> Option<String> {
        self.with_store(|c| vigil_store::repo::executable_by_id(c, d.executable_id))
            .and_then(Result::ok)
            .flatten()
            .map(|e| e.path)
    }

    /// Bring the engine in line with decisions and mode. Cheap when nothing changed.
    pub fn resync_enforcement(&self) -> Result<(), String> {
        let Some(engine) = self.engine() else {
            return Ok(());
        };
        let armed_wanted = self.enforcing();
        let desired = if self.protection_paused() {
            Desired::default() // paused: no persistent deny filters either
        } else {
            self.desired(armed_wanted)?
        };
        let key = (desired.clone(), armed_wanted);
        if self.last_applied_slot().as_ref() == Some(&key) {
            return Ok(());
        }
        let denies: Vec<PathBuf> = desired.denies.iter().cloned().collect();
        engine.set_denies(&denies, desired.inbound)?;
        let services: Vec<(String, String)> = desired.services.iter().cloned().collect();
        engine.set_service_denies(&services)?;
        if armed_wanted {
            let permits: Vec<PathBuf> = desired.permits.iter().cloned().collect();
            let skipped = engine.arm(&permits)?;
            self.check_bootstrap(&skipped)?;
            self.set_armed(true);
        } else {
            engine.disarm()?;
            self.set_armed(false);
        }
        *self.last_applied_slot() = Some(key);
        Ok(())
    }

    /// Refuse to leave the machine without its critical network paths (docs/04 bootstrap check).
    fn check_bootstrap(&self, skipped: &[PathBuf]) -> Result<(), String> {
        let critical: BTreeSet<String> = self
            .bootstrap_permits()
            .into_iter()
            .map(|p| p.to_lowercase())
            .collect();
        match skipped
            .iter()
            .find(|p| critical.contains(&p.display().to_string().to_lowercase()))
        {
            Some(p) => Err(format!(
                "bootstrap check failed: {} could not be permitted",
                p.display()
            )),
            None => Ok(()),
        }
    }

    /// Validate and perform a transition to `enforce`.
    pub fn check_enforce(&self, override_minimum: bool) -> Result<(), RpcError> {
        if self.engine().is_none() {
            return Err(rpc_off(
                "enforcement needs the Vigil service running with administrator rights",
            ));
        }
        if !override_minimum {
            let hours = self
                .settings()
                .pointer("/general/learning_minimum_hours")
                .and_then(Value::as_u64)
                .unwrap_or(24);
            let age = self.learning_age_hours();
            if age.is_none_or(|a| a < hours) {
                return Err(RpcError::new(
                    INVALID_STATE,
                    format!(
                        "learning must run for at least {hours} h before enforce (override_learning_minimum to skip)"
                    ),
                ));
            }
        }
        Ok(())
    }

    fn learning_age_hours(&self) -> Option<u64> {
        let started = self.learning_started()?;
        let t =
            OffsetDateTime::parse(&started, &time::format_description::well_known::Rfc3339).ok()?;
        u64::try_from((OffsetDateTime::now_utc() - t).whole_hours()).ok()
    }

    /// Enforcement failed: fall back to observe and flag the service (docs/04 §7).
    pub fn fail_enforcement(&self, reason: &str) {
        tracing::error!(reason, "enforcement failure, falling back to observe");
        if let Some(engine) = self.engine() {
            engine.panic();
        }
        *self.last_applied_slot() = None;
        self.set_armed(false);
        self.force_mode("observe", "enforcement failure");
        self.set_health("failed", Some("enforcement failure"));
    }

    /// `enforcement.panic`: remove every filter now and return to observe.
    pub fn panic_now(&self, actor: &str) -> Value {
        let removed = self.engine().map_or(0, |e| e.panic());
        *self.last_applied_slot() = None;
        self.set_armed(false);
        self.force_mode("observe", "panic");
        self.audit(
            actor,
            AuditKind::Panic,
            None,
            &json!({ "filters_removed": removed }),
        );
        self.status()
    }

    /// Turn blocked connections into pending items until the engine stops reporting.
    pub async fn pump_drops(self: Arc<Self>) {
        let Some(engine) = self.engine() else { return };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        if let Err(e) = engine.watch_drops(tx) {
            tracing::warn!(error = %e, "network event subscription failed");
            return;
        }
        let mut recent: Vec<Instant> = Vec::new();
        while let Some(drop) = rx.recv().await {
            let now = Instant::now();
            recent.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
            if recent.len() >= PENDING_PER_MINUTE {
                continue;
            }
            if self.record_drop(&drop) {
                recent.push(now);
                tokio::spawn(Arc::clone(&self).ai_assess_open_pending());
            }
        }
    }

    /// Create a pending item for a blocked connection; true when a new item was created.
    pub fn record_drop(&self, drop: &DropInfo) -> bool {
        let created = self.with_store(|c| -> Result<Option<i64>, vigil_store::StoreError> {
            let now = OffsetDateTime::now_utc();
            let Some(exe) = vigil_store::repo::executable_id_by_path(c, &drop.app_path)? else {
                return Ok(None);
            };
            if !decisions::active_for(c, exe, now)?.is_empty() {
                return Ok(None);
            }
            let (id, created) = decisions::create_pending(
                c,
                &NewPending {
                    executable_id: exe,
                    dest_class: classify(&drop.remote_addr),
                    dest_addr: drop.remote_addr.clone(),
                    dest_port: drop.remote_port,
                    dns_name: None,
                },
                now,
            )?;
            Ok(created.then_some(id))
        });
        let Some(Ok(Some(id))) = created else {
            return false;
        };
        if let Some(Some(item)) = self
            .with_store(|c| decisions::get_pending(c, id))
            .and_then(Result::ok)
            .map(|p| p.and_then(|p| self.pending_item(&p)))
        {
            self.emit("pending", "event.pending_created", item);
        }
        true
    }

    /// Lift blocks an earlier build placed on a score alone ("auto-contained: malicious" carries no
    /// hard-rule id): those were dev tools and user apps, not incidents. Returns how many.
    pub fn lift_score_only_containment(&self) -> usize {
        let now = OffsetDateTime::now_utc();
        let n = self
            .with_store(|c| -> Result<usize, vigil_store::StoreError> {
                let mut n = 0;
                for d in decisions::list_active(c, now)? {
                    if d.by == decisions::DecidedBy::Rule
                        && d.note.as_deref() == Some("auto-contained: malicious")
                        && decisions::revoke_decision(c, d.id, now)?
                    {
                        n += 1;
                    }
                }
                Ok(n)
            })
            .and_then(Result::ok)
            .unwrap_or(0);
        if n > 0 {
            self.audit(
                "service",
                AuditKind::DecisionRevoked,
                None,
                &json!({ "lifted": n, "reason": "score-only containment" }),
            );
        }
        n
    }

    /// Policy for a rule-based Malicious program outside `observe`: cut its network now (a
    /// persistent, revocable Block) and leave the Kill choice to the user in the popup.
    /// Acts only when a hard rule fired. Never touches the never-kill set unless HR-001/002/003 fired; never acts on an AI-only verdict.
    fn contain_malicious(&self, exe: i64) {
        if self.mode_and_health().0 == "observe" {
            return;
        }
        let Some(Ok(Some((e, ev)))) = self.with_store(|c| {
            Ok::<_, vigil_store::StoreError>(
                vigil_store::repo::executable_by_id(c, exe)?
                    .zip(vigil_store::repo::latest_evaluation(c, exe)?),
            )
        }) else {
            return;
        };
        let hard = ev.hard_rule.as_deref();
        let image = e.path.rsplit(['\\', '/']).next().unwrap_or_default();
        // A score alone (e.g. an unsigned dev tool in a user folder) never cuts a program off:
        // only a hard rule does, otherwise the advisor reviews it and the user keeps working.
        if ev.source != "rules"
            || ev.verdict != "malicious"
            || hard.is_none()
            || self.never_kill.check(image, hard).is_err()
        {
            return;
        }
        let now = OffsetDateTime::now_utc();
        let made = self.with_store(|c| {
            if !decisions::active_for(c, exe, now)?.is_empty() {
                return Ok(None);
            }
            let id = decisions::insert_decision(
                c,
                &decisions::NewDecision {
                    executable_id: exe,
                    action: Action::Block,
                    scope: decisions::Scope::Forever,
                    apply_to: decisions::ApplyTo::File,
                    publisher_thumbprint: None,
                    publisher_product: None,
                    package_family: None,
                    by: decisions::DecidedBy::Rule,
                    actor: "rule".into(),
                    note: Some(format!("auto-contained: {}", hard.unwrap_or("malicious"))),
                },
                now,
            )?;
            decisions::get_decision(c, id)
        });
        let Some(Ok(Some(d))) = made else {
            return;
        };
        self.audit(
            "rule",
            AuditKind::Decision,
            Some(&exe.to_string()),
            &json!({ "outcome": "contained", "decision_id": d.id, "action": "block",
                     "hard_rule": hard }),
        );
        let _ = self.enforce_decision(&d);
    }

    /// A running program just became Malicious: queue it for a decision (popup + AI second opinion).
    /// There is no connection yet, so the destination is the unspecified address. True when new.
    pub fn raise_malicious(&self, identity_id: &str) -> bool {
        let Ok(exe) = identity_id.parse::<i64>() else {
            return false;
        };
        let created = self.with_store(|c| -> Result<Option<i64>, vigil_store::StoreError> {
            let now = OffsetDateTime::now_utc();
            if !decisions::active_for(c, exe, now)?.is_empty() {
                return Ok(None);
            }
            let (id, created) = decisions::create_pending(
                c,
                &NewPending {
                    executable_id: exe,
                    dest_class: DestClass::Public,
                    dest_addr: "0.0.0.0".into(),
                    dest_port: 0,
                    dns_name: None,
                },
                now,
            )?;
            Ok(created.then_some(id))
        });
        let Some(Ok(Some(id))) = created else {
            // Already queued (e.g. a weaker verdict earlier): a hard rule may still apply now.
            self.contain_malicious(exe);
            return false;
        };
        if let Some(Some(item)) = self
            .with_store(|c| decisions::get_pending(c, id))
            .and_then(Result::ok)
            .map(|p| p.and_then(|p| self.pending_item(&p)))
        {
            self.emit("pending", "event.pending_created", item);
        }
        self.contain_malicious(exe);
        true
    }

    /// Periodic maintenance: expire once-permits and decisions.
    pub async fn maintain(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            if let Err(e) = self.resync_enforcement() {
                self.fail_enforcement(&e);
            }
        }
    }
}

/// Paths of every known executable a decision covers.
pub(crate) fn decision_paths(
    c: &rusqlite::Connection,
    d: &Decision,
) -> Result<Vec<String>, vigil_store::StoreError> {
    use decisions::ApplyTo;
    Ok(
        match (d.apply_to, &d.publisher_thumbprint, &d.package_family) {
            (ApplyTo::Publisher, Some(t), _) => vigil_store::repo::paths_by_thumbprint(c, t)?,
            (ApplyTo::PackageSource, _, Some(f)) => {
                vigil_store::repo::paths_by_package_family(c, f)?
            }
            _ => vigil_store::repo::executable_by_id(c, d.executable_id)?
                .map(|e| vec![e.path])
                .unwrap_or_default(),
        },
    )
}

/// Whether `path` names an existing regular file (used by engines to skip stale entries).
#[must_use]
pub fn is_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_beats_permit_case_insensitively() {
        let d = resolve(
            ["C:\\A\\x.exe".to_owned(), "C:\\B\\y.exe".to_owned()],
            ["c:\\a\\X.EXE".to_owned()],
        );
        assert_eq!(d.permits.len(), 1);
        assert!(d.permits.contains(&PathBuf::from("C:\\B\\y.exe")));
        assert_eq!(d.denies.len(), 1);
    }

    #[test]
    fn classifies_destinations() {
        assert_eq!(classify("127.0.0.1"), DestClass::Loopback);
        assert_eq!(classify("192.168.1.5"), DestClass::Private);
        assert_eq!(classify("fd00::1"), DestClass::Private);
        assert_eq!(classify("8.8.8.8"), DestClass::Public);
        assert_eq!(classify("not-an-ip"), DestClass::Public);
    }
}
