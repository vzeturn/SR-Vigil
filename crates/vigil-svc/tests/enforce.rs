//! Enforcement policy against a fake filter engine (portable; the WFP engine is covered in vigil-win).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::json;
use vigil_ipc::proto::{ENFORCEMENT_OFF, INVALID_STATE};
use vigil_store::repo::{Executable, NewEvaluation, insert_evaluation, upsert_executable};
use vigil_svc::enforce::{DropInfo, FilterEngine};
use vigil_svc::state::{Options, Shared};

#[derive(Default)]
struct Fake {
    denies: Mutex<Vec<PathBuf>>,
    permits: Mutex<Option<Vec<PathBuf>>>,
    panicked: Mutex<bool>,
}

impl FilterEngine for Fake {
    fn set_denies(&self, d: &[PathBuf]) -> Result<(), String> {
        *self.denies.lock().unwrap() = d.to_vec();
        Ok(())
    }
    fn arm(&self, p: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
        *self.permits.lock().unwrap() = Some(p.to_vec());
        Ok(Vec::new())
    }
    fn disarm(&self) -> Result<(), String> {
        *self.permits.lock().unwrap() = None;
        Ok(())
    }
    fn panic(&self) -> usize {
        *self.panicked.lock().unwrap() = true;
        *self.permits.lock().unwrap() = None;
        self.denies.lock().unwrap().clear();
        7
    }
    fn watch_drops(&self, _: tokio::sync::mpsc::UnboundedSender<DropInfo>) -> Result<(), String> {
        Ok(())
    }
}

fn setup() -> (Arc<Shared>, Arc<Fake>, i64) {
    let s = Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec![],
    });
    let id = s
        .with_store(|c| {
            let exe = Executable {
                sha256: "b".repeat(64),
                path: r"C:\tools\x.exe".into(),
                signer_thumbprint: None,
                publisher: None,
                company: None,
                product: None,
                original_filename: None,
                signature_status: "unsigned".into(),
            };
            let id = upsert_executable(c, &exe, "2026-01-01T00:00:00Z").unwrap();
            let ev = NewEvaluation {
                score: 50,
                verdict: "unknown".into(),
                hard_rule: None,
                signals_json: "[]".into(),
                rule_pack_version: "1".into(),
                source: "rules".into(),
            };
            insert_evaluation(c, id, &ev, "2026-01-01T00:00:00Z").unwrap();
            id
        })
        .unwrap();
    let fake = Arc::new(Fake::default());
    let s = Arc::new(s);
    s.attach_engine(Some(fake.clone()));
    (s, fake, id)
}

fn decide(s: &Shared, id: i64, action: &str, scope: &str) -> serde_json::Value {
    s.submit_decision(&json!({"identity_id": id.to_string(), "action": action, "scope": scope, "apply_to": "file"}))
        .unwrap()
}

#[test]
fn enforce_needs_an_engine_and_learning_time() {
    let s = Shared::new(Options {
        store: None,
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec![],
    });
    assert_eq!(
        s.set_mode("enforce", true).unwrap_err().code,
        ENFORCEMENT_OFF
    );

    let (s, fake, _) = setup();
    assert_eq!(
        s.set_mode("enforce", false).unwrap_err().code,
        INVALID_STATE
    );
    s.set_mode("enforce", true).unwrap();
    assert_eq!(s.status()["filters_armed"], true);
    assert!(fake.permits.lock().unwrap().is_some());
    s.set_mode("observe", false).unwrap();
    assert_eq!(s.status()["filters_armed"], false);
    assert!(fake.permits.lock().unwrap().is_none());
}

#[test]
fn block_is_persistent_and_beats_allow_in_any_mode() {
    let (s, fake, id) = setup();
    let r = decide(&s, id, "block", "forever");
    assert_eq!(r["applied"], true);
    assert_eq!(
        fake.denies.lock().unwrap().as_slice(),
        [PathBuf::from(r"C:\tools\x.exe")]
    );
    // an allow for the same file cannot override the block
    decide(&s, id, "allow", "forever");
    s.set_mode("enforce", true).unwrap();
    assert!(
        !fake
            .permits
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .contains(&PathBuf::from(r"C:\tools\x.exe"))
    );
    // revoking the block removes the deny and the allow takes over
    let did = r["decision"]["id"].as_str().unwrap().to_owned();
    s.revoke_decision(&json!({"decision_id": did})).unwrap();
    assert!(fake.denies.lock().unwrap().is_empty());
    assert!(
        fake.permits
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .contains(&PathBuf::from(r"C:\tools\x.exe"))
    );
}

#[test]
fn allow_once_installs_a_short_lived_permit() {
    let (s, fake, id) = setup();
    s.set_mode("enforce", true).unwrap();
    decide(&s, id, "allow", "once");
    assert!(
        fake.permits
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .contains(&PathBuf::from(r"C:\tools\x.exe"))
    );
}

#[test]
fn panic_removes_everything_returns_to_observe_and_is_audited() {
    let (s, fake, id) = setup();
    decide(&s, id, "block", "forever");
    s.set_mode("enforce", true).unwrap();
    let st = s.panic_now("user");
    assert_eq!(st["mode"], "observe");
    assert_eq!(st["filters_armed"], false);
    assert!(*fake.panicked.lock().unwrap());
    let page = s.audit_query(&json!({})).unwrap();
    assert_eq!(page["chain_ok"], true);
    let kinds: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"panic") && kinds.contains(&"mode_change"));
}

#[test]
fn blocked_connection_becomes_one_pending_item() {
    let (s, _, _) = setup();
    let d = DropInfo {
        app_path: r"c:\TOOLS\x.exe".into(),
        remote_addr: "93.184.216.34".into(),
        remote_port: 443,
    };
    assert!(s.record_drop(&d));
    assert!(!s.record_drop(&d), "deduplicated while unresolved");
    assert_eq!(
        s.list_pending().unwrap()["items"].as_array().unwrap().len(),
        1
    );
    assert_eq!(s.status()["counts"]["pending"], 1);
    assert_eq!(
        s.list_pending().unwrap()["items"][0]["alert"],
        false,
        "an unknown program waits quietly; only an established incident interrupts"
    );
    let unknown = DropInfo {
        app_path: r"C:\nope.exe".into(),
        ..d
    };
    assert!(!s.record_drop(&unknown));
}

fn rate(s: &Shared, id: i64, hard_rule: Option<&str>) {
    s.with_store(|c| {
        let ev = NewEvaluation {
            score: 5,
            verdict: "malicious".into(),
            hard_rule: hard_rule.map(Into::into),
            signals_json: "[]".into(),
            rule_pack_version: "1".into(),
            source: "rules".into(),
        };
        insert_evaluation(c, id, &ev, "2026-01-02T00:00:00Z").unwrap();
    })
    .unwrap();
}

#[test]
fn only_a_hard_rule_cuts_a_program_off_a_score_never_does() {
    let (s, fake, id) = setup();
    s.set_mode("enforce", true).unwrap();
    rate(&s, id, None);
    s.raise_malicious(&id.to_string());
    assert!(
        fake.denies.lock().unwrap().is_empty(),
        "score-only verdict must not deny"
    );
    let item = s.list_pending().unwrap()["items"][0].clone();
    assert_eq!(item["alert"], false);

    rate(&s, id, Some("HR-004"));
    s.raise_malicious(&id.to_string());
    assert_eq!(
        fake.denies.lock().unwrap().as_slice(),
        [PathBuf::from(r"C:\tools\x.exe")]
    );
}
