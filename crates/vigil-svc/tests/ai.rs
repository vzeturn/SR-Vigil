//! M5 acceptance at the service level: AI failures fall back to Pending with an audit row, the
//! preview equals what is sent, and Auto mode never overrides hard rules or kills by default.

use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use serde_json::{Value, json};
use vigil_ai::{AiError, Opinion};
use vigil_ipc::proto::INVALID_STATE;
use vigil_store::repo::{Executable, NewEvaluation, insert_evaluation, upsert_executable};
use vigil_svc::ai::{AiBackend, AiSettings, BoxFut};
use vigil_svc::enforce::{DropInfo, FilterEngine};
use vigil_svc::state::{Options, Shared};
use zeroize::Zeroizing;

const PATH: &str = r"C:\tools\x.exe";

struct Fake {
    reply: Mutex<Result<Opinion, fn() -> AiError>>,
    sent: Mutex<Vec<Value>>,
}

impl Fake {
    fn new(reply: Result<Opinion, fn() -> AiError>) -> Arc<Self> {
        Arc::new(Self {
            reply: Mutex::new(reply),
            sent: Mutex::default(),
        })
    }
}

impl AiBackend for Fake {
    fn seal(&self, plain: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(plain.iter().rev().copied().collect())
    }
    fn unseal(&self, cipher: &[u8], _: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        Ok(Zeroizing::new(cipher.iter().rev().copied().collect()))
    }
    fn assess<'a>(
        &'a self,
        _: &'a AiSettings,
        _: &'a SecretString,
        payload: &'a Value,
        _: &'a [String],
    ) -> BoxFut<'a, Result<(Opinion, String), AiError>> {
        self.sent.lock().unwrap().push(payload.clone());
        let r = match &*self.reply.lock().unwrap() {
            Ok(o) => Ok((o.clone(), "fake-model".to_string())),
            Err(e) => Err(e()),
        };
        Box::pin(async move { r })
    }
    fn calls_today(&self) -> u32 {
        0
    }
}

fn opinion(verdict: &str, conf: f64, action: &str) -> Opinion {
    serde_json::from_value(json!({
        "verdict": verdict, "confidence": conf, "recommended_action": action,
        "reasons": ["test"], "indicators": []
    }))
    .unwrap()
}

struct NullEngine;
impl FilterEngine for NullEngine {
    fn set_denies(&self, _: &[std::path::PathBuf], _: bool) -> Result<(), String> {
        Ok(())
    }
    fn arm(&self, _: &[std::path::PathBuf]) -> Result<Vec<std::path::PathBuf>, String> {
        Ok(Vec::new())
    }
    fn disarm(&self) -> Result<(), String> {
        Ok(())
    }
    fn panic(&self) -> usize {
        0
    }
    fn watch_drops(&self, _: tokio::sync::mpsc::UnboundedSender<DropInfo>) -> Result<(), String> {
        Ok(())
    }
}

fn enforce(s: &Shared) {
    s.attach_engine(Some(Arc::new(NullEngine)));
    s.set_mode("enforce", true).unwrap();
}

fn setup(hard_rule: Option<&str>, score: u8, verdict: &str) -> (Arc<Shared>, i64) {
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
                sha256: "c".repeat(64),
                path: PATH.into(),
                signer_thumbprint: None,
                publisher: None,
                company: None,
                product: None,
                original_filename: None,
                signature_status: "unsigned".into(),
            };
            let id = upsert_executable(c, &exe, "2026-01-01T00:00:00Z").unwrap();
            let ev = NewEvaluation {
                score,
                verdict: verdict.into(),
                hard_rule: hard_rule.map(str::to_string),
                signals_json: "[]".into(),
                rule_pack_version: "1".into(),
                source: "rules".into(),
            };
            insert_evaluation(c, id, &ev, "2026-01-01T00:00:00Z").unwrap();
            id
        })
        .unwrap();
    let s = Arc::new(s);
    s.record_drop(&DropInfo {
        app_path: PATH.into(),
        remote_addr: "93.184.216.34".into(),
        remote_port: 443,
    });
    (s, id)
}

fn enable(s: &Shared, mode: &str, extra: &Value) {
    let mut p = json!({"api_key": "k-test", "mode": mode, "enabled": true, "acknowledge_data_categories": true});
    p.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    s.ai_config_set(&p, "user").unwrap();
}

fn pending_count(s: &Shared) -> usize {
    s.list_pending().unwrap()["items"].as_array().unwrap().len()
}

fn audit_text(s: &Shared) -> String {
    s.audit_query(&json!({})).unwrap().to_string()
}

#[tokio::test]
async fn failures_fall_back_to_pending_with_an_audit_row() {
    for err in [
        (|| AiError::InvalidOutput("bad".into())) as fn() -> AiError,
        || AiError::InvalidOutput("injected".into()),
        || AiError::Timeout,
    ] {
        let (s, _) = setup(None, 60, "safe");
        s.attach_ai(Arc::new(vigil_svc::ai::LiveBackend::new(Arc::new(NoVault))));
        let fake = Fake::new(Err(err));
        s.attach_ai(fake.clone());
        enable(&s, "auto", &json!({}));
        Arc::clone(&s).ai_assess_open_pending().await;
        assert_eq!(pending_count(&s), 1, "item must stay pending");
        assert!(audit_text(&s).contains("ai_decision"), "{}", audit_text(&s));
    }
}

struct NoVault;
impl vigil_svc::ai::KeyVault for NoVault {
    fn seal(&self, p: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(p.to_vec())
    }
    fn unseal(&self, c: &[u8], _: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        Ok(Zeroizing::new(c.to_vec()))
    }
}

#[tokio::test]
async fn preview_hash_equals_the_bytes_sent() {
    let (s, id) = setup(None, 60, "safe");
    let fake = Fake::new(Ok(opinion("safe", 0.5, "allow")));
    s.attach_ai(fake.clone());
    enable(&s, "advisor", &json!({}));
    let preview = s
        .ai_preview(&json!({"identity_id": id.to_string()}))
        .unwrap();
    s.ai_explain(&json!({"identity_id": id.to_string()}))
        .await
        .unwrap();
    let sent = fake.sent.lock().unwrap()[0].clone();
    assert_eq!(sent, preview["payload"]);
    assert_eq!(
        preview["payload_sha256"],
        vigil_core::redact::payload_sha256(&sent)
    );
}

#[tokio::test]
async fn auto_never_decides_when_a_hard_rule_fired() {
    let (s, _) = setup(Some("HR-001"), 60, "safe");
    s.attach_ai(Fake::new(Ok(opinion("safe", 0.99, "allow"))));
    enable(&s, "auto", &json!({}));
    Arc::clone(&s).ai_assess_open_pending().await;
    assert_eq!(pending_count(&s), 1);
    assert_eq!(
        s.list_decisions().unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn auto_decides_above_threshold_and_never_kills_by_default() {
    let (s, _) = setup(None, 20, "malicious");
    enforce(&s);
    s.attach_ai(Fake::new(Ok(opinion("malicious", 0.99, "kill"))));
    enable(&s, "auto", &json!({}));
    Arc::clone(&s).ai_assess_open_pending().await;
    assert_eq!(pending_count(&s), 0);
    let d = s.list_decisions().unwrap();
    let first = &d["items"][0];
    assert_eq!(first["action"], "block");
    assert_eq!(first["by"], "ai");
}

#[tokio::test]
async fn activity_counts_assessments_decisions_and_leftovers() {
    let (s, _) = setup(None, 20, "malicious");
    enforce(&s);
    s.attach_ai(Fake::new(Ok(opinion("malicious", 0.99, "kill"))));
    enable(&s, "auto", &json!({}));
    Arc::clone(&s).ai_assess_open_pending().await;
    let t = &s.ai_activity()["today"];
    assert_eq!(
        (t["calls"].as_u64(), t["blocked"].as_u64()),
        (Some(1), Some(1))
    );

    let (s, _) = setup(None, 60, "safe");
    enforce(&s);
    s.attach_ai(Fake::new(Ok(opinion("safe", 0.5, "allow"))));
    enable(&s, "auto", &json!({}));
    Arc::clone(&s).ai_assess_open_pending().await;
    let t = &s.ai_activity()["today"];
    assert_eq!(
        (t["calls"].as_u64(), t["left_to_user"].as_u64()),
        (Some(1), Some(1))
    );
}

#[tokio::test]
async fn ai_only_suggests_outside_enforce() {
    for mode in ["observe", "learning"] {
        let (s, _) = setup(None, 20, "malicious");
        s.set_mode(mode, true).unwrap();
        s.attach_ai(Fake::new(Ok(opinion("malicious", 0.99, "block"))));
        enable(&s, "auto", &json!({}));
        Arc::clone(&s).ai_assess_open_pending().await;
        assert_eq!(pending_count(&s), 1, "{mode}: the user still decides");
        assert_eq!(
            s.list_decisions().unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
}

#[tokio::test]
async fn auto_leaves_low_confidence_pending() {
    let (s, _) = setup(None, 60, "safe");
    s.attach_ai(Fake::new(Ok(opinion("safe", 0.80, "allow"))));
    enable(&s, "auto", &json!({}));
    Arc::clone(&s).ai_assess_open_pending().await;
    assert_eq!(pending_count(&s), 1);
}

#[test]
fn enabling_needs_a_key_and_the_key_is_never_returned() {
    let (s, _) = setup(None, 60, "safe");
    s.attach_ai(Fake::new(Ok(opinion("safe", 0.9, "allow"))));
    let e = s
        .ai_config_set(&json!({"enabled": true, "mode": "advisor"}), "user")
        .unwrap_err();
    assert_eq!(e.code, INVALID_STATE);
    enable(&s, "advisor", &json!({}));
    let cfg = s.ai_config_get();
    assert_eq!(cfg["has_key"], true);
    assert!(!cfg.to_string().contains("k-test"));
    assert!(!audit_text(&s).contains("k-test"));
}

#[test]
fn reputation_keys_are_write_only_and_needed_to_turn_a_service_on() {
    let (s, _) = setup(None, 60, "unknown");
    s.attach_ai(Fake::new(Ok(opinion("safe", 0.9, "allow"))));
    let set = |p: Value| s.reputation_config_set(&p, "user");
    let e = set(json!({"service": "virustotal", "enabled": true})).unwrap_err();
    assert_eq!(e.code, INVALID_STATE);
    assert!(set(json!({"service": "malwarebazaar", "api_key": "bad key"})).is_err());
    assert!(set(json!({"service": "other", "enabled": false})).is_err());

    let cfg =
        set(json!({"service": "virustotal", "api_key": "vt-secret-1", "enabled": true})).unwrap();
    assert_eq!(cfg["virustotal"], json!({"enabled": true, "has_key": true}));
    assert_eq!(cfg["malwarebazaar"]["has_key"], false);
    assert_eq!(s.settings()["virustotal"]["enabled"], true);
    assert!(!cfg.to_string().contains("vt-secret-1"));
    assert!(!audit_text(&s).contains("vt-secret-1"));
    assert!(audit_text(&s).contains("virustotal"));

    let cfg = set(json!({"service": "virustotal", "api_key": ""})).unwrap();
    assert_eq!(
        cfg["virustotal"],
        json!({"enabled": false, "has_key": false})
    );
}

#[tokio::test]
async fn malicious_program_is_raised_once_without_a_connection() {
    let (s, _) = setup(Some("HR-001"), 10, "malicious");
    // A second program that never opened a connection (setup's drop belongs to the first).
    let id = s
        .with_store(|c| {
            let exe = Executable {
                sha256: "d".repeat(64),
                path: r"C:	ools\y.exe".into(),
                signer_thumbprint: None,
                publisher: None,
                company: None,
                product: None,
                original_filename: None,
                signature_status: "unsigned".into(),
            };
            let id = upsert_executable(c, &exe, "2026-01-01T00:00:00Z").unwrap();
            let ev = NewEvaluation {
                score: 10,
                verdict: "malicious".into(),
                hard_rule: Some("HR-001".into()),
                signals_json: "[]".into(),
                rule_pack_version: "1".into(),
                source: "rules".into(),
            };
            insert_evaluation(c, id, &ev, "2026-01-01T00:00:00Z").unwrap();
            id
        })
        .unwrap();
    let before = pending_count(&s);
    assert!(
        s.raise_malicious(&id.to_string()),
        "first flag creates a pending item"
    );
    assert!(
        !s.raise_malicious(&id.to_string()),
        "second flag is a duplicate"
    );
    assert_eq!(pending_count(&s), before + 1);
    let items = s.list_pending().unwrap()["items"].clone();
    assert!(
        items
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["destination"]["port"] == 0)
    );
}

/// A rule-based Malicious program that has not opened a connection yet.
fn malicious_exe(s: &Shared, path: &str, hard_rule: &str) -> i64 {
    s.with_store(|c| {
        let exe = Executable {
            sha256: "e".repeat(64),
            path: path.into(),
            signer_thumbprint: None,
            publisher: None,
            company: None,
            product: None,
            original_filename: None,
            signature_status: "unsigned".into(),
        };
        let id = upsert_executable(c, &exe, "2026-01-01T00:00:00Z").unwrap();
        let ev = NewEvaluation {
            score: 10,
            verdict: "malicious".into(),
            hard_rule: Some(hard_rule.into()),
            signals_json: "[]".into(),
            rule_pack_version: "1".into(),
            source: "rules".into(),
        };
        insert_evaluation(c, id, &ev, "2026-01-01T00:00:00Z").unwrap();
        id
    })
    .unwrap()
}

fn active_blocks(s: &Shared, id: i64) -> Vec<vigil_store::decisions::Decision> {
    s.with_store(|c| vigil_store::decisions::active_for(c, id, time::OffsetDateTime::now_utc()))
        .unwrap()
        .unwrap()
}

#[test]
fn malicious_is_contained_by_a_block_outside_observe() {
    let (s, _) = setup(None, 60, "safe");
    s.set_mode("learning", true).unwrap();
    let id = malicious_exe(&s, r"C:	ools\evil.exe", "HR-001");
    assert!(s.raise_malicious(&id.to_string()));
    let d = active_blocks(&s, id);
    assert_eq!(d.len(), 1, "one containment decision");
    assert_eq!(d[0].action, vigil_store::decisions::Action::Block);
    assert_eq!(d[0].by, vigil_store::decisions::DecidedBy::Rule);
}

#[test]
fn observe_mode_never_contains() {
    let (s, _) = setup(None, 60, "safe");
    s.set_mode("observe", true).unwrap();
    let id = malicious_exe(&s, r"C:	ools\evil.exe", "HR-001");
    assert!(s.raise_malicious(&id.to_string()));
    assert_eq!(active_blocks(&s, id).len(), 0);
}

fn suspect_row(id: i64) -> vigil_svc::state::ProcRow {
    vigil_svc::state::ProcRow {
        pid: 4_000_000_001,
        start_time: "t1".into(),
        ppid: 1,
        name: "x.exe".into(),
        path: Some(PATH.into()),
        parent_path: None,
        identity_id: Some(id.to_string()),
        verdict: Some("unknown".into()),
        score: Some(50),
        freshness: None,
        tab: false,
        origin: None,
    }
}

#[tokio::test]
async fn storm_suspects_are_judged_by_the_advisor_and_acted_on_only_in_enforce() {
    for (mode, outcome) in [("observe", "storm_noted"), ("enforce", "storm_kill")] {
        let (s, id) = setup(None, 50, "unknown");
        if mode == "enforce" {
            enforce(&s);
        } else {
            s.set_mode(mode, true).unwrap();
        }
        s.attach_ai(Fake::new(Ok(opinion("malicious", 0.99, "block"))));
        enable(&s, "auto", &json!({}));
        Arc::clone(&s).storm_review(suspect_row(id), 4).await;
        assert!(audit_text(&s).contains(outcome), "{mode}: {outcome}");
        // asked once per run, however often the scan sees the same suspect
        Arc::clone(&s).storm_review(suspect_row(id), 4).await;
    }
}

#[tokio::test]
async fn a_hesitant_advisor_never_stops_a_suspect() {
    let (s, id) = setup(None, 50, "unknown");
    enforce(&s);
    s.attach_ai(Fake::new(Ok(opinion("malicious", 0.5, "block"))));
    enable(&s, "auto", &json!({}));
    Arc::clone(&s).storm_review(suspect_row(id), 4).await;
    let a = audit_text(&s);
    assert!(a.contains("storm_noted") && !a.contains("storm_kill"));
}

#[tokio::test]
async fn a_confident_verdict_is_remembered_for_an_identical_program() {
    let (s, id) = setup(None, 60, "safe");
    let fake = Fake::new(Ok(opinion("safe", 0.9, "allow")));
    s.attach_ai(fake.clone());
    enable(&s, "advisor", &json!({}));
    s.ai_assess(id, false).await.unwrap();
    // A different model changes the response-cache key, never the exact-match memory.
    enable(&s, "advisor", &json!({"model": "other-model"}));
    let (again, ..) = s.ai_assess(id, false).await.unwrap();
    assert!(again.cached);
    assert_eq!(fake.sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_hesitant_verdict_is_not_remembered() {
    let (s, id) = setup(None, 60, "safe");
    let fake = Fake::new(Ok(opinion("safe", 0.6, "allow")));
    s.attach_ai(fake.clone());
    enable(&s, "advisor", &json!({}));
    s.ai_assess(id, false).await.unwrap();
    enable(&s, "advisor", &json!({"model": "other-model"}));
    s.ai_assess(id, false).await.unwrap();
    assert_eq!(fake.sent.lock().unwrap().len(), 2);
}

fn live_connection(s: &Shared, id: i64) {
    let row = suspect_row(id);
    s.sync_connections(vec![vigil_svc::state::ConnRow {
        id: "c1".into(),
        pid: row.pid,
        direction: "outbound",
        local_addr: "10.0.0.2".into(),
        local_port: 50_000,
        remote_addr: Some("203.0.113.9".into()),
        remote_port: Some(443),
        state: "established",
        verdict: None,
        dns_name: None,
        reputation: None,
        first_seen: "t".into(),
        last_seen: "t".into(),
    }]);
    s.put_process(row);
}

#[tokio::test]
async fn an_attack_in_progress_is_stopped_but_an_idle_program_is_only_blocked() {
    for live in [true, false] {
        let (s, id) = setup(None, 20, "malicious");
        enforce(&s);
        if live {
            live_connection(&s, id);
        }
        s.attach_ai(Fake::new(Ok(opinion("malicious", 0.99, "kill"))));
        enable(&s, "auto", &json!({}));
        Arc::clone(&s).ai_assess_open_pending().await;
        let d = s.list_decisions().unwrap();
        assert_eq!(
            d["items"][0]["action"],
            if live { "kill" } else { "block" },
            "live={live}"
        );
    }
}
