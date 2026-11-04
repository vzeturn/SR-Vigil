//! M5 acceptance at the service level: AI failures fall back to Pending with an audit row, the
//! preview equals what is sent, and Auto mode never overrides hard rules or kills by default.

use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use serde_json::{Value, json};
use vigil_ai::{AiError, Opinion};
use vigil_ipc::proto::INVALID_STATE;
use vigil_store::repo::{Executable, NewEvaluation, insert_evaluation, upsert_executable};
use vigil_svc::ai::{AiBackend, AiSettings, BoxFut};
use vigil_svc::enforce::DropInfo;
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
