//! A user decision changes the live verdict: allow feeds HA-002 and queues the file for
//! re-evaluation; revoking undoes both.

use serde_json::json;
use vigil_store::repo::{Executable, upsert_executable};
use vigil_svc::state::{Options, Shared};

const PATH: &str = r"C:\Tools\app.exe";

fn shared_with_exe() -> (Shared, i64) {
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
                sha256: "a".repeat(64),
                path: PATH.into(),
                signer_thumbprint: None,
                publisher: None,
                company: None,
                product: None,
                original_filename: None,
                signature_status: "unsigned".into(),
            };
            upsert_executable(c, &exe, "2026-01-01T00:00:00Z").unwrap()
        })
        .unwrap();
    (s, id)
}

#[test]
fn allow_reaches_the_verdict_and_revoke_withdraws_it() {
    let (s, id) = shared_with_exe();
    assert!(!s.user_allows(id));

    let out = s
        .submit_decision(&json!({
            "identity_id": id.to_string(), "action": "allow", "scope": "forever", "apply_to": "file",
        }))
        .unwrap();
    assert!(s.user_allows(id));
    assert_eq!(s.take_rejudge_paths(), vec![PATH.to_string()]);
    assert_eq!(s.take_rejudge_paths(), Vec::<String>::new());

    let decision_id = out["decision"]["id"].as_str().unwrap().to_owned();
    s.revoke_decision(&json!({ "decision_id": decision_id }))
        .unwrap();
    assert!(!s.user_allows(id));
    assert_eq!(s.take_rejudge_paths(), vec![PATH.to_string()]);
}

#[test]
fn a_newer_block_overrides_an_older_allow() {
    let (s, id) = shared_with_exe();
    for action in ["allow", "block"] {
        s.submit_decision(&json!({
            "identity_id": id.to_string(), "action": action, "scope": "forever", "apply_to": "file",
        }))
        .unwrap();
    }
    assert!(!s.user_allows(id));
}
