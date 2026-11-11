//! Pausing protection: no automatic blocking or killing, lockdown refused, state visible and reversible.

use serde_json::json;
use vigil_svc::state::{Options, Shared};

fn shared() -> Shared {
    Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec![],
    })
}

#[test]
fn paused_protection_refuses_lockdown_and_never_kills() {
    let s = shared();
    assert_eq!(s.status()["protection"], true);

    let st = s.set_protection(false).unwrap();
    assert_eq!(st["protection"], false);
    assert!(s.protection_paused() && !s.enforcing());
    assert_eq!(s.storm_scan(), 0);
    assert_eq!(s.auto_kill_malicious(), 0);
    assert_eq!(s.respawn_scan(), 0);
    let e = s.purge_start(&json!({}), "user").unwrap_err();
    assert!(e.message.contains("paused"), "{}", e.message);

    assert_eq!(s.set_protection(true).unwrap()["protection"], true);
    assert!(!s.protection_paused());
}
