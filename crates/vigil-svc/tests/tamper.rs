//! docs/08 §5: a Vigil filter deleted by another program is put back (forced resync), audited and
//! reported to the UI (fake engine).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;
use vigil_svc::enforce::{DropInfo, FilterEngine, Tampered};
use vigil_svc::state::{Options, Shared};

#[derive(Default)]
struct Engine {
    syncs: AtomicUsize,
}

impl FilterEngine for Engine {
    fn set_denies(&self, _: &[PathBuf], _: bool) -> Result<(), String> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn arm(&self, _: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
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

#[test]
fn a_deleted_filter_is_put_back_audited_and_reported() {
    let s = Arc::new(Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec![],
    }));
    let engine = Arc::new(Engine::default());
    s.attach_engine(Some(engine.clone()));
    s.resync_enforcement().unwrap();
    s.resync_enforcement().unwrap();
    assert_eq!(
        engine.syncs.load(Ordering::SeqCst),
        1,
        "unchanged state is a no-op"
    );

    let mut bus = s.subscribe_bus();
    s.on_tamper(&Tampered {
        filter: "deny",
        target: r"C:\Users\a\x.exe".into(),
    });
    assert_eq!(
        engine.syncs.load(Ordering::SeqCst),
        2,
        "the deletion forces a resync"
    );

    let e = bus.try_recv().unwrap();
    assert_eq!(e.method, "event.filter_tampered");
    assert_eq!(
        e.params,
        json!({"filter": "deny", "target": r"C:\Users\a\x.exe", "restored": true})
    );

    let audit = s.audit_query(&json!({"kind": "filter_remove"})).unwrap();
    let row = &audit["items"][0];
    assert_eq!(row["actor"], "unknown");
    assert_eq!(row["details"]["by"], "another program");
    assert_eq!(row["details"]["restored"], true);
}
