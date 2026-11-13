//! FR-021: blocking one service's network reaches the filter engine only when the service has its
//! own SID and is not network-essential; unblocking removes it (fake engine and control).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::json;
use vigil_core::service::{HostedService, SID_TYPE_NONE, SID_TYPE_UNRESTRICTED, service_sid};
use vigil_store::persistence::Found;
use vigil_svc::enforce::{DropInfo, FilterEngine};
use vigil_svc::kill::{KillOutcome, ProcessControl, Snap};
use vigil_svc::state::{Options, Shared};

#[derive(Default)]
struct Engine {
    services: Mutex<Vec<(String, String)>>,
}

impl FilterEngine for Engine {
    fn set_denies(&self, _: &[PathBuf], _: bool) -> Result<(), String> {
        Ok(())
    }
    fn set_service_denies(&self, s: &[(String, String)]) -> Result<(), String> {
        *self.services.lock().unwrap() = s.to_vec();
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

struct Control(Vec<HostedService>);

impl ProcessControl for Control {
    fn list(&self) -> Vec<Snap> {
        Vec::new()
    }
    fn terminate(&self, _: u32, _: u64) -> KillOutcome {
        KillOutcome::Failed
    }
    fn sha256(&self, _: &str) -> Option<String> {
        None
    }
    fn services(&self) -> Vec<HostedService> {
        self.0.clone()
    }
    fn persist_scan(&self) -> Vec<Found> {
        Vec::new()
    }
    fn persist_disable(&self, _: &str, _: &str) -> Result<String, String> {
        Err("unused".into())
    }
    fn persist_restore(&self, _: &str, _: &str, _: &str) -> Result<(), String> {
        Err("unused".into())
    }
    fn persist_delete(&self, _: &str, _: &str) -> Result<(), String> {
        Err("unused".into())
    }
}

fn svc(pid: u32, name: &str, sid_type: u32, suspicious: Option<&'static str>) -> HostedService {
    HostedService {
        pid,
        name: name.into(),
        display_name: format!("{name} service"),
        dll: Some(format!(r"C:\Windows\System32\{name}.dll")),
        sid_type,
        suspicious,
    }
}

fn setup() -> (Arc<Shared>, Arc<Engine>) {
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
    s.attach_control(Arc::new(Control(vec![
        svc(900, "WSearch", SID_TYPE_UNRESTRICTED, None),
        svc(900, "Legacy", SID_TYPE_NONE, Some("unsigned")),
        svc(800, "Dnscache", SID_TYPE_UNRESTRICTED, None),
    ])));
    (s, engine)
}

fn block(s: &Shared, name: &str, on: bool) -> serde_json::Value {
    s.service_block_network(&json!({"name": name, "block": on}), "user")
        .unwrap()
}

#[test]
fn only_a_service_with_its_own_sid_that_is_not_essential_can_be_blocked() {
    let (s, engine) = setup();
    assert_eq!(block(&s, "Legacy", true)["error_code"], "no_service_sid");
    assert_eq!(
        block(&s, "dnscache", true)["error_code"],
        "protected_target"
    );
    assert_eq!(block(&s, "Gone", true)["error_code"], "not_found");
    assert!(engine.services.lock().unwrap().is_empty());

    assert_eq!(block(&s, "wsearch", true)["ok"], true);
    assert_eq!(
        *engine.services.lock().unwrap(),
        vec![("WSearch".to_owned(), service_sid("WSearch"))]
    );
    let list = s.service_list();
    let row = |n: &str| {
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == n)
            .cloned()
            .unwrap()
    };
    assert_eq!(row("WSearch")["network_blocked"], true);
    assert_eq!(row("WSearch")["shared_with"], json!(["Legacy"]));
    assert_eq!(row("Legacy")["refusal"], "no_service_sid");

    assert_eq!(block(&s, "WSEARCH", false)["ok"], true);
    assert!(engine.services.lock().unwrap().is_empty());
    assert_eq!(block(&s, "WSearch", false)["detail"], "not blocked");
}

#[test]
fn a_suspicious_service_dll_is_reported_once() {
    let (s, _) = setup();
    let mut bus = s.subscribe_bus();
    assert_eq!(s.service_alert_scan(), 1);
    assert_eq!(s.service_alert_scan(), 0);
    let e = bus.try_recv().unwrap();
    assert_eq!(e.method, "event.service_alert");
    assert_eq!(e.params["service"], "Legacy");
    assert_eq!(e.params["reason"], "unsigned");
}
