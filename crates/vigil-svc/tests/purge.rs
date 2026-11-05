//! Kill policy against a fake process table: T-KILL-01 (respawn) and T-KILL-02 (protected target).

use std::sync::{Arc, Mutex};

use serde_json::json;
use vigil_store::persistence::Found;
use vigil_store::repo::{Executable, NewEvaluation, insert_evaluation, upsert_executable};
use vigil_svc::kill::{KillOutcome, ProcessControl, Snap};
use vigil_svc::state::{Options, ProcRow, Shared};

const BAD: &str = r"C:\Temp\bad.exe";

#[derive(Default)]
struct Fake {
    procs: Mutex<Vec<Snap>>,
    killed: Mutex<Vec<u32>>,
    frozen: Mutex<Vec<u32>>,
    thawed: Mutex<Vec<u32>>,
    items: Mutex<Vec<Found>>,
}

fn found(kind: &str, loc: &str) -> Found {
    Found {
        kind: kind.into(),
        location: loc.into(),
        image_path: Some(BAD.into()),
        command: Some(BAD.into()),
        risk_note: None,
    }
}

impl Fake {
    fn spawn(&self, pid: u32, parent: u32, image: &str) {
        self.procs.lock().unwrap().push(Snap {
            pid,
            ppid: parent,
            started: u64::from(pid) * 10,
            start_time: format!("t{pid}"),
            image: Some(image.into()),
        });
    }
}

impl ProcessControl for Fake {
    fn list(&self) -> Vec<Snap> {
        self.procs.lock().unwrap().clone()
    }
    fn terminate(&self, pid: u32, _: u64) -> KillOutcome {
        self.procs.lock().unwrap().retain(|p| p.pid != pid);
        self.killed.lock().unwrap().push(pid);
        KillOutcome::Terminated
    }
    fn suspend(&self, pid: u32, _: u64) -> bool {
        self.frozen.lock().unwrap().push(pid);
        true
    }
    fn resume(&self, pid: u32, _: u64) -> bool {
        self.thawed.lock().unwrap().push(pid);
        true
    }
    fn persist_scan(&self) -> Vec<Found> {
        self.items.lock().unwrap().clone()
    }
    fn persist_disable(&self, _: &str, loc: &str) -> Result<String, String> {
        self.items.lock().unwrap().retain(|f| f.location != loc);
        Ok(format!("was:{loc}"))
    }
    fn persist_restore(&self, kind: &str, loc: &str, backup: &str) -> Result<(), String> {
        assert_eq!(backup, format!("was:{loc}"));
        self.items.lock().unwrap().push(found(kind, loc));
        Ok(())
    }
    fn persist_delete(&self, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn sha256(&self, path: &str) -> Option<String> {
        // A renamed copy keeps the same content hash.
        Some(if path.ends_with("bad.exe") || path.ends_with("copy.exe") {
            "a".repeat(64)
        } else {
            "c".repeat(64)
        })
    }
}

fn setup() -> (Arc<Shared>, Arc<Fake>, String) {
    let s = Arc::new(Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec!["lsass.exe".into()],
    }));
    let id = s
        .with_store(|c| {
            let exe = Executable {
                sha256: "a".repeat(64),
                path: BAD.into(),
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
                hard_rule: None,
                signals_json: "[]".into(),
                rule_pack_version: "1".into(),
                source: "rules".into(),
            };
            insert_evaluation(c, id, &ev, "2026-01-01T00:00:00Z").unwrap();
            id
        })
        .unwrap()
        .to_string();
    let fake = Arc::new(Fake::default());
    s.attach_control(fake.clone());
    (s, fake, id)
}

fn row(pid: u32, image: &str, identity: Option<&str>) -> ProcRow {
    ProcRow {
        pid,
        start_time: format!("t{pid}"),
        ppid: 1,
        name: image.rsplit('\\').next().unwrap().into(),
        path: Some(image.into()),
        parent_path: None,
        identity_id: identity.map(Into::into),
        verdict: Some("malicious".into()),
        score: Some(10),
        freshness: None,
        tab: false,
        origin: None,
    }
}

fn lock_row(
    pid: u32,
    image: &str,
    id: &str,
    verdict: &str,
    origin: Option<&'static str>,
) -> ProcRow {
    ProcRow {
        verdict: Some(verdict.into()),
        origin,
        ..row(pid, image, Some(id))
    }
}

#[test]
fn lockdown_stops_only_untrusted_and_holds_them_off_with_a_flag_after_three_comebacks() {
    let (s, fake, id) = setup();
    let safe = r"C:\Program Files\App\safe.exe";
    let mine = r"C:\Users\me\mine.exe";
    for (pid, img, verdict, origin) in [
        (800, BAD, "unknown", None),
        (801, safe, "safe", None),
        (802, mine, "unknown", Some("user")),
        (803, r"C:\Windows\System32\lsass.exe", "unknown", None),
    ] {
        fake.spawn(pid, 1, img);
        s.put_process(lock_row(pid, img, &id, verdict, origin));
    }
    let r = s.purge_start(&json!({}), "user").unwrap();
    assert_eq!(r["active"], true);
    assert_eq!(r["stopped"], 1);
    assert_eq!(*fake.killed.lock().unwrap(), vec![800]);
    assert_eq!(r["spared"]["safe"], 1);
    assert_eq!(r["spared"]["user"], 1);
    assert_eq!(r["spared"]["never_kill"], 1);

    // It comes back: killed again, counted, and flagged for the advisor on the third time.
    for i in 0..3 {
        fake.spawn(810 + i, 1, BAD);
        let flagged = s.purge_scan();
        assert_eq!(flagged.len(), usize::from(i == 2), "comeback {i}");
    }
    let st = s.purge_status();
    assert_eq!(st["held"][0]["respawns"], 3);
    assert_eq!(st["held"][0]["flagged"], true);
    assert_eq!(
        fake.procs.lock().unwrap().len(),
        3,
        "trusted programs untouched"
    );

    // Ending the hold lets the program run again.
    assert_eq!(s.purge_stop("user")["active"], false);
    fake.spawn(820, 1, BAD);
    assert_eq!(s.purge_scan().len(), 0);
    assert!(fake.procs.lock().unwrap().iter().any(|p| p.pid == 820));
}
