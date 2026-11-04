//! Kill policy against a fake process table: T-KILL-01 (respawn) and T-KILL-02 (protected target).

use std::sync::{Arc, Mutex};

use serde_json::json;
use vigil_store::repo::{Executable, NewEvaluation, insert_evaluation, upsert_executable};
use vigil_svc::kill::{KillOutcome, ProcessControl, Snap};
use vigil_svc::state::{Options, ProcRow, Shared};

const BAD: &str = r"C:\Temp\bad.exe";

#[derive(Default)]
struct Fake {
    procs: Mutex<Vec<Snap>>,
    killed: Mutex<Vec<u32>>,
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
    }
}

fn kill(s: &Shared, pid: u32, extra: &serde_json::Value) -> serde_json::Value {
    let mut p = json!({ "pid": pid, "start_time": format!("t{pid}") });
    p.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    s.kill_process(&p, "user").unwrap()
}

#[test]
fn t_kill_02_protected_target_is_refused_and_not_terminated() {
    let (s, fake, _) = setup();
    fake.spawn(500, 4, r"C:\Windows\System32\lsass.exe");
    let r = kill(&s, 500, &json!({}));
    assert_eq!(r["ok"], false);
    assert_eq!(r["error_code"], "protected_target");
    assert!(fake.killed.lock().unwrap().is_empty());
}

#[test]
fn never_kill_yields_to_a_masquerade_hard_rule() {
    let (s, fake, id) = setup();
    // A fake lsass.exe that fired HR-002 is provably an impostor and may be killed.
    s.with_store(|c| {
        let ev = NewEvaluation {
            score: 0,
            verdict: "malicious".into(),
            hard_rule: Some("HR-002".into()),
            signals_json: "[]".into(),
            rule_pack_version: "1".into(),
            source: "rules".into(),
        };
        insert_evaluation(c, id.parse().unwrap(), &ev, "2026-02-01T00:00:00Z").unwrap();
    });
    fake.spawn(501, 4, r"C:\Users\Public\lsass.exe");
    s.put_process(row(501, r"C:\Users\Public\lsass.exe", Some(&id)));
    assert_eq!(kill(&s, 501, &json!({}))["ok"], true);
}

#[test]
fn t_kill_01_every_respawn_and_renamed_copy_is_killed_and_counted() {
    let (s, fake, id) = setup();
    fake.spawn(600, 1, BAD);
    s.put_process(row(600, BAD, Some(&id)));
    assert_eq!(kill(&s, 600, &json!({}))["ok"], true);

    for i in 0..20 {
        fake.spawn(700 + i, 1, BAD);
        assert_eq!(s.respawn_scan(), 1, "respawn {i}");
    }
    fake.spawn(900, 1, r"D:\renamed\copy.exe");
    assert_eq!(s.respawn_scan(), 1, "same hash, different name");
    fake.spawn(901, 1, r"C:\Windows\notepad.exe");
    assert_eq!(s.respawn_scan(), 0, "unrelated image untouched");

    let n = s
        .with_store(|c| vigil_store::blocks::active(c).unwrap()[0].respawn_kills)
        .unwrap();
    assert_eq!(n, 21);
}

#[test]
fn tree_kill_takes_leaves_first_and_skips_protected_children() {
    let (s, fake, id) = setup();
    fake.spawn(10, 1, BAD);
    fake.spawn(11, 10, r"C:\Temp\child.exe");
    fake.spawn(12, 11, r"C:\Temp\grand.exe");
    fake.spawn(13, 10, r"C:\Windows\System32\lsass.exe");
    s.put_process(row(10, BAD, Some(&id)));
    assert_eq!(kill(&s, 10, &json!({ "tree": true }))["ok"], true);
    assert_eq!(*fake.killed.lock().unwrap().first().unwrap(), 12);
    assert!(!fake.killed.lock().unwrap().contains(&13));
    assert_eq!(*fake.killed.lock().unwrap().last().unwrap(), 10);
}

#[test]
fn auto_kill_does_nothing_outside_enforce() {
    let (s, fake, id) = setup();
    fake.spawn(800, 1, BAD);
    s.put_process(row(800, BAD, Some(&id)));
    assert_eq!(s.auto_kill_malicious(), 0, "observe mode never kills");
    assert!(fake.killed.lock().unwrap().is_empty());
}
