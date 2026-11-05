//! Kill policy against a fake process table: T-KILL-01 (respawn) and T-KILL-02 (protected target).

use std::sync::{Arc, Mutex};

use serde_json::json;
use vigil_store::persistence::Found;
use vigil_store::repo::{Executable, NewEvaluation, insert_evaluation, upsert_executable};
use vigil_svc::kill::{KillOutcome, ProcessControl, Snap};
use vigil_svc::state::{Options, ProcRow, Shared};

const BAD: &str = r"C:\Temp\bad.exe";
const LAUNCHER: &str = r"C:\Temp\run.exe";

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
        origin: None,
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

#[test]
fn t_pers_01_scan_disable_restore_delete_follow_the_state_machine() {
    let (s, fake, _) = setup();
    fake.items
        .lock()
        .unwrap()
        .push(found("run_key", "HKCU-Run-x"));
    let scan = s.persistence_scan(Some(BAD)).unwrap();
    let id = scan["findings"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(scan["findings"][0]["status"], "found");

    let apply =
        |action: &str| s.persistence_apply(&json!({ "item_id": id, "action": action }), "user");
    assert_eq!(
        apply("restore").unwrap()["ok"],
        false,
        "nothing to restore yet"
    );
    assert!(apply("delete").is_err(), "delete needs a prior disable");
    assert_eq!(apply("disable").unwrap()["ok"], true);
    assert!(fake.items.lock().unwrap().is_empty());
    assert_eq!(apply("restore").unwrap()["ok"], true);
    assert_eq!(fake.items.lock().unwrap().len(), 1);
    assert_eq!(apply("disable").unwrap()["ok"], true);
    assert_eq!(apply("delete").unwrap()["ok"], true);

    let page = s.audit_query(&json!({})).unwrap();
    assert_eq!(page["chain_ok"], true);
    let n = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "persistence_action")
        .count();
    assert_eq!(n, 4);
}

#[test]
fn persistence_never_touches_a_protected_system_image() {
    let (s, fake, _) = setup();
    let mut f = found("service", "service:lsass");
    f.image_path = Some(r"C:\Windows\System32\lsass.exe".into());
    fake.items.lock().unwrap().push(f);
    let scan = s.persistence_scan(None).unwrap();
    let id = scan["findings"][0]["id"].as_str().unwrap();
    let r = s
        .persistence_apply(&json!({ "item_id": id, "action": "disable" }), "user")
        .unwrap();
    assert_eq!(r["error_code"], "protected_target");
    assert_eq!(fake.items.lock().unwrap().len(), 1);
}

/// Parent 900 with `n` live same-image children, all known to the fake table and the row map.
fn cloner(s: &Shared, fake: &Fake, id: &str, verdict: &str, n: u32) {
    fake.spawn(900, 1, BAD);
    let mut parent = row(900, BAD, Some(id));
    parent.verdict = Some(verdict.into());
    s.put_process(parent);
    for pid in 901..901 + n {
        fake.spawn(pid, 900, BAD);
        let mut r = row(pid, BAD, Some(id));
        r.ppid = 900;
        r.verdict = Some(verdict.into());
        s.put_process(r);
    }
}

#[test]
fn a_self_cloning_program_is_killed_in_any_mode() {
    let (s, fake, id) = setup();
    s.set_mode("observe", true).unwrap();
    cloner(&s, &fake, &id, "unknown", 12);
    assert_eq!(s.storm_scan(), 1, "observe mode still stops a storm");
    assert!(fake.killed.lock().unwrap().contains(&900));
}

#[test]
fn sibling_clones_of_a_safe_program_are_left_alone() {
    let (s, fake, id) = setup();
    cloner(&s, &fake, &id, "safe", 12);
    assert_eq!(s.storm_scan(), 0);
    assert!(fake.killed.lock().unwrap().is_empty());
}

#[test]
fn a_hijacked_safe_program_is_reclassified_malicious_and_killed() {
    let (s, fake, id) = setup();
    fake.spawn(900, 1, BAD);
    let mut parent = row(900, BAD, Some(&id));
    parent.verdict = Some("safe".into());
    s.put_process(parent);
    for pid in 901..913 {
        fake.spawn(pid, 900, r"C:\Windows\System32\cmd.exe");
        let mut r = row(pid, r"C:\Windows\System32\cmd.exe", None);
        r.ppid = 900;
        r.verdict = Some("safe".into());
        s.put_process(r);
    }
    assert_eq!(s.storm_scan(), 1);
    assert!(fake.killed.lock().unwrap().contains(&900));
    let latest = s
        .with_store(|c| vigil_store::repo::latest_evaluation(c, id.parse().unwrap()))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(latest.verdict, "malicious");
}

#[test]
fn a_signed_ide_running_many_shells_is_not_killed() {
    let (s, fake, id) = setup();
    s.with_store(|c| {
        c.execute(
            "UPDATE executables SET signature_status = 'valid_embedded' WHERE id = ?1",
            [id.parse::<i64>().unwrap()],
        )
    })
    .unwrap()
    .unwrap();
    fake.spawn(900, 1, BAD);
    s.put_process(row(900, BAD, Some(&id)));
    for pid in 901..913 {
        fake.spawn(pid, 900, r"C:\Windows\System32\cmd.exe");
        let mut r = row(pid, r"C:\Windows\System32\cmd.exe", None);
        r.ppid = 900;
        s.put_process(r);
    }
    assert_eq!(
        s.storm_scan(),
        0,
        "a validly signed program is left to the advisor"
    );
    assert!(fake.killed.lock().unwrap().is_empty());
}

/// A freshly relaunched program has no identity yet; a storm verdict on a guess would kill a real app.
#[test]
fn a_program_still_being_classified_is_never_stormed() {
    let (s, fake, _) = setup();
    fake.spawn(900, 1, BAD);
    s.put_process(row(900, BAD, None));
    for pid in 901..913 {
        fake.spawn(pid, 900, BAD);
        let mut r = row(pid, BAD, None);
        r.ppid = 900;
        s.put_process(r);
    }
    assert_eq!(s.storm_scan(), 0);
    assert!(fake.killed.lock().unwrap().is_empty());
}

#[test]
fn a_signed_program_with_nested_copies_is_left_to_the_advisor() {
    let (s, fake, id) = setup();
    s.with_store(|c| {
        c.execute(
            "UPDATE executables SET signature_status = 'valid_embedded' WHERE id = ?1",
            [id.parse::<i64>().unwrap()],
        )
    })
    .unwrap()
    .unwrap();
    fake.spawn(900, 1, BAD);
    s.put_process(row(900, BAD, Some(&id)));
    for pid in 901..909 {
        fake.spawn(pid, pid - 1, BAD);
        let mut r = row(pid, BAD, Some(&id));
        r.ppid = pid - 1;
        s.put_process(r);
    }
    assert_eq!(s.storm_scan(), 0);
    assert!(fake.killed.lock().unwrap().is_empty());
}

/// A killed program reopened by the user is frozen and asked about; the answer decides (docs/18 §4).
fn reopen_by_user(s: &Shared, fake: &Fake, id: &str, pid: u32) {
    fake.spawn(pid, 1, BAD);
    let mut r = row(pid, BAD, Some(id));
    r.origin = Some("user");
    s.put_process(r);
}

#[test]
fn reopen_by_user_is_frozen_then_allow_lifts_the_kill() {
    let (s, fake, id) = setup();
    fake.spawn(600, 1, BAD);
    s.put_process(row(600, BAD, Some(&id)));
    assert_eq!(kill(&s, 600, &json!({}))["ok"], true);

    reopen_by_user(&s, &fake, &id, 700);
    assert_eq!(s.respawn_scan(), 0, "frozen, not killed");
    assert_eq!(*fake.frozen.lock().unwrap(), [700]);

    s.reopen_answer(&json!({ "pid": 700, "start_time": "t700", "allow": true }))
        .unwrap();
    assert_eq!(*fake.thawed.lock().unwrap(), [700]);
    assert!(
        s.with_store(|c| vigil_store::blocks::active(c).unwrap().is_empty())
            .unwrap()
    );
    assert!(
        s.reopen_answer(&json!({ "pid": 700, "start_time": "t700", "allow": true }))
            .is_err()
    );
}

#[test]
fn reopen_by_user_keep_stopped_kills_and_stays_quiet() {
    let (s, fake, id) = setup();
    fake.spawn(600, 1, BAD);
    s.put_process(row(600, BAD, Some(&id)));
    assert_eq!(kill(&s, 600, &json!({}))["ok"], true);

    reopen_by_user(&s, &fake, &id, 700);
    assert_eq!(s.respawn_scan(), 0);
    s.reopen_answer(&json!({ "pid": 700, "start_time": "t700", "allow": false }))
        .unwrap();
    assert!(fake.killed.lock().unwrap().contains(&700));

    reopen_by_user(&s, &fake, &id, 701);
    assert_eq!(s.respawn_scan(), 1, "silenced: killed without a new prompt");
    assert_eq!(*fake.frozen.lock().unwrap(), [700]);
}

#[test]
fn reopen_by_a_script_is_killed_without_a_prompt() {
    let (s, fake, id) = setup();
    fake.spawn(600, 1, BAD);
    s.put_process(row(600, BAD, Some(&id)));
    assert_eq!(kill(&s, 600, &json!({}))["ok"], true);

    fake.spawn(700, 1, BAD);
    let mut r = row(700, BAD, Some(&id));
    r.origin = Some("script");
    s.put_process(r);
    assert_eq!(s.respawn_scan(), 1);
    assert!(fake.frozen.lock().unwrap().is_empty());
}

#[test]
fn a_launcher_flooding_respawns_is_asked_about_exactly_once() {
    let (s, fake, id) = setup();
    let mut bus = s.subscribe_bus();
    fake.spawn(600, 1, BAD);
    s.put_process(row(600, BAD, Some(&id)));
    assert_eq!(kill(&s, 600, &json!({}))["ok"], true);

    fake.spawn(50, 1, LAUNCHER);
    for i in 0..20 {
        fake.spawn(700 + i, 50, BAD);
        assert_eq!(s.respawn_scan(), 1, "respawn {i} still killed");
    }
    let mut prompts = 0;
    while let Ok(e) = bus.try_recv() {
        if e.method == "event.launcher_prompt" {
            prompts += 1;
            assert_eq!(e.params["launcher"], LAUNCHER);
        }
    }
    assert_eq!(prompts, 1);

    s.launcher_answer(&json!({ "launcher": LAUNCHER, "action": "allow" }))
        .unwrap();
    assert!(
        s.with_store(|c| vigil_store::blocks::active(c).unwrap().is_empty())
            .unwrap()
    );
    assert!(
        s.launcher_answer(&json!({ "launcher": LAUNCHER, "action": "allow" }))
            .is_err()
    );
}

#[test]
fn stopping_a_launcher_kills_it() {
    let (s, fake, id) = setup();
    fake.spawn(600, 1, BAD);
    s.put_process(row(600, BAD, Some(&id)));
    assert_eq!(kill(&s, 600, &json!({}))["ok"], true);
    fake.spawn(50, 1, LAUNCHER);
    s.put_process(row(50, LAUNCHER, None));
    for i in 0..5 {
        fake.spawn(700 + i, 50, BAD);
        s.respawn_scan();
    }
    s.launcher_answer(&json!({ "launcher": LAUNCHER, "action": "stop" }))
        .unwrap();
    assert!(fake.killed.lock().unwrap().contains(&50));
}
