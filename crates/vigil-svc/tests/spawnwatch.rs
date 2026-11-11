//! PRC-001 in the service (`docs/15 §2`): a suspicious child marks its parent once.

use serde_json::json;
use vigil_svc::state::{Options, ProcRow, Shared};

const WORD: &str = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
const CMD: &str = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe";

fn setup() -> Shared {
    let s = Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec![],
    });
    s.put_process(ProcRow {
        pid: 4,
        start_time: "t4".into(),
        ppid: 0,
        name: "WINWORD.EXE".into(),
        path: Some(WORD.into()),
        parent_path: None,
        identity_id: None,
        verdict: Some("safe".into()),
        score: Some(95),
        freshness: None,
        tab: false,
        origin: None,
    });
    s
}

#[test]
fn office_shell_marks_the_parent_and_rejudges_once() {
    let s = setup();
    s.note_spawn(4, CMD, Some("cmd /c whoami"));
    assert!(s.spawned_suspicious_child(WORD));
    assert_eq!(s.take_rejudge_paths(), vec![WORD.to_string()]);
    s.note_spawn(4, CMD, Some("cmd /c whoami"));
    assert!(
        s.take_rejudge_paths().is_empty(),
        "same finding re-judges once"
    );
}

#[test]
fn unknown_parent_or_ordinary_child_changes_nothing() {
    let s = setup();
    s.note_spawn(77, CMD, Some("cmd /c whoami"));
    s.note_spawn(4, r"C:\Windows\notepad.exe", None);
    assert!(!s.spawned_suspicious_child(WORD));
    assert_eq!(s.take_rejudge_paths(), Vec::<String>::new());
}
