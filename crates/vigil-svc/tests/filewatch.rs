//! FIL-001/002 and RES-001 in the service (`docs/15 §2`): findings attach to the pid's program once.

use serde_json::json;
use vigil_svc::state::{Options, ProcRow, Shared};

const TOOL: &str = r"C:\Users\a\AppData\Local\Temp\tool.exe";
const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
const DEFENDER: &str = r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe";
const LOGINS: &str =
    r"\Device\HarddiskVolume3\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data";

fn row(pid: u32, path: &str) -> ProcRow {
    ProcRow {
        pid,
        start_time: format!("t{pid}"),
        ppid: 0,
        name: vigil_core::analysis::path::basename(path).into(),
        path: Some(path.into()),
        parent_path: None,
        identity_id: None,
        verdict: Some("unknown".into()),
        score: Some(50),
        freshness: None,
        tab: false,
        origin: None,
    }
}

fn setup() -> Shared {
    let s = Shared::new(Options {
        store: Some(vigil_store::open_in_memory().unwrap()),
        rules: json!([]),
        trust: vec![],
        rule_pack_version: "1".into(),
        network_critical: vec![],
        never_kill: vec![],
    });
    for (pid, path) in [(10, TOOL), (11, CHROME), (12, DEFENDER)] {
        s.put_process(row(pid, path));
    }
    s
}

#[test]
fn a_drop_marks_the_program_and_rejudges_it_once() {
    let s = setup();
    s.note_file_drop(10, r"C:\Users\a\Downloads\a.exe");
    s.note_file_drop(10, r"C:\Users\a\Downloads\b.exe");
    assert!(s.files_seen(TOOL).dropped_executable);
    assert_eq!(s.take_rejudge_paths(), vec![TOOL.to_string()]);
    s.note_file_drop(99, r"C:\Users\a\Downloads\c.exe");
    assert_eq!(s.take_rejudge_paths(), Vec::<String>::new());
}

#[test]
fn renames_count_only_past_the_threshold() {
    let s = setup();
    for i in 0..29 {
        s.note_rename(10, "locked", i);
    }
    assert!(!s.files_seen(TOOL).mass_renamed);
    s.note_rename(10, "locked", 29);
    assert!(s.files_seen(TOOL).mass_renamed);
}

#[test]
fn credential_store_access_depends_on_who_opens_it() {
    let s = setup();
    let store = vigil_core::analysis::fileact::sensitive_store(LOGINS).unwrap();
    s.note_credential_open(12, store);
    assert_eq!(
        s.files_seen(DEFENDER),
        vigil_core::observe::FileSeen::default()
    );
    s.note_credential_open(11, store);
    let chrome = s.files_seen(CHROME);
    assert!(chrome.credential_store_as_owner && !chrome.foreign_credential_store);
    s.note_credential_open(10, store);
    assert!(s.files_seen(TOOL).foreign_credential_store);
}
