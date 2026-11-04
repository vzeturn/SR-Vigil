//! Observation → Facts → verdict, using the real rule files and a Windows-like machine context.

use std::collections::{HashMap, HashSet};

use vigil_core::analysis::path::{PathEnv, normalize};
use vigil_core::eval::evaluate;
use vigil_core::observe::{Behaviour, Context, Observation, SignerInfo, VersionInfo, build_facts};
use vigil_core::rules::{Lolbins, Publishers, RuleStore, SignatureState, SystemProcesses, Verdict};

fn ctx() -> Context {
    Context {
        path_env: PathEnv {
            system_root: normalize(r"C:\Windows"),
            program_files: vec![
                normalize(r"C:\Program Files"),
                normalize(r"C:\Program Files (x86)"),
            ],
            user_writable: vec![normalize(r"C:\ProgramData")],
            vigil_data_dir: normalize(r"C:\ProgramData\Vigil"),
            removable_drives: vec![],
        },
        vars: HashMap::from([("systemroot".into(), r"c:\windows".into())]),
        system: SystemProcesses::parse("t", include_str!("../../../rules/system_processes.toml"))
            .unwrap(),
        lolbins: Lolbins::parse("t", include_str!("../../../rules/lolbins.toml")).unwrap(),
        publishers: Publishers::parse("t", include_str!("../../../rules/publishers.toml")).unwrap(),
        locked_thumbprints: HashSet::new(),
    }
}

fn ms_signer() -> SignerInfo {
    SignerInfo {
        state: SignatureState::ValidCatalog,
        org: Some("Microsoft Corporation".into()),
        chain_names: vec!["Microsoft Root Certificate Authority 2010".into()],
        thumbprints: vec![],
        ms_root: true,
        os_signed: true,
    }
}

fn obs(path: &str, parent: Option<&str>, signer: SignerInfo, company: &str) -> Observation {
    Observation {
        path: path.into(),
        parent_path: parent.map(Into::into),
        signer,
        version: VersionInfo {
            company: company.into(),
            ..VersionInfo::default()
        },
        behaviour: Behaviour::default(),
        vt_detections: None,
        vt_first_seen_days: None,
        user_denylisted: false,
        user_allowed: false,
        vigil_self: false,
    }
}

fn verdict(o: &Observation) -> (u8, Verdict, Vec<String>) {
    let pack = RuleStore::from_embedded().unwrap().active();
    let e = evaluate(&pack, &build_facts(&ctx(), o));
    (
        e.score,
        e.verdict,
        e.signals.into_iter().map(|s| s.id).collect(),
    )
}

#[test]
fn genuine_svchost_is_safe() {
    let o = obs(
        r"C:\Windows\System32\svchost.exe",
        Some(r"C:\Windows\System32\services.exe"),
        ms_signer(),
        "Microsoft Corporation",
    );
    assert_eq!(verdict(&o).0, 100);
    assert_eq!(verdict(&o).1, Verdict::Safe);
}

#[test]
fn svchost_copy_in_temp_is_malicious_even_if_signed() {
    let o = obs(
        r"C:\Users\x\AppData\Local\Temp\svchost.exe",
        None,
        ms_signer(),
        "Microsoft Corporation",
    );
    let (score, v, ids) = verdict(&o);
    assert!(ids.contains(&"HR-002".to_string()));
    assert_eq!((score, v), (0, Verdict::Malicious));
}

#[test]
fn svchost_with_wrong_parent_is_hr003() {
    let o = obs(
        r"C:\Windows\System32\svchost.exe",
        Some(r"C:\Users\x\evil.exe"),
        ms_signer(),
        "Microsoft Corporation",
    );
    assert!(verdict(&o).2.contains(&"HR-003".to_string()));
}

#[test]
fn unsigned_lookalike_in_temp_is_malicious() {
    let o = obs(
        r"C:\Users\x\AppData\Local\Temp\svch0st.exe",
        None,
        SignerInfo::unsigned(),
        "",
    );
    let (score, v, ids) = verdict(&o);
    assert!(ids.contains(&"SIG-020".to_string()));
    assert_eq!((score, v), (0, Verdict::Malicious));
}

#[test]
fn unsigned_binary_claiming_microsoft_is_hr007() {
    let o = obs(
        r"D:\tools\thing.exe",
        None,
        SignerInfo::unsigned(),
        "Microsoft Corporation",
    );
    assert!(verdict(&o).2.contains(&"HR-007".to_string()));
}

#[test]
fn pinned_microsoft_signer_requires_root_match() {
    let mut o = obs(
        r"C:\Program Files\Tool\t.exe",
        None,
        ms_signer(),
        "Microsoft Corporation",
    );
    assert!(
        verdict(&o).2.contains(&"SIG-001".to_string())
            || verdict(&o).2.contains(&"SIG-002".to_string())
    );
    o.signer.chain_names = vec!["Some Other Root".into()];
    o.signer.ms_root = false;
    let ids = verdict(&o).2;
    assert!(ids.contains(&"SIG-003".to_string()) && !ids.contains(&"SIG-002".to_string()));
}

#[test]
fn lolbin_outbound_is_capped() {
    let mut o = obs(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        None,
        ms_signer(),
        "Microsoft Corporation",
    );
    o.behaviour = Behaviour {
        has_outbound: true,
        dest_public: true,
        ..Behaviour::default()
    };
    let (score, v, _) = verdict(&o);
    assert_eq!((score, v), (70, Verdict::Unknown));
}
