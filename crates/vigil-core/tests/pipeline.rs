//! Observation → Facts → verdict, using the real rule files and a Windows-like machine context.

use std::collections::HashMap;

use vigil_core::analysis::path::{PathEnv, normalize};
use vigil_core::eval::{Facts, evaluate};
use vigil_core::observe::{Behaviour, Context, Observation, SignerInfo, VersionInfo, build_facts};
use vigil_core::rules::{
    Lolbins, PathClass, Publishers, RuleStore, SignatureState, SystemProcesses, Verdict,
    VersionStatus,
};

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
        locked_thumbprints: HashMap::new(),
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
fn unsigned_writable_module_fires_mod_001() {
    let mut o = obs(
        r"C:\Program Files\Acme\acme.exe",
        None,
        ms_signer(),
        "Acme Corp",
    );
    assert!(!verdict(&o).2.contains(&"MOD-001".to_string()));
    o.behaviour.unsigned_writable_module = true;
    assert!(verdict(&o).2.contains(&"MOD-001".to_string()));
}

#[test]
fn unsigned_code_is_penalised_once() {
    let mut o = obs(
        r"C:\Users\x\AppData\Local\uv\tool.exe",
        None,
        SignerInfo::unsigned(),
        "",
    );
    let (alone, _, _) = verdict(&o);
    o.behaviour.unsigned_writable_module = true;
    let (both, _, ids) = verdict(&o);
    assert!(ids.contains(&"MOD-001".to_string()) && !ids.contains(&"SIG-010".to_string()));
    assert_eq!(
        both,
        alone + 15 - 30,
        "only the worst unsigned-code penalty counts"
    );
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

fn known_facts(status: VersionStatus, path_class: PathClass) -> Facts {
    Facts {
        signature: SignatureState::ValidEmbedded,
        path_class,
        known_software: true,
        version_status: status,
        ..Facts::default()
    }
}

fn ver_score(status: VersionStatus, path_class: PathClass) -> (u8, Vec<String>) {
    let pack = RuleStore::from_embedded().unwrap().active();
    let e = evaluate(&pack, &known_facts(status, path_class));
    let ids = e.signals.into_iter().map(|s| s.id).collect();
    (e.score, ids)
}

#[test]
fn version_tiers_cost_5_15_30_and_only_the_worst_applies() {
    let base = ver_score(VersionStatus::Unknown, PathClass::ProgramFiles);
    for (status, id, cost) in [
        (VersionStatus::Outdated, "VER-001", 5),
        (VersionStatus::FarBehind, "VER-002", 15),
        (VersionStatus::Vulnerable, "VER-003", 30),
    ] {
        let (score, ids) = ver_score(status, PathClass::ProgramFiles);
        assert_eq!(score, base.0 - cost, "{id}");
        assert_eq!(ids.iter().filter(|i| i.starts_with("VER-")).count(), 1);
        assert!(ids.iter().any(|i| i == id));
    }
}

#[test]
fn outdated_known_software_is_never_malicious_from_age_alone() {
    let (score, _) = ver_score(VersionStatus::Vulnerable, PathClass::ProgramFiles);
    assert!(score > vigil_core::consts::MALICIOUS_MAX, "{score}");
}

#[test]
fn version_penalty_needs_a_trusted_install_location() {
    let (_, ids) = ver_score(VersionStatus::Vulnerable, PathClass::UserWritable);
    assert!(!ids.iter().any(|i| i.starts_with("VER-")));
}

#[test]
fn a_package_from_a_known_source_offsets_the_unsigned_penalty_but_stays_unknown() {
    let pack = RuleStore::from_embedded().unwrap().active();
    let base = Facts {
        signature: SignatureState::Unsigned,
        path_class: PathClass::UserWritable,
        ..Facts::default()
    };
    let plain = evaluate(&pack, &base);
    let sourced = evaluate(
        &pack,
        &Facts {
            package_source_trusted: true,
            ..base
        },
    );
    assert_eq!(sourced.score, plain.score + 30);
    assert!(sourced.signals.iter().any(|s| s.id == "PKG-001"));
    assert!(sourced.score < vigil_core::consts::SAFE_MIN);
    assert!(sourced.score > vigil_core::consts::MALICIOUS_MAX);
}

#[test]
fn an_unsigned_download_costs_10_and_a_signed_one_costs_nothing() {
    let pack = RuleStore::from_embedded().unwrap().active();
    let unsigned = Facts {
        signature: SignatureState::Unsigned,
        path_class: PathClass::UserWritable,
        ..Facts::default()
    };
    let plain = evaluate(&pack, &unsigned).score;
    let web = evaluate(
        &pack,
        &Facts {
            from_internet: true,
            ..unsigned
        },
    );
    assert_eq!(web.score, plain - 10);
    assert!(web.signals.iter().any(|s| s.id == "SRC-001"));
    let signed = Facts {
        signature: SignatureState::ValidEmbedded,
        from_internet: true,
        ..Facts::default()
    };
    let e = evaluate(&pack, &signed);
    assert!(e.signals.iter().all(|s| s.id != "SRC-001"));
}

#[test]
fn a_known_good_hash_adds_15_but_never_makes_an_unsigned_file_safe() {
    let pack = RuleStore::from_embedded().unwrap().active();
    let unsigned = Facts {
        signature: SignatureState::Unsigned,
        path_class: PathClass::UserWritable,
        ..Facts::default()
    };
    let plain = evaluate(&pack, &unsigned).score;
    let known = evaluate(
        &pack,
        &Facts {
            hash_known_good: true,
            ..unsigned
        },
    );
    assert_eq!(known.score, plain + 15);
    assert!(known.signals.iter().any(|s| s.id == "HASH-001"));
    assert!(known.score < vigil_core::consts::SAFE_MIN);
}
