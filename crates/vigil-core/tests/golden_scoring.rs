//! Golden tests: every row of `docs/03 §3`, evaluated with the embedded default rule pack.

use vigil_core::eval::{Evaluation, Facts, evaluate};
use vigil_core::rules::{PathClass, RuleStore, SignatureState, Verdict};

fn eval(f: &Facts) -> Evaluation {
    evaluate(&RuleStore::from_embedded().unwrap().active(), f)
}

fn ids(e: &Evaluation) -> Vec<&str> {
    e.signals.iter().map(|s| s.id.as_str()).collect()
}

fn signed(path_class: PathClass) -> Facts {
    Facts {
        signature: SignatureState::ValidEmbedded,
        path_class,
        ..Facts::default()
    }
}

fn unsigned(path_class: PathClass) -> Facts {
    Facts {
        path_class,
        ..Facts::default()
    }
}

#[track_caller]
fn check(f: &Facts, expect_ids: &[&str], score: u8, verdict: Verdict) {
    let e = eval(f);
    for id in expect_ids {
        assert!(ids(&e).contains(id), "missing {id} in {:?}", ids(&e));
    }
    assert_eq!((e.score, e.verdict), (score, verdict), "{:?}", ids(&e));
}

#[test]
fn svchost_ms_signed_system() {
    let f = Facts {
        signer_ms_root: true,
        os_signed: true,
        company_matches_signer: true,
        name_in_canonical_set: true,
        parent_check_applies: true,
        never_kill_set: true,
        ..signed(PathClass::System)
    };
    check(&f, &["SIG-001", "SIG-004", "LOC-001"], 100, Verdict::Safe);
    assert!(eval(&f).never_kill);
}

#[test]
fn chrome_pinned_publisher() {
    let f = Facts {
        signer_pinned: true,
        company_matches_signer: true,
        ..signed(PathClass::ProgramFiles)
    };
    check(&f, &["SIG-002", "SIG-004", "LOC-001"], 100, Verdict::Safe);
}

#[test]
fn small_vendor_program_files() {
    let f = Facts {
        company_matches_signer: true,
        ..signed(PathClass::ProgramFiles)
    };
    check(&f, &["SIG-003", "SIG-004", "LOC-001"], 88, Verdict::Safe);
}

#[test]
fn per_user_signed_app() {
    let f = Facts {
        company_matches_signer: true,
        ..signed(PathClass::UserWritable)
    };
    check(&f, &["SIG-003", "SIG-004"], 83, Verdict::Safe);
}

#[test]
fn signed_with_conflicting_metadata() {
    let f = Facts {
        company_conflicts_signer: true,
        ..signed(PathClass::UserWritable)
    };
    check(&f, &["SIG-003", "SIG-014"], 50, Verdict::Unknown);
}

#[test]
fn unsigned_downloads_with_dns() {
    let f = Facts {
        has_outbound: true,
        dest_public: true,
        ..unsigned(PathClass::UserWritable)
    };
    check(&f, &["SIG-010"], 35, Verdict::Unknown);
}

#[test]
fn signed_app_reaching_a_listed_bad_host() {
    let f = Facts {
        company_matches_signer: true,
        has_outbound: true,
        dest_public: true,
        bad_destination: true,
        ..signed(PathClass::ProgramFiles)
    };
    check(&f, &["NET-001"], 43, Verdict::Unknown);
}

#[test]
fn unsigned_tool_reaching_a_generated_name() {
    let f = Facts {
        has_outbound: true,
        dest_public: true,
        generated_dest_name: true,
        risky_port_or_tld: true,
        ..unsigned(PathClass::UserWritable)
    };
    check(&f, &["SIG-010", "NET-002", "BEH-004"], 10, Verdict::Unknown);
}

#[test]
fn unsigned_temp_beaconing() {
    let f = Facts {
        beaconing: true,
        ..unsigned(PathClass::UserWritable)
    };
    check(&f, &["SIG-010", "BEH-002"], 5, Verdict::Unknown);
}

#[test]
fn typosquat_clamps_at_zero() {
    let f = Facts {
        typosquat: true,
        ..unsigned(PathClass::UserWritable)
    };
    check(&f, &["SIG-010", "SIG-020"], 0, Verdict::Unknown);
}

#[test]
fn svchost_in_temp_is_hr002() {
    let f = Facts {
        name_in_canonical_set: true,
        at_canonical_path: false,
        ..unsigned(PathClass::UserWritable)
    };
    let e = eval(&f);
    assert!(ids(&e).contains(&"HR-002"));
    assert_eq!((e.score, e.verdict), (0, Verdict::Malicious));
}

#[test]
fn powershell_outbound_is_capped_at_70() {
    let f = Facts {
        signer_ms_root: true,
        os_signed: true,
        company_matches_signer: true,
        lolbin: true,
        has_outbound: true,
        dest_public: true,
        ..signed(PathClass::System)
    };
    check(
        &f,
        &["SIG-001", "SIG-004", "LOC-001", "BEH-001"],
        70,
        Verdict::Unknown,
    );
}

#[test]
fn powershell_copied_to_downloads() {
    let f = Facts {
        signer_pinned: true,
        os_signed: true,
        company_matches_signer: true,
        lolbin: true,
        has_outbound: true,
        dest_public: true,
        ..signed(PathClass::UserWritable)
    };
    check(
        &f,
        &["SIG-002", "SIG-004", "SIG-015", "BEH-001"],
        43,
        Verdict::Unknown,
    );
}

#[test]
fn unsigned_microsoft_metadata_is_hr007() {
    let f = Facts {
        claims_pinned_publisher: true,
        ..unsigned(PathClass::Other)
    };
    let e = eval(&f);
    assert!(ids(&e).contains(&"HR-007"));
    assert_eq!((e.score, e.verdict), (0, Verdict::Malicious));
}

#[test]
fn replaced_file_loses_user_allow() {
    let allowed = Facts {
        user_allowed: true,
        ..unsigned(PathClass::UserWritable)
    };
    check(&allowed, &["HA-002"], 100, Verdict::Safe);
    let replaced = Facts {
        user_allowed: false,
        ..allowed
    };
    check(&replaced, &["SIG-010"], 35, Verdict::Unknown);
}

#[test]
fn hard_rule_beats_user_allow_but_not_self() {
    let f = Facts {
        user_allowed: true,
        signature: SignatureState::Invalid,
        ..Facts::default()
    };
    check(&f, &["HR-001", "HA-002"], 0, Verdict::Malicious);
    let own = Facts {
        vigil_self: true,
        ..f
    };
    check(&own, &["HA-001"], 100, Verdict::Safe);
}

#[test]
fn terminal_rule_still_lists_other_signals() {
    let f = Facts {
        signer_pinned: true,
        signature: SignatureState::Revoked,
        path_class: PathClass::ProgramFiles,
        ..Facts::default()
    };
    let e = eval(&f);
    assert!(ids(&e).contains(&"HR-004") && ids(&e).contains(&"LOC-001"));
    assert_eq!(e.verdict, Verdict::Malicious);
}

#[test]
fn virustotal_bands() {
    let vt = |d| Facts {
        vt_detections: Some(d),
        vt_first_seen_days: Some(90),
        company_matches_signer: false,
        ..signed(PathClass::Other)
    };
    check(&vt(0), &["SIG-003", "REP-001"], 85, Verdict::Safe);
    check(&vt(2), &["REP-010"], 55, Verdict::Unknown);
    check(&vt(6), &["REP-011"], 15, Verdict::Unknown);
    check(&vt(10), &["HR-005"], 0, Verdict::Malicious);
    let off = Facts {
        vt_detections: None,
        ..vt(0)
    };
    check(&off, &["SIG-003"], 75, Verdict::Unknown);
}
