//! docs/08 §5: the service's process mitigation policies apply and leave every Windows API it
//! uses working. A separate test binary, so the policies never leak into other tests.
#![cfg(all(windows, feature = "integration"))]

use std::path::Path;

use vigil_win::harden::{MITIGATIONS, apply_mitigations, mitigation_flags};

#[test]
fn mitigations_apply_and_the_service_apis_still_work() {
    let failed: Vec<_> = apply_mitigations()
        .into_iter()
        .map(|(p, e)| format!("{p}: {e}"))
        .collect();
    assert!(failed.is_empty(), "{failed:?}");
    for (name, policy, flags) in MITIGATIONS {
        let got = mitigation_flags(policy).unwrap_or_default();
        assert_eq!(got & flags, flags, "{name} not in effect");
    }

    let engine = vigil_win::wfp::Engine::open_dynamic().unwrap();
    engine.list_filters(vigil_win::wfp::Scope::Dynamic).unwrap();
    let cipher = vigil_win::dpapi::protect(b"secret", b"entropy").unwrap();
    assert_eq!(
        vigil_win::dpapi::unprotect(&cipher, b"entropy").unwrap(),
        b"secret"
    );
    let notepad = r"C:\Windows\System32\notepad.exe";
    assert!(vigil_win::trust::verify(notepad).ms_root);
    assert_eq!(
        vigil_win::hash::hash_file(Path::new(notepad))
            .unwrap()
            .len(),
        64
    );
    assert!(
        !vigil_win::process::snapshot().unwrap().is_empty(),
        "no processes seen"
    );
}
