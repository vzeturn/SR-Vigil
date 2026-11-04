//! Dependency rules from CLAUDE.md: core depends on no Vigil crate; store/ipc/ai only on core;
//! only `vigil-win` may use unsafe (every other crate forbids it).

use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vigil_deps(crate_dir: &str) -> Vec<String> {
    let text =
        std::fs::read_to_string(root().join("crates").join(crate_dir).join("Cargo.toml")).unwrap();
    let doc: toml::Table = text.parse().unwrap();
    ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .filter_map(|k| doc.get(*k)?.as_table())
        .flat_map(|t| t.keys().cloned())
        .filter(|k| k.starts_with("vigil-"))
        .collect()
}

#[test]
fn core_depends_on_no_vigil_crate() {
    assert_eq!(vigil_deps("vigil-core"), Vec::<String>::new());
}

#[test]
fn store_ipc_ai_depend_only_on_core() {
    for c in ["vigil-store", "vigil-ipc", "vigil-ai"] {
        assert!(
            vigil_deps(c).iter().all(|d| d == "vigil-core"),
            "{c}: {:?}",
            vigil_deps(c)
        );
    }
}

#[test]
fn only_vigil_win_may_use_unsafe() {
    for (dir, file) in [
        ("vigil-core", "src/lib.rs"),
        ("vigil-store", "src/lib.rs"),
        ("vigil-ipc", "src/lib.rs"),
        ("vigil-ai", "src/lib.rs"),
        ("vigil-svc", "src/main.rs"),
        ("vigilctl", "src/main.rs"),
    ] {
        let src = std::fs::read_to_string(root().join("crates").join(dir).join(file)).unwrap();
        assert!(
            src.contains("#![forbid(unsafe_code)]"),
            "{dir} must forbid unsafe_code"
        );
    }
}
