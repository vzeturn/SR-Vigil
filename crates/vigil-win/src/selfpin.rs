//! Vigil's own binaries (HA-001, `docs/03 §4`): pinned by SHA-256 the first time this process asks.
//!
//! The pin covers the Vigil executables next to the running one (the install directory, writable
//! only by administrators). A pinned path whose file no longer matches its pin is not Vigil.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::hash::hash_file;

const BINARIES: [&str; 3] = ["vigil-svc.exe", "vigil-ui.exe", "vigilctl.exe"];

struct Pin {
    path: PathBuf,
    sha256: String,
}

fn pins() -> &'static [Pin] {
    static PINS: OnceLock<Vec<Pin>> = OnceLock::new();
    PINS.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(Path::to_path_buf))
            .map(|dir| pin_dir(&dir))
            .unwrap_or_default()
    })
}

fn pin_dir(dir: &Path) -> Vec<Pin> {
    BINARIES
        .iter()
        .map(|name| dir.join(name))
        .filter_map(|path| hash_file(&path).ok().map(|sha256| Pin { path, sha256 }))
        .collect()
}

fn matches(pins: &[Pin], path: &str) -> bool {
    pins.iter()
        .find(|p| p.path.to_string_lossy().eq_ignore_ascii_case(path))
        .is_some_and(|p| hash_file(&p.path).is_ok_and(|h| h == p.sha256))
}

/// Whether `path` is one of Vigil's own binaries, unchanged since it was pinned.
#[must_use]
pub fn is_vigil_self(path: &str) -> bool {
    matches(pins(), path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_binary_matches_until_it_changes() {
        let dir = std::env::temp_dir().join(format!("vigil-selfpin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ui = dir.join("vigil-ui.exe");
        std::fs::write(&ui, b"vigil ui").unwrap();
        let pins = pin_dir(&dir);
        let path = ui.to_string_lossy().to_uppercase();

        assert!(matches(&pins, &path));
        assert!(!matches(&pins, &dir.join("other.exe").to_string_lossy()));
        std::fs::write(&ui, b"tampered").unwrap();
        assert!(!matches(&pins, &path));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
