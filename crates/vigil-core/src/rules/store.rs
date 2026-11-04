use std::path::Path;
use std::sync::{Arc, RwLock};

use super::{RuleError, RulePack};

/// The default pack compiled into the binary.
pub const EMBEDDED_DEFAULT: &str = include_str!("../../../../rules/default.toml");

/// Holds the active pack. A failed reload leaves the previous pack in place (fail closed to last good).
#[derive(Debug)]
pub struct RuleStore {
    active: RwLock<Arc<RulePack>>,
}

impl RuleStore {
    /// Start from the embedded defaults.
    pub fn from_embedded() -> Result<Self, RuleError> {
        let pack = RulePack::parse("embedded:default.toml", EMBEDDED_DEFAULT)?;
        Ok(Self {
            active: RwLock::new(Arc::new(pack)),
        })
    }

    /// The currently active pack.
    pub fn active(&self) -> Arc<RulePack> {
        // A poisoned lock still holds a fully valid pack: swaps only ever store complete packs.
        Arc::clone(
            &self
                .active
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Rebuild embedded defaults + every `*.toml` in `overrides_dir` (sorted by file name).
    /// A missing directory means "no overrides". On any error the active pack is unchanged and the
    /// error is returned so the caller can write the audit entry.
    pub fn reload(&self, overrides_dir: &Path) -> Result<Arc<RulePack>, RuleError> {
        let mut pack = RulePack::parse("embedded:default.toml", EMBEDDED_DEFAULT)?;
        for (name, text) in read_overrides(overrides_dir)? {
            pack = pack.with_override(&name, &text)?;
        }
        let pack = Arc::new(pack);
        *self
            .active
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::clone(&pack);
        Ok(pack)
    }
}

fn read_overrides(dir: &Path) -> Result<Vec<(String, String)>, RuleError> {
    let io_err = |p: &Path, e: &std::io::Error| RuleError::Io {
        path: p.display().to_string(),
        message: e.to_string(),
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(dir, &e)),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| io_err(dir, &e))?.path();
        if path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("toml"))
            && path.is_file()
        {
            files.push(path);
        }
    }
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p).map_err(|e| io_err(&p, &e))?;
            let name = p
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            Ok((name, text))
        })
        .collect()
}
