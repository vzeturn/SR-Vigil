//! SHA-256 of files with a `(path, size, mtime)` cache.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use sha2::{Digest, Sha256};

type Key = (PathBuf, u64, Option<SystemTime>);

/// Hashes files, skipping the read when path, size and mtime are unchanged.
#[derive(Debug, Default)]
pub struct HashCache {
    entries: Mutex<HashMap<Key, String>>,
}

impl HashCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lower-case hex SHA-256 of `path`.
    pub fn sha256(&self, path: &Path) -> std::io::Result<String> {
        let meta = std::fs::metadata(path)?;
        let key = (path.to_path_buf(), meta.len(), meta.modified().ok());
        if let Some(h) = self.lock().get(&key) {
            return Ok(h.clone());
        }
        let digest = hash_file(path)?;
        self.lock().insert(key, digest.clone());
        Ok(digest)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Key, String>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Uncached SHA-256 of a file.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digest_and_cache_follows_content_changes() {
        let dir = std::env::temp_dir().join(format!("vigil-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.bin");
        std::fs::write(&p, b"abc").unwrap();
        let c = HashCache::new();
        assert_eq!(
            c.sha256(&p).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::write(&p, b"abcd").unwrap();
        assert_eq!(c.sha256(&p).unwrap(), hash_file(&p).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
