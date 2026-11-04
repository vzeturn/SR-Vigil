#![cfg(windows)]
//! Windows integration: process snapshot, hashing, `WinVerifyTrust`, `VersionInfo`.
//!
//! All `unsafe` lives in this crate, each block with a `// SAFETY:` comment, behind safe APIs.
#![allow(clippy::missing_errors_doc)]

pub mod dpapi;
pub mod etw;
pub mod harden;
pub mod hash;
pub mod kill;
pub mod modules;
pub mod net;
pub mod observe;
pub mod persist;
pub mod pipe;
pub mod process;
pub mod trust;
pub mod version;
pub mod wfp;

/// Errors from the Windows layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("windows api: {0}")]
    Api(#[from] windows::core::Error),
    #[error("etw: {0}")]
    Etw(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
