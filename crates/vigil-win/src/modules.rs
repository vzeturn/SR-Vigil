//! Loaded-module inspection for DLL sideloading (T14, `docs/03` MOD-001).

use vigil_core::analysis::path::{classify, normalize};
use vigil_core::observe::Context;
use vigil_core::rules::PathClass;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};

use crate::trust;

/// Upper bound of signature checks per process, so one pathological process cannot stall a scan.
const MAX_CHECKS: usize = 16;

fn module_paths(pid: u32) -> Vec<String> {
    // SAFETY: plain Win32 call; the snapshot handle is closed below.
    let Ok(snap) =
        (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) })
    else {
        return Vec::new();
    };
    let mut entry = MODULEENTRY32W {
        dwSize: u32::try_from(size_of::<MODULEENTRY32W>()).unwrap_or(0),
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: `entry.dwSize` is set and `entry` outlives both calls.
    let mut more = unsafe { Module32FirstW(snap, &raw mut entry) }.is_ok();
    while more {
        let end = entry
            .szExePath
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExePath.len());
        out.push(String::from_utf16_lossy(&entry.szExePath[..end]));
        // SAFETY: same invariants as `Module32FirstW` above.
        more = unsafe { Module32NextW(snap, &raw mut entry) }.is_ok();
    }
    // SAFETY: `snap` was returned by a successful call and is closed exactly once.
    let _ = unsafe { CloseHandle(snap) };
    out
}

/// `true` when `pid` has loaded a module from a user-writable path that lacks a valid signature.
#[must_use]
pub fn has_unsigned_writable_module(ctx: &Context, pid: u32) -> bool {
    module_paths(pid)
        .into_iter()
        .filter(|p| classify(&normalize(p), &ctx.path_env) == PathClass::UserWritable)
        .take(MAX_CHECKS)
        .any(|p| !trust::verify(&p).valid())
}
