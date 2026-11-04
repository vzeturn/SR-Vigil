//! Self-protection primitives (docs/08 §5): DLL search-path lock-down and the data-directory ACL.

use std::path::Path;

use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};
use windows::Win32::System::Threading::{
    BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, SetPriorityClass,
};
use windows::core::{PCWSTR, PWSTR};

use crate::to_wide;

/// Protected DACL: SYSTEM and Administrators full control, inherited by children, nobody else.
pub const DATA_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Run below normal priority so scanning never competes with what the user is doing.
pub fn lower_priority() -> Result<(), windows::core::Error> {
    // SAFETY: the pseudo-handle from `GetCurrentProcess` is always valid for the calling process.
    unsafe { SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS) }
}

/// Only load DLLs from System32 for the rest of the process lifetime.
pub fn restrict_dll_search() -> Result<(), windows::core::Error> {
    // SAFETY: plain call with a documented flag; no pointers involved.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) }
}

fn free(ptr: *mut core::ffi::c_void) {
    if !ptr.is_null() {
        // SAFETY: `ptr` was allocated with LocalAlloc by the security APIs and is freed once.
        let _ = unsafe { LocalFree(HLOCAL(ptr)) };
    }
}

/// The directory's current DACL as SDDL (`None` when it cannot be read).
fn current_dacl_sddl(path: &Path) -> Option<String> {
    let wpath = to_wide(&path.to_string_lossy());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wpath` is NUL-terminated and outlives the call; `sd` is a valid out-pointer and is
    // released with `LocalFree` below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wpath.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &raw mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let mut text = PWSTR::null();
    // SAFETY: `sd` is the descriptor returned above; `text` is a valid out-pointer.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            1,
            DACL_SECURITY_INFORMATION,
            &raw mut text,
            None,
        )
    }
    .is_ok();
    let out = if ok {
        // SAFETY: on success `text` is a NUL-terminated wide string allocated by the API.
        let s = unsafe { text.to_string() }.ok();
        free(text.0.cast());
        s
    } else {
        None
    };
    free(sd.0);
    out
}

/// Make sure `dir` carries exactly [`DATA_DIR_SDDL`]. Returns `true` when the ACL had drifted and
/// was re-applied (the caller audits that), `false` when it was already correct.
pub fn ensure_data_dir_acl(dir: &Path) -> Result<bool, windows::core::Error> {
    if current_dacl_sddl(dir).as_deref() == Some(DATA_DIR_SDDL) {
        return Ok(false);
    }
    let wsddl = to_wide(DATA_DIR_SDDL);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wsddl` is NUL-terminated and outlives the call; `sd` is a valid out-pointer,
    // released with `LocalFree` below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wsddl.as_ptr()),
            1,
            &raw mut sd,
            None,
        )?;
    }
    let result = (|| {
        let (mut present, mut defaulted) = (false.into(), false.into());
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `sd` is valid; the out-pointers are valid; the DACL points into `sd`.
        unsafe {
            GetSecurityDescriptorDacl(sd, &raw mut present, &raw mut dacl, &raw mut defaulted)?;
        }
        let wpath = to_wide(&dir.to_string_lossy());
        // SAFETY: `wpath` is NUL-terminated; `dacl` stays valid while `sd` is alive.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wpath.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                PSID::default(),
                PSID::default(),
                Some(dacl),
                None,
            )
        };
        if rc == ERROR_SUCCESS {
            Ok(true)
        } else {
            Err(windows::core::Error::from(
                windows::core::HRESULT::from_win32(rc.0),
            ))
        }
    })();
    free(sd.0);
    result
}
