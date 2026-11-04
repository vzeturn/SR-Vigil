//! Unbacked executable memory (`docs/03` BEH-005, optional).
//!
//! Walks a process's address space with `VirtualQueryEx` and reports committed, private,
//! read-write-execute regions: code that runs from memory no image file backs (injection, shellcode,
//! reflective loaders). JIT engines also allocate such memory, so the caller scans only processes whose
//! own image is not validly signed, and the scan is off unless `VIGIL_MEMORY_SCAN=1`.

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, VirtualQueryEx,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

/// Upper bound of regions inspected per process.
const MAX_REGIONS: usize = 50_000;

/// Whether the optional scan is switched on (`VIGIL_MEMORY_SCAN=1`).
#[must_use]
pub fn enabled() -> bool {
    std::env::var_os("VIGIL_MEMORY_SCAN").is_some_and(|v| v == "1")
}

/// `true` for a committed, private, read-write-execute region.
fn is_unbacked_exec(m: &MEMORY_BASIC_INFORMATION) -> bool {
    m.State == MEM_COMMIT && m.Type == MEM_PRIVATE && m.Protect == PAGE_EXECUTE_READWRITE
}

/// `true` when `pid` holds a private RWX region. Unreadable processes report `false`.
#[must_use]
pub fn has_unbacked_exec_memory(pid: u32) -> bool {
    // SAFETY: plain Win32 call; the handle is closed below.
    let Ok(h) = (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }) else {
        return false;
    };
    let mut addr = 0usize;
    let mut found = false;
    for _ in 0..MAX_REGIONS {
        let mut m = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `h` is a live process handle and `m` is a correctly sized out-buffer.
        let n = unsafe {
            VirtualQueryEx(
                h,
                Some(addr as *const _),
                &raw mut m,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if n == 0 {
            break;
        }
        if is_unbacked_exec(&m) {
            found = true;
            break;
        }
        let Some(next) = (m.BaseAddress as usize).checked_add(m.RegionSize) else {
            break;
        };
        if next <= addr {
            break;
        }
        addr = next;
    }
    // SAFETY: `h` came from a successful `OpenProcess` and is closed exactly once.
    let _ = unsafe { CloseHandle(h) };
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Memory::{MEM_IMAGE, PAGE_EXECUTE_READ};

    fn region(ty: windows::Win32::System::Memory::PAGE_TYPE, p: u32) -> MEMORY_BASIC_INFORMATION {
        MEMORY_BASIC_INFORMATION {
            State: MEM_COMMIT,
            Type: ty,
            Protect: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(p),
            ..Default::default()
        }
    }

    #[test]
    fn only_private_rwx_counts() {
        assert!(is_unbacked_exec(&region(
            MEM_PRIVATE,
            PAGE_EXECUTE_READWRITE.0
        )));
        assert!(!is_unbacked_exec(&region(
            MEM_IMAGE,
            PAGE_EXECUTE_READWRITE.0
        )));
        assert!(!is_unbacked_exec(&region(MEM_PRIVATE, PAGE_EXECUTE_READ.0)));
    }

    #[test]
    fn finds_a_real_rwx_allocation_in_this_process() {
        use windows::Win32::System::Memory::{MEM_RELEASE, MEM_RESERVE, VirtualAlloc, VirtualFree};
        // SAFETY: allocates and frees a private page owned by this test.
        let p =
            unsafe { VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
        assert!(!p.is_null());
        let hit = has_unbacked_exec_memory(std::process::id());
        // SAFETY: `p` was returned by `VirtualAlloc` above.
        let _ = unsafe { VirtualFree(p, 0, MEM_RELEASE) };
        assert!(hit);
    }
}
