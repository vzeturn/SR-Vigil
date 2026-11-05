//! `TerminateProcess` with a start-time check so a recycled PID is never killed by mistake.

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, FILETIME, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE, TerminateProcess,
};

use crate::process::{Handle, filetime};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
}

/// Freeze (`true`) or thaw (`false`) `pid` iff its creation time still equals `expected_start`.
/// Returns `false` when the process is gone, replaced, or access is refused.
fn set_suspended(pid: u32, expected_start: u64, freeze: bool) -> bool {
    // SAFETY: plain Win32 call; the returned handle is owned and closed by `Handle`.
    let Ok(h) = (unsafe {
        OpenProcess(
            PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
    }) else {
        return false;
    };
    let h = Handle(h);
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: all four out-pointers refer to live, writable `FILETIME`s.
    let times = unsafe {
        GetProcessTimes(
            h.0,
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if times.is_err() || filetime(created) != expected_start {
        return false;
    }
    // SAFETY: `h` is a live process handle opened with PROCESS_SUSPEND_RESUME; `HANDLE` is
    // layout-compatible with the kernel handle `NtSuspendProcess` expects.
    let status = unsafe {
        if freeze {
            NtSuspendProcess(h.0)
        } else {
            NtResumeProcess(h.0)
        }
    };
    status >= 0
}

/// Freeze every thread of `pid` (the process stays alive but runs no code).
#[must_use]
pub fn suspend(pid: u32, expected_start: u64) -> bool {
    set_suspended(pid, expected_start, true)
}

/// Undo [`suspend`].
#[must_use]
pub fn resume(pid: u32, expected_start: u64) -> bool {
    set_suspended(pid, expected_start, false)
}

/// Outcome of one terminate attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Terminated,
    /// No such process, or the PID now belongs to a different process.
    Gone,
    /// Protected/PPL or insufficient rights; do not retry.
    AccessDenied,
    Failed,
}

/// Terminate `pid` iff its creation time still equals `expected_start` (100 ns ticks since 1601).
#[must_use]
pub fn terminate(pid: u32, expected_start: u64) -> Outcome {
    // SAFETY: plain Win32 call; the returned handle is owned and closed by `Handle`.
    let h = match unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
    } {
        Ok(h) => Handle(h),
        Err(e) => {
            let code = e.code();
            return if code == ERROR_ACCESS_DENIED.to_hresult() {
                Outcome::AccessDenied
            } else if code == ERROR_INVALID_PARAMETER.to_hresult() {
                Outcome::Gone
            } else {
                Outcome::Failed
            };
        }
    };
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: all four out-pointers refer to live, writable `FILETIME`s.
    let times = unsafe {
        GetProcessTimes(
            h.0,
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if times.is_err() {
        return Outcome::Failed;
    }
    if filetime(created) != expected_start {
        return Outcome::Gone;
    }
    // SAFETY: `h` is a live process handle opened with PROCESS_TERMINATE.
    match unsafe { TerminateProcess(h.0, 1) } {
        Ok(()) => Outcome::Terminated,
        Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => Outcome::AccessDenied,
        Err(_) => Outcome::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminates_a_child_and_refuses_a_stale_start_time() {
        let mut child = std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let (_, start) = crate::process::query(child.id());
        let start = start.expect("start time");
        assert_eq!(terminate(child.id(), start + 1), Outcome::Gone);
        assert!(
            child.try_wait().unwrap().is_none(),
            "stale start must not kill"
        );
        assert!(suspend(child.id(), start));
        assert!(
            !suspend(child.id(), start + 1),
            "stale start must not freeze"
        );
        assert!(resume(child.id(), start));
        assert_eq!(terminate(child.id(), start), Outcome::Terminated);
        assert!(child.wait().is_ok());
    }
}
