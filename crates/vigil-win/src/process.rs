//! Process snapshot, image path and start time, with a start-time-checked parent chain.

use std::collections::HashMap;

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use crate::Error;

/// One process from a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    /// Executable file name from the snapshot (always present).
    pub name: String,
    /// Full Win32 image path; `None` for protected/inaccessible processes.
    pub image: Option<String>,
    /// Creation time as 100 ns ticks since 1601 (`FILETIME`).
    pub start_time: Option<u64>,
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by a successful Win32 call and is closed exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn utf16_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn filetime(ft: FILETIME) -> u64 {
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

/// Image path and start time of `pid`, when the process can be opened with limited rights.
#[must_use]
pub fn query(pid: u32) -> (Option<String>, Option<u64>) {
    // SAFETY: plain Win32 call; the returned handle is owned and closed by `Handle`.
    let Ok(h) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return (None, None);
    };
    let h = Handle(h);

    let mut buf = vec![0u16; 32_768];
    let mut len = u32::try_from(buf.len()).unwrap_or(32_768);
    // SAFETY: `buf` is valid for `len` u16s and `len` is updated to the written length.
    let image = unsafe {
        QueryFullProcessImageNameW(
            h.0,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &raw mut len,
        )
    }
    .ok()
    .map(|()| String::from_utf16_lossy(&buf[..len as usize]));

    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: all four out-pointers refer to live, writable `FILETIME`s.
    let start = unsafe {
        GetProcessTimes(
            h.0,
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .ok()
    .map(|()| filetime(created));
    (image, start)
}

/// Snapshot all processes, enriched with image path and start time.
pub fn snapshot() -> Result<Vec<ProcessInfo>, Error> {
    // SAFETY: plain Win32 call; handle owned by `Handle`.
    let snap = Handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?);
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: `entry.dwSize` is set and `snap` is a valid snapshot handle.
    let mut more = unsafe { Process32FirstW(snap.0, &raw mut entry) }.is_ok();
    while more {
        let (image, start_time) = query(entry.th32ProcessID);
        out.push(ProcessInfo {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            name: utf16_to_string(&entry.szExeFile),
            image,
            start_time,
        });
        // SAFETY: same invariants as `Process32FirstW` above.
        more = unsafe { Process32NextW(snap.0, &raw mut entry) }.is_ok();
    }
    Ok(out)
}

/// Resolve each process's parent, rejecting reused PIDs: a parent that started *after* its
/// child cannot be the real parent, so it is omitted ("unknown parent never fires").
#[must_use]
pub fn parent_of(procs: &[ProcessInfo]) -> HashMap<u32, &ProcessInfo> {
    let by_pid: HashMap<u32, &ProcessInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    procs
        .iter()
        .filter_map(|p| {
            let parent = by_pid.get(&p.ppid)?;
            match (parent.start_time, p.start_time) {
                (Some(ps), Some(cs)) if ps > cs => None,
                _ => Some((p.pid, *parent)),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_contains_self_with_image_path() {
        let me = std::process::id();
        let all = snapshot().unwrap();
        let p = all.iter().find(|p| p.pid == me).expect("self in snapshot");
        assert!(p.image.as_deref().is_some_and(|i| i.contains(".exe")));
        assert!(p.start_time.is_some());
    }

    fn proc_at(pid: u32, parent: u32, start: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: parent,
            name: String::new(),
            image: None,
            start_time: Some(start),
        }
    }

    #[test]
    fn reused_parent_pid_is_rejected() {
        let procs = [
            proc_at(10, 4, 100),
            proc_at(20, 10, 200),
            proc_at(30, 10, 50),
        ];
        let m = parent_of(&procs);
        assert_eq!(m[&20].pid, 10);
        assert!(!m.contains_key(&30), "parent started after child");
    }
}
