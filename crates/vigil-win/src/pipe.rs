//! Named-pipe server instances for the control channel (`docs/05 §1–2`).
//!
//! * DACL: SYSTEM and Administrators full control; Authenticated Users may only read/write data
//!   (no `FILE_CREATE_PIPE_INSTANCE`, so nobody else can add instances to the pipe).
//! * `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance, so a process that already owns the
//!   name makes the service fail instead of serving clients through a squatter.
//! * Remote clients are rejected.
//! * The caller's role comes from the client *process* token (`GetNamedPipeClientProcessId` +
//!   `TokenElevation`), which avoids thread-bound impersonation inside async code.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
    TokenElevation,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::PCWSTR;

use crate::to_wide;

/// SYSTEM and Administrators: full; Authenticated Users: read data, write data, read attributes,
/// read EA, read control, synchronize (0x12008B) and nothing that creates pipe instances.
pub const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;AU)";

/// Create one server instance. Pass `first = true` for the very first instance of the pipe.
pub fn create_instance(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let wsddl = to_wide(PIPE_SDDL);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wsddl` is NUL-terminated and outlives the call; `sd` is a valid out-pointer. The
    // returned descriptor is released with `LocalFree` below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wsddl.as_ptr()),
            1,
            &raw mut sd,
            None,
        )
    }
    .map_err(io::Error::from)?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first).reject_remote_clients(true);
    // SAFETY: `attrs` points at a valid SECURITY_ATTRIBUTES whose descriptor stays alive until the
    // pipe is created; the kernel copies the descriptor.
    let created = unsafe {
        opts.create_with_security_attributes_raw(name, (&raw mut attrs).cast::<c_void>())
    };
    // SAFETY: `sd.0` was allocated by the conversion call above and is freed exactly once.
    let _ = unsafe { LocalFree(HLOCAL(sd.0)) };
    created
}

struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful Win32 call and is closed exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Whether the process `pid` runs with an elevated token (Administrators/SYSTEM, UAC-approved).
#[must_use]
pub fn process_is_elevated(pid: u32) -> bool {
    // SAFETY: plain Win32 calls; every handle is owned and closed by `Owned`.
    unsafe {
        let Ok(p) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let p = Owned(p);
        let mut token = HANDLE::default();
        if OpenProcessToken(p.0, TOKEN_QUERY, &raw mut token).is_err() {
            return false;
        }
        let token = Owned(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&raw mut elevation).cast::<c_void>()),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
            &raw mut len,
        )
        .is_ok()
            && elevation.TokenIsElevated != 0
    }
}

/// PID of the process on the other end of a connected pipe instance.
pub fn client_pid(server: &NamedPipeServer) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: the handle belongs to a live `NamedPipeServer`; `pid` is a valid out-pointer.
    unsafe { GetNamedPipeClientProcessId(HANDLE(server.as_raw_handle()), &raw mut pid) }
        .map_err(io::Error::from)?;
    Ok(pid)
}

/// `true` when the connected client is an elevated administrator.
pub fn client_is_elevated(server: &NamedPipeServer) -> io::Result<bool> {
    Ok(process_is_elevated(client_pid(server)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::windows::named_pipe::ClientOptions;

    fn unique(tag: &str) -> String {
        format!(r"\\.\pipe\vigil-test-{tag}-{}", std::process::id())
    }

    #[tokio::test]
    async fn second_first_instance_is_refused_and_extra_instances_work() {
        let name = unique("squat");
        let first = create_instance(&name, true).expect("first instance");
        // A squatter claiming first-instance ownership of an existing name must fail.
        assert!(create_instance(&name, true).is_err());
        // The service itself can add further instances afterwards.
        let _second = create_instance(&name, false).expect("additional instance");
        drop(first);
    }

    #[tokio::test]
    async fn client_pid_is_this_process_and_elevation_matches() {
        let name = unique("pid");
        let server = create_instance(&name, true).unwrap();
        let client = ClientOptions::new().open(&name).unwrap();
        server.connect().await.unwrap();
        let me = std::process::id();
        assert_eq!(client_pid(&server).unwrap(), me);
        assert_eq!(
            client_is_elevated(&server).unwrap(),
            process_is_elevated(me)
        );
        drop(client);
    }

    #[test]
    fn authenticated_users_cannot_create_pipe_instances() {
        // FILE_CREATE_PIPE_INSTANCE == FILE_APPEND_DATA == 0x4 must not be in the AU mask.
        let mask = PIPE_SDDL.split("(A;;").last().unwrap();
        let hex = mask.split(';').next().unwrap().trim_start_matches("0x");
        let rights = u32::from_str_radix(hex, 16).unwrap();
        assert_eq!(rights & 0x4, 0);
    }
}
