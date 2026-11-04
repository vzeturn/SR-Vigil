# 13 — Cross-platform roadmap (Windows first, macOS next)

Goal: one product, one rule engine, one UI, on Windows and macOS. Windows ships first and stays the reference. This doc is the route to macOS; it changes no Windows behaviour and the non-negotiables in `CLAUDE.md` (user-mode only, hard rules first, fail open, untrusted strings are data) apply unchanged.

## 1. What already ports

| Part | Status |
|---|---|
| `vigil-core` (facts, signals, score, verdict, beaconing, typosquat) | OS-neutral code; **path classification, system-process and publisher data are Windows-specific** (see M7) |
| `vigil-store`, `vigil-ai`, `proxy/` | OS-neutral (SQLite, HTTPS client, Node) |
| `apps/ui` (React + Tauri v2) | Tauri runs on macOS (WKWebView); only the Rust side that owns the pipe is OS-specific |
| `vigil-ipc` | protocol is neutral; transport is a Windows named pipe |

## 2. Windows-only today and its macOS counterpart

| Concern | Windows | macOS (user-mode, no kernel extension) |
|---|---|---|
| Process list | ToolHelp / NT APIs | `libproc` (`proc_listpids`, `proc_pidpath`); other users' processes need root |
| Process start events | ETW | EndpointSecurity `NOTIFY_EXEC` / `AUTH_EXEC` (system extension) |
| Connections | IP Helper + ETW | `proc_pidfdinfo` sockets for polling; Network Extension content filter for per-flow events |
| Signature | `WinVerifyTrust`, catalogs | Security.framework `SecStaticCodeCheckValidity` + `SecCodeCopySigningInformation`; **Team ID** replaces thumbprint pins; notarization status |
| Block / allow | WFP filters | `NEFilterDataProvider` (system extension) |
| Kill | `TerminateProcess` | `kill(SIGKILL)`; SIP-protected and platform binaries are refused as `protected_target` |
| Service | SCM `VigilSvc` | `launchd` LaunchDaemon `com.vigil.svc` |
| IPC | `\\.\pipe\vigil-control` + ACL | Unix socket under `/var/run/vigil/` with peer-credential check (`LOCAL_PEERCRED`) |
| Secret store | DPAPI machine scope | Keychain (system keychain item, service only) |
| Installer | WiX MSI | notarized `.pkg` / `.dmg` |

## 3. Honest constraints

- **Observation works without Apple approval**: a signed user-mode build can list processes, check signatures and show connections of the current user.
- **Enforcement needs Apple-granted entitlements** (`com.apple.developer.endpoint-security.client`, `com.apple.developer.networking.networkextension`), a paid Developer ID, notarization, and the user approving the system extension and Full Disk Access. Until granted, macOS runs in `observe` mode only.
- The same "bounded, revocable" honesty applies as on Windows: nothing here is kernel code.

## 4. Milestones

| # | Milestone | Deliver | Done when |
|---|---|---|---|
| M7 | **Portability refactor** (Windows regression-free) | New crate `vigil-platform` with traits `ProcessSource`, `SignatureVerifier`, `NetEvents`, `Enforcer`, `SecretStore`, `Transport`; `vigil-win` implements them; `vigil-svc` and `vigilctl` depend on the traits. `PathEnv`, `system_processes`, `lolbins`, `publishers` become per-OS rule files selected by an `os` key. `vigil-ipc` transport behind a trait. CI job on `macos-latest` running `cargo test -p vigil-core -p vigil-store -p vigil-ipc -p vigil-ai` | All Windows gates unchanged and green; the macOS CI job is green |
| M8 | **macOS observe-only** (`vigil-mac`, `#![cfg(target_os = "macos")]`) | libproc process/socket snapshot, Security.framework signatures with Team-ID pins, `launchd` daemon, Unix-socket IPC, Keychain secret, Tauri build on macOS, `vigilctl scan` | `vigilctl scan` on macOS 13+ (arm64 and x86_64): ≥ 95% Safe on a clean install, no panics; UI shows live processes and connections; runs as a standard user without prompts |
| M9 | **macOS enforcement** | EndpointSecurity exec monitor/auth, Network Extension content filter, `protected_target` for SIP/platform binaries, fail-open when the extension is not running | Unsigned test binary in `/tmp` is blocked from a non-loopback destination; stopping the daemon leaves the network working |
| M10 | **macOS release** | Notarized universal `.pkg`, release workflow on `macos-latest`, docs/README platform table | Install on a clean Mac in ≤ 3 clicks |

Prerequisites outside the code: an Apple Developer Program membership and the two entitlement requests (start them during M8; approval takes time). An Apple-silicon Mac is needed for M8–M10 manual checks; the maintainer's iMac fits.

## 5. Rules for contributors

1. New OS-specific code goes only in `vigil-win` / `vigil-mac`; shared logic goes in `vigil-core` and takes OS data as input.
2. Do not add `cfg(windows)` to `vigil-core`; if a rule needs OS data, add a field to the per-OS rule files.
3. Every platform-trait method has a contract test that runs against a fake in `vigil-core`.
