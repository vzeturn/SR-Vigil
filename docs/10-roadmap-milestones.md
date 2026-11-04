# 10 — Roadmap and milestones

**Tóm tắt (VI):** Bảy milestone M0–M6; mỗi milestone có phạm vi, FR/NFR đóng lại và tiêu chí nghiệm thu kiểm chứng được. Claude Code thực hiện tuần tự, mỗi milestone kết thúc bằng fmt + clippy + test xanh.

| MS | Theme | Closes |
|---|---|---|
| M0 | Foundations | tooling, CI, constants, rule loader |
| M1 | Observe | FR-001..005, NFR-003/004 |
| M2 | Service + IPC + read-only UI | FR-013 (part), FR-015, FR-022 |
| M3 | Enforce Unknown + popup + audit | FR-006, 008, 009, 014, 016, 020 |
| M4 | Kill, anti-respawn, persistence | FR-007, 010, 011, 021 |
| M5 | AI advisor/auto (+ VirusTotal) | FR-012, FR-019 |
| M6 | Hardening, installer, polish | FR-017, 018, 023, NFR-006/007/013, T14 |

Standing rule for every milestone: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, docs updated, no placeholder text, audit entries for every new action.

---

## M0 — Foundations

**Deliver**
- Workspace compiles on Windows and Linux (`vigil-win` empty on Linux).
- `vigil-core::consts` with the fixed constants from `CLAUDE.md`.
- Rule pack loader: parse `rules/*.toml`, validate keys against `docs/03 §8`, embed defaults, apply overrides from `rules.d`.
- Contract tests: `rules/default.toml` signal IDs/deltas ↔ `docs/03` tables; `schemas/*.json` parse; `schemas/db.sql` applies to an in-memory SQLite.
- CI (GitHub Actions): `ubuntu-latest` (core, store, ipc, ai), `windows-latest` (all + `vigil-win` build), `cargo deny`, `cargo audit`.
- `xtask`: `cargo xtask check` runs the full local gate.

**Acceptance**
- [ ] All commands in `CLAUDE.md` succeed.
- [ ] Loading an invalid rule key fails with a clear error and does not replace the active pack.
- [ ] Contract tests fail if a delta in `default.toml` differs from the doc table.

## M1 — Observe

**Deliver**
- `vigil-win`: ETW sessions (`ferrisetw`) for Kernel-Process, Kernel-Network, DNS-Client; snapshot reconciler; `QueryFullProcessImageNameW`; command line via `NtQueryInformationProcess`/PEB read; parent chain with start-time check.
- Hashing + `WinVerifyTrust` wrapper (embedded + catalog), signer extraction, VersionInfo.
- `vigil-core`: facts → signals → score → verdict for all rules in `docs/03` (BEH-005 excluded), masquerade/typosquat logic, beaconing detector, path classifier.
- `vigil-store`: schema, repositories.
- `vigilctl scan` (no service): prints the process table with verdicts and signals; `--json`.

**Acceptance**
- [ ] Golden tests for every row of `docs/03 §3` pass.
- [ ] Test corpus in `docs/11` (T-MASQ-*, T-SIG-*) 100% flagged as expected on a Windows runner.
- [ ] 10-minute stress run: 0 ETW lost events; CPU < 2% idle.
- [ ] `vigilctl scan` on a clean Windows 11 VM: ≥ 95% Safe, no panics, no unsigned system binary misflagged.

**Tracked (found by M1 scan on a real machine)**
- MSIX/Store apps under `%ProgramFiles%\WindowsApps` have no embedded Authenticode signature (package-level `AppxSignature.p7x`), so e.g. `WidgetService.exe` is scored unsigned and hits HR-007 because its metadata claims Microsoft. Needs package-signature verification (or the WindowsApps TrustedInstaller-ACL trust path) before the clean-VM acceptance box can be ticked.

## M2 — Service, IPC, read-only UI

**Deliver**
- `VigilSvc` as a Windows service (`windows-service`), install/uninstall via `vigilctl service install|uninstall`, SCM recovery, DACL.
- `vigil-ipc` server/client, roles by token, schema contract tests, event batching.
- Modes `observe` and `learning` (no enforcement yet), settings API.
- `apps/ui`: shell, tokens, Overview, Processes, Connections, Rules & Trust (read-only), Settings, i18n (vi/en), tray, reconnect UX.

**Acceptance**
- [ ] UI shows live processes/connections with < 1 s latency; 5,000 rows at 60 fps (Playwright trace).
- [ ] Viewer (non-elevated) cannot call admin methods (`-32001`).
- [ ] Killing the service: UI shows "service unreachable", auto-recovers after SCM restart.
- [ ] Pipe cannot be created by a non-service process when the service is running (first-instance flag test).

## M3 — Enforce Unknown, popup, audit, panic

**Deliver**
- WFP engine, dynamic/persistent providers, sublayers, permit/deny/catch-all filters, net-event subscription, `rebuild_then_arm`, system bootstrap check.
- Pending/decision flow end to end, scopes/expiry, `apply_to` publisher, re-verification (FR-020).
- Popup window, Pending screen, review wizard, tray menu, Audit screen with hash chain and `chain_ok`.
- `enforcement.panic`, `vigilctl panic`.

**Acceptance**
- [ ] Unsigned test binary in `%TEMP%` is blocked from a non-loopback destination, popup appears, `Allow 1h` permits the next attempt, expiry re-blocks.
- [ ] Safe binaries never prompt on a clean VM after learning.
- [ ] Stopping the service (and killing it with `taskkill /f`) leaves Internet access working (fail-open) and persistent denies intact.
- [ ] Panic removes all filters in < 1 s and sets `observe`.
- [ ] Altering one audit row makes `chain_ok = false`.
- [ ] No self-lockout: DNS, DHCP, Windows Update, Vigil UI keep working in `enforce`.

## M4 — Kill, anti-respawn, persistence

**Deliver**
- Kill/tree kill with never-kill/PPL handling, respawn watch (path + hash), service stop/disable flow, persistent deny by path.
- Persistence scanners (all kinds in `docs/04 §5`), reversible disable, restore, delete-after-disable.
- `svchost` service attribution and `svchost_service_suspicious` alert; UWP package-id filters.

**Acceptance**
- [ ] Malicious test binary is killed within 500 ms of start and re-killed on every respawn attempt; `respawn_kills` increments.
- [ ] Renamed copy (same hash) is killed on start.
- [ ] Attempt to kill `lsass.exe`/`csrss.exe` is refused with `protected_target`.
- [ ] Disable then Restore of a Run key and a scheduled task returns the exact original state (round-trip test).

## M5 — AI advisor and auto

**Deliver**
- `vigil-ai` client with forced tool use, schema validation, retries, cache, budgets, DPAPI key store, redaction hand-off.
- Advisor in popup/details; Auto with gates (`docs/06 §4`); AI settings UI with payload preview and acknowledgement.
- Optional VirusTotal client (REP-001/010/011, HR-005) with cache and rate limit.
- Golden evaluation set and the live harness.

**Acceptance**
- [ ] With the stub server: schema-invalid, injected-text and timeout responses all fall back to Pending with audit entries.
- [ ] Redaction property tests pass; payload preview equals the bytes sent (hash compare).
- [ ] Auto never decides when a hard rule fired, never kills by default, and honours thresholds/stability gate.
- [ ] Live harness (manual): false-safe ≤ 1%, injection success 0%, schema-valid ≥ 99%.

## M6 — Hardening, installer, polish

**Deliver**
- WiX v4 MSI: service install, ACLs, self-pin, Start Menu/tray autostart, upgrade-safe, clean uninstall (removes dynamic and persistent filters).
- Self-protection checklist (`docs/08 §5`), module-signature check for Safe processes in user-writable paths (T14), BEH-005 unbacked executable memory (optional flag).
- Inbound visibility/blocking option (FR-017), import/export (FR-018), geo map, accessibility audit, performance pass.
- Release signing instructions, SBOM (`cargo cyclonedx`), `cargo deny`/`audit` gates.

**Acceptance**
- [ ] Install → learning (24 h soak) → enforce on a Windows 10 and a Windows 11 VM without lockout.
- [ ] Uninstall leaves no WFP objects (`netsh wfp show filters` contains no Vigil provider).
- [ ] Idle CPU < 2%, RSS < 150 MB at 500 processes/5,000 connections.
- [ ] axe-core/Lighthouse accessibility ≥ 95 on main views; keyboard-only run-through passes.
- [ ] Self-contained: the MSI installs on a clean Windows 10/11 machine with no prerequisite (WebView2 bootstrapper and VC runtime bundled or statically linked; no Rust, Node or SDK needed).
- [ ] Few clicks: from running the MSI to a protected machine (learning mode on) takes at most 3 clicks; first-run needs no configuration; every pending decision is answerable with one click.
- [ ] Least privilege: the UI and `vigilctl scan` run as a standard user with no elevation prompt (read-only view with signature, hash, path and parent checks). Elevation is requested only for the features that need it: service install, ETW network collection, WFP enforcement, and killing other users' or system processes. The UI shows which features are limited and offers a one-click "enable protection" UAC prompt.

---

## Backlog (post-v1, tracked)

- Per-service WFP filtering via service SID for `svchost`.
- ARM64 build.
- Signed remote rule-pack updates (Ed25519).
- Fleet management console and SIEM export (syslog/Windows Event Forwarding).
- Local small-model verdict option (no cloud).
