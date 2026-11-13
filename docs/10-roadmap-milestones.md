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
  - Status (UI tray): M2 ships tray with Open/Quit (localized from the frontend). M3 adds the pending count (tray tooltip), the Mode submenu and Panic.
  - Status: M2 ships the unprivileged slice only (process snapshot + `GetExtendedTcpTable` polling, 500 ms). ETW collection (instant events, DNS names) is deferred to M3 and needs elevation.
  - `trust.list` returns `thumbprint: ""` for org-pinned builtin publishers.
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
- MSIX/Store apps under `%ProgramFiles%WindowsApps` have no embedded Authenticode signature (the signature is the package-level `AppxSignature.p7x`). `vigil-win::msix` now treats a file there as package-signed (state `valid_catalog`, publisher from the TrustedInstaller-protected `AppxManifest.xml`) when the package root holds `AppxSignature.p7x`. The clean-VM `vigilctl scan` box still needs a Windows VM run.

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
- `enforcement.panic`, `vigilctl panic`, `vigilctl mode`.

**Status:** implemented and covered by automated tests with a fake filter engine (`crates/vigil-svc/tests/enforce.rs`); the real WFP path (`vigil-win::wfp`, `vigil-svc::winfilter`) compiles and is lint-clean but needs the elevated VM checks in `docs/11 §WFP` before the first four acceptance boxes below can be ticked. Deferred and tracked here: ETW collection, WFP failure retry backoff (docs/04 §7), daily audit anchor and Windows Event Log anchor.

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

**M4 status (branch `ms/m4-kill`)**
- Verified by automated tests: kill/respawn/renamed copy (`t_kill_01_every_respawn_and_renamed_copy_is_killed_and_counted`, fake process table, 20 respawns + same-hash copy), `protected_target` (`t_kill_02_protected_target_is_refused_and_not_terminated`), Run-key and scheduled-task disable/restore round trip against the real registry/`schtasks` (`vigil-win` persist tests), service state machine and audit (`t_pers_01_*`).
- Not verified (needs an elevated VM): the 500 ms kill latency with a real binary through the service, killing other users' processes, service-kind disable/restore against a real service.
- Deferred (tracked): `wmi_subscription`, `winlogon` and `shell_ext` scanners (not scanned yet); `svchost` service attribution and `svchost_service_suspicious`; UWP package-id filters; the enforce-mode positive path of `auto_kill_malicious` (needs an engine in the test harness).

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

**Status (M5)**
- Verified by tests: stub-server fallbacks with audit rows (`crates/vigil-svc/tests/ai.rs`, `crates/vigil-ai/tests/stub.rs`); preview hash equals payload sent; redaction property tests (`vigil-core`); Auto gates (hard rule, no-kill default, threshold); key never returned or audited.
- Not verified: live harness (needs `ANTHROPIC_API_KEY`, run manually); live model IDs/parameters (`docs/06 §9`).
- Deferred: VirusTotal client (REP-001/010/011, HR-005); command-line capture for the payload (not available from the current process sensor); `vigilctl ai` subcommands.

## M6 — Hardening, installer, polish

**Deliver**
- WiX v4 MSI: service install, ACLs, self-pin, Start Menu/tray autostart, upgrade-safe, clean uninstall (removes dynamic and persistent filters).
- Self-protection checklist (`docs/08 §5`), module-signature check for Safe processes in user-writable paths (T14), BEH-005 unbacked executable memory (done: `vigil-win::memory`, opt-in via `VIGIL_MEMORY_SCAN=1`).
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

**Status (M6, in progress):** done: MSI (`installer/`, `docs/13`), uninstall cleanup (`vigil-svc --cleanup`), DLL search-path lock-down, data-dir ACL repair, FR-018, FR-017 visibility (listening sockets shown as inbound; blocking stays off, tracked below), T14 (MOD-001), axe-core accessibility test on every page in en and vi, `cargo deny` gate green, SBOM and release workflow, static CRT. Done: one-click "Enable protection" (single UAC prompt installs the service; the UI stays unelevated). Also done: process-storm kill in every mode with advisor review below the thresholds (FR-024, `docs/04 §8`) and AI authority scaled to the mode. Open: BEH-005 collection, geo map, Lighthouse, contrast and keyboard run-through on a real WebView, performance pass, and every VM-only acceptance box above.

## M11 — Behaviour and destination reputation

Design: [docs/15-behaviour-and-reputation.md](15-behaviour-and-reputation.md).

- [x] Offline `rules/reputation.toml` (bad domains, risky ports and TLDs, DGA heuristic) and NET-001/002; BEH-001/003/004 now fed live from ETW connects and DNS answers.
- [x] ETW collectors. Done: Kernel-Process starts feed the observer, so images that exit before the next snapshot are still judged (the snapshot remains the reconciler); Kernel-Network byte counts (send/receive totals per pid and address, NET-003); DNS-Client answers (event 3008) map each address to the name the program resolved; Kernel-File creates, new files and renames, pre-filtered in the callback by `rules/files.toml`.
- [x] Rule NET-003 with fixtures and mutation checks (NET-004 is BEH-001, now live). Done: NET-003 from Kernel-Network byte counts and `rules/upload.toml`; PRC-001 from ETW process starts and `rules/spawn.toml`, scored on the parent; FIL-001/002 and RES-001 from Kernel-File and `rules/files.toml`; TRU-001 for pinned Microsoft-root publishers without NET-001, PRC-001, FIL-002 or RES-001.
- [x] Connections page: per-connection reputation chip and owning-process score.
- [x] AI payload `behaviour.events`, prompt update and spec regeneration (the proxy allowlist needs no change: the words sit under `behaviour`).

## M12 — Version freshness (approved; in progress)

Design: [docs/16-version-freshness.md](16-version-freshness.md).

- [x] Version fields in `rules/known_software.toml`; signals VER-001/002/003 with fixtures and mutation checks.
- [x] Cloudflare cron Worker (`catalogue/`) that builds and signs the snapshot from winget-pkgs. Tracked: OSV/CISA KEV automation for `vulnerable_below` (today curated in `catalogue/overrides.json`); optional `GITHUB_TOKEN` to lift the unauthenticated rate limit.
- [x] Client fetch, Ed25519 verification with `kid` rotation, rollback protection, cache in the data directory, opt-in setting `catalogue.enabled` (Settings page, vi/en).
- [x] Processes page "installed X → latest Y" with a vendor download link (checked by `catalogue::safe_link`, opened through `vigil_win::shell`).
- [x] Catalogue schema carries winget id, installer hash and end-of-support so a later user-approved clean-update flow (needs its own design) can build on it. Tracked: `end_of_support` raising VER-002.

## M13 — Kill review, launch origin, root cause (design in `docs/18`)

Reviewable and revocable kills with exceptions and false-positive reports, a local baseline
database, launch-origin detection, suspend-and-ask on re-open, launcher attribution with one
root-cause popup. Build order is in `docs/18 §7`.

- [x] Steps 1–4 built: kill review and exceptions, launch origin and baselines, freeze-and-ask on re-open (`reopen.answer`), launcher cool-down with one question (`launcher.answer`).
- [x] Fixture: a launcher respawning a killed program 20 times produces exactly one `event.launcher_prompt` (`crates/vigil-svc/tests/kill.rs`); a user-origin reopen freezes and asks, a script-origin one never prompts.
- [ ] Manual check on Windows (`docs/11`): reopen a killed program from Explorer, confirm it is frozen, the popup lists reasons, Allow resumes it, Keep stopped kills it.

## M14 — App profiles and tab containment (design in `docs/19`)

- [x] `rules/app_profiles.toml` and `vigil_core::profile` (browser roles, package origin).
- [x] `tab_scan`: a renderer that starts a program is stopped alone, with its children; the browser is never blocked.
- [x] PKG-001: uv/pip launcher whose metadata names a known source (+30, never Safe on its own).
- [ ] Destination-based per-browser-tab block (needs a browser-side channel; the OS cannot attribute connections to tabs).
- [ ] Runaway-CPU renderer handling.
- [ ] User-visible alert event when a tab was stopped.
- [ ] One-time "trust this package family" answer for dev tools.

## M15 — Signing depth, MOTW and ASR posture (design in `docs/20`)

- [x] SRC-001 Mark of the Web signal.
- [x] Read-only ASR posture (`vigilctl posture`).
- [x] Orphan anti-respawn blocks are lifted.
- [x] CIRCL hashlookup known-good hashes (HASH-001), `CLAUDE.md` rule 10 amended by the user.
- [x] ASR rules enabled (9 block, 2 audit) and `vigilctl allow` for hash-verified tools.
- [ ] MalwareBazaar and VirusTotal lookups (need an API key kept in the DPAPI store).
- [ ] ASR audit-to-block review after two weeks of audit events.

## M16 — Lockdown (design in `docs/21`)

- [x] `purge.start/stop/status`, 5-minute hold, comeback re-kill, advisor review after 3 comebacks.
- [x] Lockdown page (ring, counters, per-program intel, trace and block-for-good).
- [x] `vigilctl purge start|stop|status`.

## M17 — Release signing (design in `docs/22`)

- [x] Staged `build.ps1` (`-Stage build|package`) and a SignPath signing job with a signature gate in `release.yml`.
- [ ] Owner: SignPath approval, `SIGNPATH_ORGANIZATION_ID`/`SIGNPATH_API_TOKEN`, first signed tag, Defender reputation submission.

## M18 — URL filter and protection switch (design in `docs/23`)

- [x] Local DNS sinkhole with malware, phishing, adult and ads lists, protected names, user exceptions, reversible adapter DNS.
- [x] `dns.status`, `protection.set`, `vigilctl protection`, header switch in the UI.
- [ ] Windows VM check: enable the filter, resolve a listed test name, reboot, kill the service and confirm DNS is restored.
- [x] UI page for filter categories and exceptions (*Web filter*, `docs/07 §4.8a`).

## Backlog (post-v1, tracked)

- Inbound blocking option (FR-017): `ALE_AUTH_RECV_ACCEPT` filters, off by default.

- Bundle the WebView2 Evergreen bootstrapper in the MSI (Windows 11 and current Windows 10 already ship the runtime; older Windows 10 needs it installed once).
- Process mitigation policies for the service and live WFP change-event alerts (`docs/08` §5).

- Per-service WFP filtering via service SID for `svchost`.
- ARM64 build.
- Signed remote rule-pack updates (Ed25519).
- Fleet management console and SIEM export (syslog/Windows Event Forwarding).
- Local small-model verdict option (no cloud).

- macOS support: see [docs/17-cross-platform-macos.md](17-cross-platform-macos.md) (milestones M7–M10).

## Spec review (open items, consolidated)

- **Needs a Windows VM (elevated):** every unticked acceptance box in M2–M6 (WFP lockout/fail-open, 500 ms kill latency, panic < 1 s, clean-VM scan, 24 h learning soak, uninstall leaves no WFP objects, performance budgets NFR-001/002/005).
- **In progress:** M11 file/byte ETW collectors and the remaining behaviour rules (NFR-004 depends on them); M12 "installed vs latest" vendor link and the M13-ready catalogue schema.
- **Release:** code-signing certificate (C4), enabling GitHub private vulnerability reporting and secret scanning before the repository goes public.
- **Decided and reflected in the specs:** English-only UI (FR-022), mode-scaled AI authority and storm kill (CLAUDE.md #2, FR-024).
