# 01 — Requirements

**Tóm tắt (VI):** Danh sách yêu cầu có đánh số (FR/NFR), mức ưu tiên (M=Must, S=Should, C=Could) và milestone triển khai. Mọi PR phải tham chiếu ID yêu cầu.

## 1. Functional requirements

| ID | Requirement | Pri | MS |
|---|---|---|---|
| FR-001 | Enumerate all processes: PID, PPID, session, user SID, image path, start time, command line, integrity level. | M | M1 |
| FR-002 | Track TCP/UDP endpoints per PID in real time (ETW) plus periodic snapshot reconciliation (`GetExtendedTcpTable`/`GetExtendedUdpTable`). | M | M1 |
| FR-003 | Resolve identity: SHA-256, Authenticode/catalog signature status, signer subject + thumbprint, VersionInfo (CompanyName, ProductName, OriginalFilename). | M | M1 |
| FR-004 | Score every identity with the rule engine; store signals and explanation. | M | M1 |
| FR-005 | Detect masquerading: name↔path, name↔parent, publisher↔VersionInfo, typosquat names. | M | M1 |
| FR-006 | Safe identities connect without prompt. | M | M3 |
| FR-007 | Malicious identities: block network, kill process, block relaunch (in `enforce`). | M | M4 |
| FR-008 | Unknown identities: block outbound until a decision; create a Pending item and show popup with Allow / Block / Kill. | M | M3 |
| FR-009 | Decisions have scope (`once`, `1h`, `24h`, `forever`) and `apply_to` (`file` or `publisher`); expiry enforced by the service. | M | M3 |
| FR-010 | Kill process (optionally tree); prevent re-launch via ETW watch + persistent WFP deny + SCM stop/disable (services, with approval). | M | M4 |
| FR-011 | Persistence audit (Run keys, services, scheduled tasks, startup folders, WMI subscriptions, IFEO, AppInit_DLLs, Winlogon) with reversible disable. | S | M4 |
| FR-012 | AI advisor: user supplies Anthropic API key; **Advisor** (suggest) and **Auto** (decide above confidence threshold) modes. | S | M5 |
| FR-013 | UI: dashboard, process tree, connections, pending queue + popup, rules/trust, AI settings, audit log, settings. | M | M2–M3 |
| FR-014 | Tamper-evident audit log (hash chain) for verdicts, decisions, enforcement and configuration changes. | M | M3 |
| FR-015 | Modes: `observe`, `learning`, `enforce`; switchable at runtime by admin. | M | M2 |
| FR-016 | Panic switch: remove all dynamic filters and disable enforcement instantly (UI button, `vigilctl panic`, tray). | M | M3 |
| FR-017 | Inbound listening sockets visible; inbound blocking optional (disabled by default). | C | M6 |
| FR-018 | Import/export of user decisions and rule overrides (TOML); export audit as JSON/CSV. | S | M6 |
| FR-019 | Optional VirusTotal hash lookup (user supplies key), cached, rate-limited. | C | M5 |
| FR-020 | Re-verify identity on every process start and on file change; revoke permit and re-prompt if hash/signature changed. | M | M3 |
| FR-021 | Service attribution for `svchost.exe`: map PID/connection to hosted service(s) and ServiceDll; score the DLLs. | S | M4 |
| FR-022 | UI strings live in an i18n table; the shipped UI is English only (user decision), exports are language-neutral. | M | M2 |
| FR-024 | Process storms (self-replication, nested copies, script-host floods) are killed in every mode, with rate-adaptive thresholds and an advisor review below them; a hijacked Safe program is reclassified Malicious. See `docs/04 §8`. | M | M6 |
| FR-023 | Installer (MSI) that registers the service, ACLs the data dir, creates the Start Menu shortcut and tray autostart. | S | M6 |

## 2. Non-functional requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-001 | Idle CPU of `VigilSvc` | < 2% average, 1 core |
| NFR-002 | Memory (RSS) at 500 processes / 5,000 connections | < 150 MB |
| NFR-003 | Evaluation latency | cached p95 < 150 ms; fresh signed p95 < 600 ms; fresh unsigned p95 < 1.5 s |
| NFR-004 | ETW loss | 0 lost events in 10-min stress; buffer sizing documented |
| NFR-005 | UI event rate | batched ≤ 20 messages/s; UI stays at 60 fps with 5,000 rows |
| NFR-006 | Reliability | service auto-restart (SCM recovery); dynamic filters removed on exit (fail-open); no filter leak after crash |
| NFR-007 | Security | pipe ACL SYSTEM+Administrators; roles by token; no secret in logs/IPC/UI; Tauri CSP strict, no remote content |
| NFR-008 | Privacy | AI payload redaction per `docs/06`; AI disabled by default; local-only data |
| NFR-009 | Compatibility | Windows 10 1809+, Windows 11, Server 2019+; x64 (arm64 tracked post-M6) |
| NFR-010 | Observability | structured logs (`tracing`), rotating file in `%ProgramData%\Vigil\logs`, health event stream |
| NFR-011 | Accessibility | keyboard-operable UI, WCAG AA contrast, `prefers-reduced-motion` honoured |
| NFR-012 | Maintainability | `vigil-core` ≥ 90% line coverage; clippy clean; docs updated with code |
| NFR-013 | Safety | never-kill set enforced; panic switch effective in < 1 s |

## 3. Constraints and assumptions

- C1. Windows only; Rust stable; WebView2 runtime present for the UI.
- C2. Service requires SYSTEM; UI requires Administrators to change state, standard users get read-only unless `allow_standard_user_decisions = true`.
- C3. Without a callout driver the first connect attempt of a not-yet-evaluated app may be blocked and retried by the app; accepted for v1.
- C4. Code-signing certificate is supplied by the owner for release builds; dev builds are unsigned and use a development self-pin (see `docs/08`).
- C5. Anthropic model IDs are configuration, defaulting to `claude-haiku-5-5` with escalation to `claude-sonnet-5-5`; verify current IDs on docs.claude.com at implementation time.

## 4. Traceability

Each milestone in `docs/10-roadmap-milestones.md` lists the FR/NFR IDs it closes. Each FR maps to at least one test ID in `docs/11-testing.md`.
