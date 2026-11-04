# 12 — Handoff to Claude Code

**Tóm tắt (VI):** Cách bàn giao: mở Claude Code tại thư mục dự án, dùng lệnh `/milestone Mx`. Mỗi milestone có prompt chi tiết dưới đây; bạn duyệt theo checklist rồi mới chuyển milestone tiếp theo.

## 1. Setup

1. Prerequisites: Windows 10 1809+/11 (admin shell for integration tests), Rust stable (`rustup`), Visual Studio Build Tools (MSVC), Node 22+, pnpm, WebView2 runtime, Git.
2. `git init && git add . && git commit -m "docs: initial design handoff"` so every milestone is a reviewable diff.
3. `claude` in the repo root. `CLAUDE.md` loads automatically; `.claude/commands/` provides `/milestone` and `/review`.
4. Keep the Anthropic API key out of the repo; it is entered through the UI in M5.

## 2. Working agreement

- One milestone per session/branch (`ms/m1-observe`, …); merge only when acceptance boxes in `docs/10` are ticked.
- Claude Code must stop and ask when: a Windows API behaves differently than documented here, a requirement conflicts with another, or a dependency version cannot satisfy the design.
- Any design change = doc change in the same commit.

## 3. Milestone prompts

> Use `/milestone M0` etc. — the command expands to the prompts below. They can also be pasted manually.

### M0 — Foundations

```
Implement milestone M0 from docs/10-roadmap-milestones.md. Read CLAUDE.md, docs/02-architecture.md, docs/03-trust-scoring.md (§8 rule format) and rules/*.toml first.
Tasks: (1) vigil-core::consts with the fixed constants; (2) rule pack loader/validator with embedded defaults and rules.d overrides, failing closed to the previous pack; (3) contract tests: rules/default.toml deltas and IDs vs the tables in docs/03, schemas/*.json parse, schemas/db.sql applies to in-memory SQLite via vigil-store; (4) GitHub Actions workflows per docs/11 §7; (5) xtask crate with `cargo xtask check`.
Do not implement Windows APIs yet. Finish by running fmt, clippy, tests and listing which M0 acceptance boxes are verified.
```

### M1 — Observe

```
Implement milestone M1. Read docs/02, docs/03, docs/04 §1 (collectors only), docs/09 and docs/11 §2-3.
Order: (1) vigil-core evaluation (Facts → signals → score → verdict, hard rules, masquerade, typosquat with Unicode skeleton, beaconing, path classifier) driven by rules/*.toml, with golden fixtures for every row of docs/03 §3 written FIRST; (2) vigil-store repositories; (3) vigil-win: WinVerifyTrust wrapper (embedded + catalog, revocation cache-only then async), VersionInfo, hashing with (path,size,mtime) cache, process snapshot + parent chain with start-time check, ETW sessions for Kernel-Process / Kernel-Network / DNS-Client (verify provider GUIDs with `logman query providers`), reconciler; (4) `vigilctl scan [--json]`.
All unsafe code stays in vigil-win with SAFETY comments and safe wrappers. Report measured CPU/ETW loss in the stress run and tick the M1 acceptance boxes you can verify; list those you cannot.
```

### M2 — Service, IPC, read-only UI

```
Implement milestone M2. Read docs/02 §7, docs/05, docs/07 and schemas/ipc.schema.json.
(1) VigilSvc via windows-service with SCM recovery and service DACL; (2) vigil-ipc server/client with pipe DACL, first-instance flag, role-by-token, 1 MiB frames, batching, contract tests against the schema; (3) modes observe/learning and settings; (4) scaffold apps/ui with Tauri v2 + React + Tailwind v4 + shadcn, design tokens from docs/07 §2, Rust bridge that owns the pipe, generated TypeScript types from the schema (`pnpm gen`), screens: Overview, Processes, Connections, Rules & Trust (read-only), Settings, i18n vi/en, tray, reconnect UX.
Apply the frontend-design skill for visual quality. Prove 5,000-row virtualized lists at 60 fps with a Playwright trace. Tick acceptance boxes; list what is unverified.
```

### M3 — Enforce Unknown, popup, audit, panic

```
Implement milestone M3. Read docs/04 §1-2 and §6-7, docs/02 §5, docs/09 §4 and docs/07 §5.
(1) WFP in vigil-win: dynamic + persistent providers, sublayers, weights, permit/deny/catch-all, loopback exemption, transactions, idempotent filter keys, net-event subscription; (2) rebuild_then_arm and the system allowlist bootstrap check; (3) Pending/decision flow with scopes, expiry, apply_to publisher, FR-020 re-verification; (4) popup window (no focus steal, no default button, rate-limited), Pending screen, review wizard, tray menu; (5) audit log with hash chain, Windows Event Log anchor, Audit screen; (6) enforcement.panic and `vigilctl panic`.
Safety first: fail-open on crash must be proven by test T-FAIL-01; panic by T-FAIL-02; no self-lockout by T-LOCK-01. Run these in a VM and report results.
```

### M4 — Kill, anti-respawn, persistence

```
Implement milestone M4. Read docs/04 §3-5, docs/08 T5/T11 and docs/11 T-KILL/T-PERS.
(1) kill + tree kill honoring SG-001 never-kill and protected processes; (2) respawn watch by path and sha256; persistent deny; service stop/disable with backup; (3) persistence scanners for every kind in docs/04 §5 with reversible Disable/Restore and delete-after-disable; (4) svchost attribution and svchost_service_suspicious alert; UWP package-id filters.
Never delete files. Prove round-trip restore with tests T-PERS-01 and respawn handling with T-KILL-01.
```

### M5 — AI advisor/auto

```
Implement milestone M5. Read docs/06 completely and schemas/ai-verdict.schema.json. Check https://docs.claude.com for the current Messages API parameters and model IDs before coding; record any difference in docs/06.
(1) vigil-ai client with forced tool use, strict validation, retries, cache, budgets; (2) vigil-core::redact with property tests and the payload preview; (3) DPAPI key storage in the service and write-only ai.config.set; (4) Advisor and Auto with the gates in §4; (5) UI: AI Advisor screen, popup opinion, "Ask AI"; (6) optional VirusTotal client; (7) golden set + stub server tests, live harness behind `--features live`.
Never log keys. Never let AI text reach the policy table. Report live harness metrics if the user provides a key; otherwise state it as pending.
```

### M6 — Hardening, installer, polish

```
Implement milestone M6. Read docs/08 §5, docs/10 M6 and docs/11 §6.
(1) WiX v4 MSI (install, ACLs, self-pin, autostart, upgrade, clean uninstall including WFP objects); (2) self-protection checklist; (3) module-signature check (T14) and optional BEH-005; (4) inbound visibility/blocking option, import/export, geo map; (5) accessibility and performance passes; (6) SBOM, cargo deny/audit gates, release signing instructions.
Run the 24 h soak and report CPU/RSS/ETW loss and any lockout. Verify uninstall leaves no Vigil WFP provider.
```

## 4. Review checklist (use after each milestone)

- [ ] Acceptance boxes in `docs/10` truthfully ticked, with evidence (test names/log excerpts).
- [ ] fmt, clippy, tests green locally and in CI.
- [ ] `unsafe` only in `vigil-win` with `// SAFETY:` comments.
- [ ] Hard-rule precedence and never-kill set covered by tests.
- [ ] No secrets in logs, IPC, UI, fixtures.
- [ ] New actions audited; docs/schemas updated in the same commits.
- [ ] No placeholder text or TODO without a backlog entry.

## 5. Escalation list (ask the owner before proceeding)

1. Choosing a code-signing certificate and release distribution channel.
2. Enabling `enforce` on production endpoints.
3. Enabling AI Auto or `ai.auto_kill`.
4. Adding any new outbound network destination.
5. Any change that weakens a non-negotiable in `CLAUDE.md`.
