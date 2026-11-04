# CLAUDE.md — Vigil

You are implementing **Vigil**, a Windows endpoint tool that classifies every process and network connection as Safe / Unknown / Malicious, enforces policy, and optionally asks Claude for a second opinion. The full design lives in `docs/`. Read the relevant doc **before** writing code for a milestone. When code and docs disagree, stop and fix the doc in the same change.

## Non-negotiables

1. **User-mode only.** Never write or propose a kernel driver or WFP callout driver. Enforcement uses WFP *filters* (not callouts), `TerminateProcess`, and the Service Control Manager.
2. **Hard rules beat everything.** Order of authority: `HA-001 (Vigil's own binaries)` and `SG-001 never-kill guard` > `hard rules (HR-*)` > `user decisions (HA-002)` > `AI verdict` > `score`. AI can never override a hard rule and can never be the sole reason to kill a process (see `docs/06-ai-advisor.md`).
3. **Fail open on service failure, fail closed on unknown apps.** The catch-all block filter is a *dynamic* (session-scoped) WFP filter so a crashed service never leaves the machine offline. Explicit user/hard-rule denies are persistent.
4. **No silent destructive actions.** Never delete files, registry keys, scheduled tasks or services automatically. Disable (reversible, with backup row in DB) only after user approval; delete only after a second explicit approval.
5. **Never kill or block the never-kill set** (`rules/system_processes.toml`, `never_kill = true`) unless HR-001, HR-002 or HR-003 fired. Protected/PPL processes: report `protected_target`, do not retry.
6. **Untrusted data stays data.** Process names, command lines, file paths, DNS names and every other string from the host are untrusted. Never interpolate them into shell commands, SQL (use bound parameters), log format strings, or AI instructions.
7. **Secrets.** The Anthropic API key is stored only in the service, encrypted with DPAPI (machine scope + entropy). It is never returned over IPC, never logged, never sent to the UI. Use `secrecy::SecretString` and `zeroize`.
8. **`unsafe` is allowed only in `vigil-win`**, each block with a `// SAFETY:` comment, wrapped in a safe API. Other crates use `#![forbid(unsafe_code)]`.
9. **No placeholder text** in shipped code, docs, UI strings or configs. If something is deliberately deferred, write it as a tracked item in `docs/10-roadmap-milestones.md`.
10. **No network calls except** the Anthropic API (when enabled) and optional VirusTotal (when enabled). No telemetry, no auto-update in v1.

## Fixed constants (single source of truth: `crates/vigil-core/src/consts.rs`, mirrored in `docs/03` and `schemas/`)

| Name | Value |
|---|---|
| Score range / baseline | 0–100 / 50 |
| `SAFE_MIN` / `MALICIOUS_MAX` | 80 / 29 (Unknown = 30–79) |
| Modes | `observe`, `learning`, `enforce` |
| Verdicts | `safe`, `unknown`, `malicious` |
| Decision actions | `allow`, `block`, `kill` |
| Decision scopes | `once`, `1h`, `24h`, `forever` |
| Decision apply_to | `file` (sha256 + path), `publisher` |
| Pipe | `\\.\pipe\vigil-control` |
| Protocol version | `1` |
| Service name | `VigilSvc` |
| Data dir | `%ProgramData%\Vigil` (ACL: SYSTEM + Administrators only) |
| CLI | `vigilctl` |

## Workspace and dependency rules

- `vigil-core` depends on nothing OS-specific and on no other Vigil crate. All scoring/policy logic lives here and is unit-testable on Linux.
- `vigil-store`, `vigil-ipc`, `vigil-ai` depend only on `vigil-core`.
- `vigil-win` depends on `vigil-core`; the whole crate is `#![cfg(windows)]`.
- `vigil-svc` orchestrates everything; `vigilctl` talks to the service via `vigil-ipc` only.
- `apps/ui` never touches the pipe from JavaScript. The Tauri Rust side owns the pipe; React uses `invoke` and Tauri events.

## Commands

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                       # core/store/ipc/ai run on any OS
cargo test -p vigil-win --features integration   # Windows + elevated shell only
cargo run -p vigilctl -- status
pnpm -C apps/ui install && pnpm -C apps/ui tauri dev
pnpm -C apps/ui lint && pnpm -C apps/ui test
```

## Conventions

- Rust edition 2024, `thiserror` for library errors, `anyhow` only in binaries, `tracing` for logs (structured fields, no string-built messages).
- Public types crossing IPC derive `serde::{Serialize, Deserialize}` and match `schemas/ipc.schema.json` exactly; add a contract test that validates sample payloads against the schema.
- Rules are data (`rules/*.toml`), embedded with `include_str!`, overridable from `%ProgramData%\Vigil\rules.d\`. Adding a signal means: rule entry + doc row in `docs/03` + fixture test.
- Every enforcement action writes an audit row (hash-chained, see `docs/09`).
- UI strings go through i18n (`vi`, `en`); never hardcode user-visible text.
- Commit small, one concern per commit, message format `area: imperative summary` (e.g. `win: add WinVerifyTrust wrapper`).

## Workflow

1. Use `/milestone Mx` to execute a milestone end-to-end; it reads the milestone's acceptance criteria and stops when all are verified.
2. Write tests first for `vigil-core` logic (fixtures in `crates/vigil-core/tests/fixtures/`).
3. Windows-only behaviour must be verifiable by an integration test or a documented manual check in `docs/11-testing.md`.
4. Before declaring done: fmt, clippy, tests, and a self-review via `/review`.
5. If a requirement is ambiguous or a Windows API behaves differently than the docs assume, record the finding in `docs/` and ask the user before changing the design.
