# Vigil

**Know what runs on your Windows PC and what it talks to — Safe, Unknown or Malicious, with a reason for every call.**

Vigil is an open-source, user-mode endpoint tool for Windows 10 1809+ / 11. It watches every process and network connection, scores each executable identity from 0 to 100 with an explainable rule engine, and enforces policy: allow, block, or ask you. An AI second opinion (Claude) is optional and can never override a hard rule.

> **Status: v1.0.0.** Process and network classification, WFP enforcement, kill and persistence control, lockdown, the DNS URL filter, the optional Claude advisor and the English UI are implemented and covered by automated tests. Releases are not code-signed yet (see [docs/22](docs/22-code-signing-ci.md)); verify the SHA-256 published with each release. Open items are in [the roadmap](docs/10-roadmap-milestones.md).

## Download

Get `Vigil-1.0.0.msi` and its `.sha256` from the [latest release](https://github.com/vzeturn/SR-Vigil/releases/latest), check the hash (`Get-FileHash .\Vigil-1.0.0.msi`), and run the installer as administrator. On a Windows on ARM device, take the `-arm64.msi` file instead (releases after 1.0.1). Windows SmartScreen will warn until the build is signed. Vigil starts in `learning` mode and blocks nothing until you choose `enforce`.

**Platforms:** Windows 10/11 today. macOS is planned in stages (portability refactor, observe-only, then enforcement); see [docs/17-cross-platform-macos.md](docs/17-cross-platform-macos.md).

> **VI:** Vigil là công cụ bảo vệ endpoint chạy hoàn toàn ở user-mode cho Windows: phân loại mọi process và kết nối mạng thành Safe / Unknown / Malicious, giải thích được từng quyết định, tự chặn hoặc hỏi người dùng; AI (Claude) chỉ là ý kiến tham khảo tùy chọn. Dự án đang phát triển, chưa dùng làm lớp bảo vệ chính.

## Why Vigil

- **Explainable.** Every verdict lists the signals that fired and their score deltas. No black box.
- **Hard rules win.** Tampered signature, system-name masquerade, wrong parent process, publisher impersonation and revoked certificates override any score and any AI output.
- **User-mode only.** No kernel driver. Enforcement uses Windows Filtering Platform *filters*, `TerminateProcess` and the Service Control Manager.
- **Fails safe for usability.** The catch-all block filter is session-scoped, so a crashed service never leaves the machine offline. Unknown apps stay blocked while it runs.
- **Local-first and private.** No telemetry, no auto-update. The only network calls are the optional AI advisor (your own Anthropic key, or the project's rate-limited proxy, opt-out), optional VirusTotal and MalwareBazaar (your own key, only a file's SHA-256 is sent), the CIRCL known-good hash lookup (SHA-256 only, opt-out), opt-in downloads of the signed version catalogue, the signed rule pack (it can only add warning signs) and the domain blocklists (GET only). Nothing else leaves the machine.
- **Self-defending.** Programs that clone themselves or flood the machine with script hosts are killed in every mode; a hijacked Safe program is reclassified Malicious ([docs/04 §8](docs/04-enforcement-wfp.md)).
- **URL filter.** An optional local DNS sinkhole blocks malware, phishing, adult and ad domains from public lists, with protected names and your own exceptions; DNS is restored automatically ([docs/23](docs/23-url-filter.md)).
- **Suspicious network behaviour.** Programs that call one Internet address at a regular rhythm (beaconing) are flagged from connection timing alone; traffic is never decrypted or read, and nothing about it goes to the AI until you press Analyze ([docs/24](docs/24-suspicious-network-behaviour.md)).
- **One switch.** Pause protection from the header: nothing is blocked or killed while paused, assessments stay live.
- **No silent destruction.** Nothing is deleted automatically; persistence items are disabled reversibly after your approval.

## How it classifies

| Verdict | Score | In `enforce` mode |
|---|---|---|
| **Safe** | ≥ 80 | Allowed without prompting (still checked for forgery). |
| **Unknown** | < 80 | Network blocked, you choose Allow / Block / Kill. A low score means "not proven", not malicious. |
| **Malicious** | a hard rule or real evidence | Blocked and terminated. |

Modes: `observe` (log only), `learning` (build a baseline), `enforce`. Authority order: Vigil's own binaries and the never-kill guard › hard rules › your decisions › AI verdict › score. Details: [docs/03-trust-scoring.md](docs/03-trust-scoring.md).

## Architecture

```
 ETW (process / network / DNS)          Tauri v2 + React UI
          │                                     │  invoke / events
 ┌────────▼─────────┐   named pipe   ┌──────────▼─────────┐
 │ VigilSvc (SYSTEM)│◄──────────────►│ UI (Rust side owns │
 │ collect · score  │ \\.\pipe\      │ the pipe)          │
 │ enforce · audit  │ vigil-control  └────────────────────┘
 └───┬──────────┬───┘
     │ WFP filters, TerminateProcess        optional: Anthropic API · VirusTotal
     ▼
 SQLite (hash-chained audit log)
```

| Crate | Role |
|---|---|
| `vigil-core` | Pure scoring, policy, masquerade and beaconing logic. No OS dependency; tested on any platform. |
| `vigil-store` | SQLite persistence and audit chain. |
| `vigil-ipc` | Named-pipe framing and protocol types. |
| `vigil-ai` | Claude client, redaction, verdict-schema validation. |
| `vigil-win` | The only crate with `unsafe`: ETW, WFP, `WinVerifyTrust`, process control. |
| `vigil-svc` / `vigilctl` | Windows service host and admin CLI. |
| `apps/ui` | Tauri v2 desktop app (English). |

| `proxy/`, `catalogue/` | Optional Cloudflare Workers: shared AI endpoint, signed version catalogue and signed rule pack. Deployed separately; secrets via `wrangler secret`, account id via `CLOUDFLARE_ACCOUNT_ID`. |

Full design: [docs/](docs/) (requirements, architecture, enforcement, IPC, AI advisor, threat model, data model, testing, release).

## Build from source

Requirements: Windows 10 1809+/11, Rust stable (see `rust-toolchain.toml`), Visual Studio 2022 Build Tools with the Windows SDK, Node 22+, pnpm, WebView2.

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                 # core/store/ipc/ai run on any OS
cargo run -p vigilctl -- status
pnpm -C apps/ui install; pnpm -C apps/ui tauri dev
```

Build the installer with `installer/build.ps1` ([docs/13-release.md](docs/13-release.md)); it is self-contained and needs no prerequisites on the target machine.

### Developing on macOS or Linux

Everything except the Windows layer builds and tests on macOS and Linux (CI lints the workspace on Ubuntu). This covers scoring, rules, store, IPC, AI, the service logic, the UI front end and both Workers. Requirements: Rust stable, Node 22+, pnpm.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                       # vigil-win is empty off Windows
pnpm -C apps/ui install && pnpm -C apps/ui lint && pnpm -C apps/ui test
(cd proxy && npm test) && (cd catalogue && npm test)
```

These need Windows and are checked by the `windows-latest` CI jobs or on a Windows VM:
- `vigil-win`, including its `--features integration` tests (elevated);
- the running service;
- the Tauri app's named-pipe side;
- the MSI.

The Workers deploy from any OS with `wrangler`, using `CLOUDFLARE_ACCOUNT_ID` set to the maintainer's own account (see `proxy/README.md`, `catalogue/README.md`).

## Security

Vigil handles privileged operations and an API key, so it is built defensively:

- The Anthropic API key lives only in the service, encrypted with DPAPI; it is never sent over IPC, logged, or shown in the UI.
- Process names, paths, command lines and DNS names are treated as untrusted data: bound SQL parameters, no shell interpolation, redacted and schema-constrained AI prompts.
- The control pipe is restricted to administrators; the data directory `%ProgramData%\Vigil` is SYSTEM + Administrators only.

Found a vulnerability? Please follow [SECURITY.md](SECURITY.md) and do not open a public issue.

## Contributing

Read [CLAUDE.md](CLAUDE.md) for the non-negotiable constraints and conventions, then the relevant doc under `docs/`. Commits use `area: imperative summary`. `fmt`, `clippy -D warnings` and tests must pass. Never commit secrets, API keys, certificates or machine data — the `.gitignore` is deliberately strict.

## License

Dual-licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option. Unless you state otherwise, any contribution you intentionally submit for inclusion in Vigil is dual-licensed as above, without additional terms.
