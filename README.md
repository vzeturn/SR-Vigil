# Vigil — Windows Process & Connection Trust Guard

> **VI:** Phần mềm an ninh endpoint viết bằng Rust, kiểm tra mọi process và kết nối mạng của máy Windows, chấm điểm độ tin cậy, tự động cho phép / chặn / hỏi người dùng, có thể nhờ Claude đánh giá thay.
> **EN:** A Rust endpoint-security tool that inspects every process and network connection on a Windows host, scores trustworthiness, and automatically allows, blocks, or asks the user — optionally delegating decisions to Claude.

---

## 1. Tóm tắt (VI)

### Giá trị
- Giảm rủi ro mã độc và dịch vụ lạ gọi ra Internet mà không cần mua EDR đầy đủ.
- Mọi quyết định đều có **lý do giải thích được** (signal + điểm), có audit log, có thể kiểm toán (ISO/IEC 27001:2022 A.8.7, A.8.15, A.8.16, A.8.20).
- Chạy hoàn toàn ở user-mode (không cần viết kernel driver) và local-first: AI là tùy chọn.

### Ba mức kết luận

| Verdict | Điểm | Hành vi khi `enforce` |
|---|---|---|
| **Safe** | ≥ 80 | Cho qua, không hỏi. Publisher tin cậy nhưng vẫn bị kiểm tra giả mạo. |
| **Unknown** | 30–79 | Chặn mạng, hiện popup **Allow / Block / Kill**. |
| **Malicious** | ≤ 29 hoặc khớp hard rule | Chặn ngay, kill process, khóa chặn bật lại. |

### Kiến trúc một đoạn
Windows service `VigilSvc` (Rust, chạy SYSTEM) thu thập sự kiện bằng ETW, chấm điểm bằng rule engine (chữ ký số, chống giả mạo, hành vi), thi hành bằng Windows Filtering Platform (WFP) và `TerminateProcess`. UI Tauri v2 (React) giao tiếp với service qua named pipe `\\.\pipe\vigil-control`. Claude (Messages API) chỉ nhận metadata đã ẩn danh hóa và chỉ được trả JSON theo schema cố định; hard rule luôn thắng AI.

### Bắt đầu với Claude Code (3 bước)
1. Mở terminal tại thư mục này (Windows 10 1809+/11, đã cài Rust stable, Node 22+, pnpm, WebView2).
2. Chạy `claude`, rồi gõ: `/milestone M0`.
3. Duyệt kết quả theo checklist ở `docs/12-handoff-prompts.md`, lặp lại với `M1` … `M6`.

### Bộ tài liệu

| File | Nội dung |
|---|---|
| `CLAUDE.md` | Chỉ dẫn cố định cho Claude Code (ràng buộc, lệnh, quy ước) |
| `docs/00-overview.md` | Tầm nhìn, phạm vi, thuật ngữ |
| `docs/01-requirements.md` | Yêu cầu chức năng / phi chức năng (FR/NFR) |
| `docs/02-architecture.md` | Thành phần, crate, luồng dữ liệu, state machine |
| `docs/03-trust-scoring.md` | Mô hình chấm điểm, hard rule, chống giả mạo |
| `docs/04-enforcement-wfp.md` | WFP, kill, chống bật lại, persistence audit |
| `docs/05-ipc-protocol.md` | Giao thức named pipe service ↔ UI |
| `docs/06-ai-advisor.md` | Tích hợp Claude, redaction, chống prompt injection |
| `docs/07-ui-spec.md` | Đặc tả UI/UX, design tokens, màn hình |
| `docs/08-threat-model.md` | Mô hình mối đe dọa, ánh xạ ISO 27001 |
| `docs/09-data-model.md` | SQLite, retention, audit hash chain |
| `docs/10-roadmap-milestones.md` | Milestone M0–M6 và tiêu chí nghiệm thu |
| `docs/11-testing.md` | Chiến lược kiểm thử, ca kiểm thử, CI |
| `docs/12-handoff-prompts.md` | Prompt bàn giao từng milestone cho Claude Code |
| `schemas/` | JSON Schema cho IPC, schema verdict của AI, SQL schema |
| `rules/` | Rule mặc định, danh sách publisher, process hệ thống, LOLBin |
| `config/default-policy.toml` | Chính sách mặc định của service |

---

## 2. Summary (EN)

**Vigil** is a Windows service (`VigilSvc`) plus a Tauri v2 UI. The service collects process and network telemetry via ETW, verifies Authenticode/catalog signatures, scores each executable identity from 0 to 100 with an explainable rule engine, and enforces policy with WFP filters and process termination. Unknown executables are blocked from the network until a user (or Claude, if configured) approves them. Hard rules (tampered signature, masquerading system binary, wrong parent process, revoked certificate, publisher impersonation) always override scores and AI output.

- **Language/stack:** Rust (service, core, IPC, store, AI client) · Tauri v2 + React + TypeScript + Tailwind (UI) · SQLite.
- **Scope:** user-mode only; no kernel driver; outbound enforcement first, inbound visibility second.
- **Start:** see `docs/12-handoff-prompts.md`. Milestones: `docs/10-roadmap-milestones.md`.

## 3. Repository layout

```
vigil/
├── CLAUDE.md                  # standing instructions for Claude Code
├── .claude/                   # slash commands + permissions
├── Cargo.toml                 # workspace
├── crates/
│   ├── vigil-core/            # pure logic: types, scoring, policy (cross-platform)
│   ├── vigil-store/           # SQLite persistence, audit chain
│   ├── vigil-ipc/             # named-pipe framing + protocol types
│   ├── vigil-ai/              # Claude client, redaction, cache
│   ├── vigil-win/             # ETW, WFP, WinVerifyTrust, process control (cfg(windows))
│   ├── vigil-svc/             # service binary (SCM host + orchestrator)
│   └── vigilctl/              # admin/debug CLI
├── apps/ui/                   # Tauri v2 app (created in M2)
├── rules/                     # default rule pack (embedded at build time)
├── config/                    # default policy
├── schemas/                   # JSON Schema + SQL
└── docs/                      # design documents
```
