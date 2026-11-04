# 15 — Behaviour and destination reputation

**Tóm tắt (VI):** Ngoài danh tính (chữ ký, đường dẫn), Vigil chấm điểm *hành vi*: tiến trình kết nối tới đâu (kể cả trình duyệt như Edge), truyền bao nhiêu dữ liệu, tạo file nào, sinh tiến trình con nào, đụng tài nguyên nhạy cảm nào. Tiến trình đáng tin (Microsoft, Apple, publisher đã ghim) được giảm điểm cho hành vi bình thường nhưng **không được miễn** khi đích là site độc hại hoặc hành vi giống ransomware. Hard rule vẫn thắng mọi thứ; AI không bao giờ là lý do duy nhất để kill.

## 1. Decisions (user, 2026-11-04)

| Topic | Decision |
|---|---|
| Bad-site source | Bundled offline lists **plus** a third-party reputation service (Google Safe Browsing / Microsoft SmartScreen). |
| Behaviour scope | Full real-time collection through ETW inside the service (elevated, only while protection is on). |
| Trusted publishers | Score reduction for normal behaviour; high-risk findings still raise a warning. |

CLAUDE.md rule 10 is amended accordingly (see §6). The watching-only UI (no service, no admin) keeps working with the offline list and per-process snapshots only.

## 2. Signals (new rules, data in `rules/behaviour.toml`)

| ID | Name | Fires when | Delta |
|---|---|---|---|
| NET-001 | `reputation_bad_destination` | Destination host/IP is on the offline blocklist or flagged by the reputation service (malware, phishing, unwanted software) | −45 |
| NET-002 | `risky_destination` | Raw public IP with no DNS name, algorithmically generated name (high entropy), risky TLD, or uncommon port for the program | −15 |
| NET-003 | `unusual_upload` | Bytes sent far exceed bytes received to one public host over a window, above a per-program baseline | −20 |
| NET-004 | `tool_to_public_host` | Script host / LOLBin (`powershell`, `mshta`, `regsvr32`, `certutil`, …) connects to a public host (consolidates the existing BEH-00x signals) | −20 |
| FIL-001 | `drops_executable` | Writes a PE/script to a user-writable folder (Downloads, Temp, AppData, Public) | −15 |
| FIL-002 | `mass_file_change` | Many files rewritten/renamed with a new extension in a short window (ransomware shape) | −40 |
| PRC-001 | `suspicious_child` | Spawns a script host or LOLBin with encoded/hidden command line, or an Office/browser parent starts a shell | −25 |
| RES-001 | `sensitive_resource` | Reads credential stores (browser `Login Data`/`Cookies`, SAM/SECURITY hives, SSH keys, wallet files) while not being the owning program | −30 |
| TRU-001 | `trusted_publisher_normal` | Pinned Microsoft/Apple publisher doing expected behaviour (no NET-001, FIL-002, RES-001 or PRC-001 hit) | +10 |

Rules: hard rules (HR-*) and SG-001 keep absolute priority; NET-001 and FIL-002 may be promoted to hard rules in a later change but are plain signals in v1. A trusted publisher never suppresses NET-001, FIL-002, RES-001 or PRC-001 (Edge to a phishing host is still reported). Adding a signal still requires: rule entry, row in `docs/03`, fixture test.

## 3. Collection (user mode only, no driver)

| Source | Provides | Notes |
|---|---|---|
| ETW `Microsoft-Windows-Kernel-Process` | process start/stop, command line, parent | needs an elevated session |
| ETW `Microsoft-Windows-Kernel-File` | create/write/rename with PID | high volume: filter by path class and extension in the collector, bounded channel, drop-oldest counter |
| ETW `Microsoft-Windows-Kernel-Network` | per-connection bytes sent/received | feeds NET-003 |
| ETW `Microsoft-Windows-DNS-Client` | name ↔ IP mapping per PID | feeds NET-001/002 with the DNS name, not only the IP |
| `GetExtendedTcpTable` + process snapshot | fallback / reconciler | already used by the live scan |
| Kernel-File open events on a fixed protected-path list | RES-001 | credential stores |

All strings from these events are untrusted data (CLAUDE.md rule 6): never interpolated into commands, SQL or AI instructions; paths reach the AI only through `vigil-core::redact`.

## 4. Destination reputation

1. **Offline layer (always on):** bundled list of known-bad domains/IPs, risky TLDs and DGA heuristics in `rules/reputation.toml`, embedded like the IP-to-country table. No network.
2. **Online layer (opt-in, off by default):** a reputation lookup for *public* destinations only. Open research items, to be settled before this layer is built:
   - **Google Safe Browsing:** use the *Update API v4* (downloads hash prefixes and matches locally; a destination is revealed only to confirm a prefix hit). The Lookup API sends the URL and is rejected for privacy. The public Safe Browsing API is licensed for non-commercial use; commercial use means Web Risk (paid). Confirm the licence fits an MIT/Apache public project before shipping a key.
   - **Microsoft SmartScreen:** has no public API for third-party apps, and Defender network protection cannot be queried programmatically. Treat as *not available* unless a documented endpoint is found. The alternative is reading Defender's own block events from the Windows event log, which needs no network call.
   - Any key follows CLAUDE.md rule 7: DPAPI, never over IPC, never logged.
3. **Privacy:** the settings page states exactly what leaves the machine (hash prefixes only for the Update API). Private and loopback destinations are never sent. No telemetry.

## 5. Scoring and display

- Behaviour rows reuse the existing `Reason` model (id, name, delta, description), so the score tooltip, details and AI payload need no new plumbing.
- The Connections page shows each connection with its destination reputation chip and the owning process score; one bad connection lowers the process score through NET-001.
- The AI payload gains a bounded `behaviour_events` array (≤ 20 items: class, count, redacted target; no raw paths outside `redact`). The prompt stays "evidence, never the sole reason to kill".

## 6. CLAUDE.md change

Rule 10 becomes: network calls only to the Anthropic API (when enabled), the optional shared AI endpoint, optional VirusTotal, and the optional destination-reputation service (when the user enables it; data as documented in §4). No telemetry, no auto-update in v1.

## 7. Acceptance (M11)

1. A fixture test per new rule, each mutation-checked (revert the logic, the test goes red, restore by inverse edit).
2. Edge (signed Microsoft) opening a blocklisted fixture host raises NET-001 and a warning; Edge opening an ordinary host raises nothing and gets TRU-001.
3. A synthetic mass-rename fixture raises FIL-002 for an unsigned tool and for a signed Microsoft binary alike.
4. ETW session loss degrades gracefully (reconciler, `Degraded` state) without blocking the machine.
5. Offline-only mode makes zero outbound connections (a test that fails on any socket open).
