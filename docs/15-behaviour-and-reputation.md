# 15 — Behaviour and destination reputation

**Tóm tắt (VI):** Ngoài danh tính (chữ ký, đường dẫn), Vigil chấm điểm *hành vi*: tiến trình kết nối tới đâu (kể cả trình duyệt như Edge), truyền bao nhiêu dữ liệu, tạo file nào, sinh tiến trình con nào, đụng tài nguyên nhạy cảm nào. Tiến trình đáng tin (Microsoft, Apple, publisher đã ghim) được giảm điểm cho hành vi bình thường nhưng **không được miễn** khi đích là site độc hại hoặc hành vi giống ransomware. Hard rule vẫn thắng mọi thứ; AI không bao giờ là lý do duy nhất để kill.

## 1. Decisions (user, 2026-11-04)

| Topic | Decision |
|---|---|
| Bad-site source | Bundled offline lists and the URL-filter malware/phishing feeds; no online destination lookup (revised 2026-11-11, see §4). |
| Behaviour scope | Full real-time collection through ETW inside the service (elevated, only while protection is on). |
| Trusted publishers | Score reduction for normal behaviour; high-risk findings still raise a warning. |

CLAUDE.md rule 10 is amended accordingly (see §6). The watching-only UI (no service, no admin) keeps working with the offline list and per-process snapshots only.

## 2. Signals (new rules, data in `rules/behaviour.toml`)

| ID | Name | Fires when | Delta |
|---|---|---|---|
| NET-001 | `reputation_bad_destination` | Destination host/IP is on the offline blocklist or flagged by the reputation service (malware, phishing, unwanted software) | −45 |
| NET-002 | `generated_destination_name` | Algorithmically generated DNS name (high entropy). Raw IP without DNS stays BEH-003 and risky port/TLD stays BEH-004 (`docs/03`), so nothing is counted twice | −15 |
| NET-003 | `unusual_upload` | Bytes sent far exceed bytes received to one public host within a window: fixed thresholds in `rules/upload.toml` (≥ 50 MB and ≥ 10× received in 10 min) rather than a learned per-program baseline; pinned publishers are exempt | −20 |
| NET-004 | `tool_to_public_host` | Consolidated into BEH-001 `lolbin_outbound` (−25, cap 70), now fed live; no separate rule | — |
| FIL-001 | `drops_executable` | Writes a PE/script to a user-writable folder (Downloads, Temp, AppData, Public) | −15 |
| FIL-002 | `mass_file_change` | Many files rewritten/renamed with a new extension in a short window (ransomware shape) | −40 |
| PRC-001 | `suspicious_child` | Spawns a script host or LOLBin with encoded/hidden command line, or an Office/browser parent starts a shell | −25 |
| RES-001 | `sensitive_resource` | Reads credential stores (browser `Login Data`/`Cookies`, SAM/SECURITY hives, SSH keys, wallet files) while not being the owning program | −30 |
| TRU-001 | `trusted_publisher_normal` | Pinned publisher whose chain ends in a Microsoft root doing expected behaviour: no NET-001, PRC-001, FIL-002 or RES-001 finding this run | +10 |

Rules: hard rules (HR-*) and SG-001 keep absolute priority; NET-001 and FIL-002 may be promoted to hard rules in a later change but are plain signals in v1. A trusted publisher never suppresses NET-001, FIL-002, RES-001 or PRC-001 (Edge to a phishing host is still reported). Adding a signal still requires: rule entry, row in `docs/03`, fixture test.

## 3. Collection (user mode only, no driver)

| Source | Provides | Notes |
|---|---|---|
| ETW `Microsoft-Windows-Kernel-Process` | process start/stop with parent PID and image | needs an elevated session; the event carries no command line, so for a child named in `rules/spawn.toml` the collector reads it with `NtQueryInformationProcess(ProcessCommandLineInformation)` right after the start event (missed when the child exits first). Feeds PRC-001 on the parent. Every start is also handed to the observer (bounded queue of 1024, oldest dropped): an image that exits before the next 500 ms snapshot is still evaluated, recorded and, if malicious, alerted |
| ETW `Microsoft-Windows-Kernel-File` | keywords CREATE (event 12, every open, field `FileName`), RENAME_SETLINK_PATH (27, field `FilePath` = the name **after** the rename) and CREATE_NEW_FILE (30, `FileName`); PID from the event header; paths in NT device form (`\Device\HarddiskVolumeN\...`), matched on their tail so no drive-letter mapping is needed | high volume: the callback queues only events matching `rules/files.toml` (FIL-001 drops, FIL-002 double-extension renames, RES-001 store opens) into the bounded queue shared with the other providers, so a burst cannot crowd out process and network events; when the queue is full the newest event is dropped |
| ETW `Microsoft-Windows-Kernel-Network` | events 10/11 (TCPv4 sent/received), 26/27 (TCPv6) and 42/43 (UDPv4), fields `PID`, `daddr` (remote address) and `size`; no payload | per-packet volume: totals per (pid, address) are kept on the callback thread and only a crossed NET-003 threshold is queued (once per window); feeds NET-003 |
| ETW `Microsoft-Windows-DNS-Client` | event 3008 `QueryName` + `QueryResults`: name ↔ IP mapping per PID (10 min, bounded) | feeds NET-001/002 with the DNS name, not only the IP; no packet is read, so TLS SNI/JA4 capture is not needed |
| `GetExtendedTcpTable` + process snapshot | fallback / reconciler | the 500 ms snapshot stays the source of truth for running processes, so starts or stops ETW lost (full queue, session stopped) are repaired on the next tick |
| Kernel-File open events (event 12) on the store list in `rules/files.toml` | RES-001 | attributed to the program behind the PID; an owner-named program is decided at evaluation, where its signature is known |

All strings from these events are untrusted data (CLAUDE.md rule 6): never interpolated into commands, SQL or AI instructions; paths reach the AI only through `vigil-core::redact`.

## 4. Destination reputation

1. **Offline layer (always on, built):** bundled bad hosts, risky ports/TLDs and the DGA thresholds in `rules/reputation.toml`, embedded like the IP-to-country table, plus the malware and phishing lists of the URL filter when the user has downloaded them (`docs/23`). No network. Each public outbound connect (ETW, or the table poll without ETW) is assessed once per program and finding: a new finding re-evaluates the program and writes an audit row naming the signals.
2. **Online layer:** not built. Google Safe Browsing and SmartScreen were not chosen (user decision, 2026-11-11): Safe Browsing's licence is non-commercial and SmartScreen has no public API. File-hash lookups (VirusTotal, MalwareBazaar) are opt-in with the user's key and send only a SHA-256 (`docs/20 §5.1`).
3. **Privacy:** destinations never leave the machine. No telemetry.

## 5. Scoring and display

- Behaviour rows reuse the existing `Reason` model (id, name, delta, description), so the score tooltip, details and AI payload need no new plumbing.
- The Connections page shows each connection with its destination reputation chip and the owning process score; one bad connection lowers the process score through NET-001.
- The AI payload carries `behaviour.events` (≤ 20 items): one fixed class word per finding above (NET-001/002/003, BEH-003/004, PRC-001, FIL-001/002, RES-001 for a foreign store), with no count and no target. The destination already travels in `destination` under its own consent rule, and fixed words cannot carry attacker text. The words sit inside the existing `behaviour` key, so the shared endpoint's allowlist is unchanged; the prompt treats them as evidence, never the sole reason to kill.

## 6. CLAUDE.md change

None: the offline layer makes no network call. The rule-10 entry for an optional destination-reputation service stays reserved but unused, since no online layer was chosen (§4).

## 7. Acceptance (M11)

1. A fixture test per new rule, each mutation-checked (revert the logic, the test goes red, restore by inverse edit).
2. Edge (signed Microsoft) opening a blocklisted fixture host raises NET-001 and a warning; Edge opening an ordinary host raises nothing and gets TRU-001.
3. A synthetic mass-rename fixture raises FIL-002 for an unsigned tool and for a signed Microsoft binary alike.
4. ETW session loss degrades gracefully (reconciler, `Degraded` state) without blocking the machine.
5. Offline-only mode makes zero outbound connections (a test that fails on any socket open).
