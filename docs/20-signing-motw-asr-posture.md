# 20 — Signing depth, Mark of the Web and ASR posture

Local-only evidence that strengthens a verdict without new network calls (`CLAUDE.md` rule 10).

## 1. Code signing (already in `vigil-win/src/trust.rs`)

WinVerifyTrust with catalog lookup (Microsoft's catalog database), revocation from the local cache only, publisher pinning and typosquat detection. Rules: SIG-003, SIG-010, SIG-011, KNOW-001. Unchanged here.

## 2. Mark of the Web (SRC-001)

Windows, browsers and mail clients attach a `Zone.Identifier` stream to downloaded files. `vigil_core::analysis::motw::from_internet` reads only `ZoneId` (3 Internet, 4 Restricted) from the `[ZoneTransfer]` section. `HostUrl` and `ReferrerUrl` are untrusted text and are never read, stored or logged. The reader is `vigil-win/src/observe.rs::from_internet`, capped at 4096 bytes. Rule SRC-001 (−10) applies to downloaded, unsigned programs; a missing stream is neutral because most legitimate installs carry none.

## 3. ASR posture (read-only)

`vigil_core::posture::RECOMMENDED_ASR` lists the Microsoft Defender Attack Surface Reduction rules that cover gaps Vigil cannot see. `vigil-win/src/asr.rs` reads each rule's state from the registry (policy key first, then local key). `vigilctl posture` prints state per rule and a summary. Vigil never changes Defender settings (rule 4); it only tells the user what is off.

## 4. Block lifetime

An anti-respawn block lives only as long as the kill decision that created it. `respawn_scan` first lifts any block with no active kill decision (revoked, expired or never recorded), so a program the user no longer denies is not killed again. Audit and log record the release.

## 5. Known-good hash lookup (HASH-001)

User decision: network attestation sources are allowed (`CLAUDE.md` rule 10 amended). The service asks CIRCL hashlookup (NIST NSRL and vendor package hashes) about the SHA-256 of each unknown **unsigned** file: one GET per hash, nothing else sent (no path, name or machine data), the answer asked once and cached in `%ProgramData%\Vigil\hashrep.json`. Setting `hash_reputation.enabled` (default on) turns it off. A `hashlookup:trust` of 50 or more marks the hash known-good; the answer is untrusted JSON of which only that number is read. HASH-001 adds +15 to an unsigned file and never makes it Safe on its own (baseline 50 + 15 stays Unknown). Signed files are judged by their signature and never sent.

### 5.1 Keyed services: VirusTotal and MalwareBazaar (REP-001/010/011, HR-005, HR-008)

User decision (2026-11-13): both are opt-in, use the user's own key, and receive **only the SHA-256** of an unknown unsigned file, never the file, path, name or machine data.

- **Keys.** Set in Settings or with `reputation.config.set` (admin). The key is sealed with DPAPI (machine scope, the `ai.entropy` value) under `rep.virustotal.key` / `rep.malwarebazaar.key`. It is write-only: `reputation.config.get` returns only `has_key`, the audit row (`config_change`) names the service and what changed, never the key. Turning a service on without a key is refused; an empty key removes it and turns the service off.
- **VirusTotal.** `GET https://www.virustotal.com/api/v3/files/<sha256>` with `x-apikey`. Only `last_analysis_stats.malicious` and `first_submission_date` are read; 404 means unknown to VirusTotal. At most 3 questions a minute, 16 s apart (free key: 4/min), and no more than `virustotal.daily_lookup_budget` (default 500) a UTC day.
- **MalwareBazaar.** `POST https://mb-api.abuse.ch/api/v1/` with `Auth-Key` and the body `query=get_info&hash=<sha256>`. The hash counts as listed only when `query_status` is `ok` and `data` is non-empty; a listed sample fires HR-008 (malicious, terminal).
- **Cache and re-asking.** Answers are cached in `hashrep-virustotal.json` / `hashrep-malwarebazaar.json` in the data directory and asked again after 7 days, so later detections reach files already seen. A hit queues every recorded path of that file for re-scoring at once; otherwise the hourly recheck picks it up. Any error, including HTTP 429, ends the round and the next minute tries again. Answers are untrusted JSON capped at 2 MiB (VirusTotal) and 64 KiB (MalwareBazaar).

## 6. Trust by verified hash

`vigilctl allow <path> --sha256 <hash> --source <where verified>` records a forever allow bound to the file's hash. The service refuses it if it sees different bytes. Use it after comparing the file with the vendor's official release.

## 7. ASR defaults chosen

Block: LSASS credential theft, Office child processes, email executable content, scripts launching downloads, obfuscated scripts, Office macro Win32 calls, untrusted USB programs, WMI persistence, vulnerable signed drivers. Audit only (they break developer and admin tools): PsExec/WMI process creation, programs that are not widely used. Change with `Set-MpPreference` or Windows Security; `vigilctl posture` shows the result.
