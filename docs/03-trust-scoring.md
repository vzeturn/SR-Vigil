# 03 — Trust scoring and anti-forgery

**Tóm tắt (VI):** Điểm = `clamp(50 + Σ trọng số tín hiệu, 0, 100)`, sau đó áp trần (cap). Safe ≥ 80, Unknown 30–79, Malicious ≤ 29. Hard rule (HR-*) ép Malicious bất kể điểm. Toàn bộ trọng số nằm ở `rules/default.toml`; tài liệu này là bản mô tả, file rule là nguồn chạy thực tế.

## 1. Model

```
score    = clamp(BASELINE(50) + Σ delta(signal), 0, 100)
score    = min(score, min(cap(signal)))            # caps, e.g. LOLBin outbound ≤ 70
verdict  = HA-001 ? safe                           # Vigil's own verified binaries
         : HR-*   ? malicious                      # any hard rule
         : HA-002 ? safe                           # user allow, only when no HR-* fired
         : score ≥ 80 ? safe : score ≤ 29 ? malicious : unknown
score    = 0 when a hard rule forces malicious, 100 when HA-001/HA-002 force safe
```

The `signals` array always lists every signal and rule that fired, even when a terminal rule overrides the score. Safe-guard SG-001 never changes a verdict; it only blocks kill/deny actions (see `docs/04`).

- **Static evaluation** is per identity `(sha256, path, signer thumbprint)` and cached.
- **Dynamic evaluation** adds connection/behaviour signals per `(identity, destination)`; a verdict downgrade emits `event.verdict_changed`.
- Evaluations store `rule_pack_version`, signals and score, so any verdict is reproducible.

## 2. Signal catalogue

IDs, deltas and conditions here must match `rules/default.toml` (a contract test enforces it).

### 2.1 Trust signals

| ID | Name | Condition | Δ | Cap |
|---|---|---|---|---|
| SIG-001 | `os_signed_canonical` | Valid signature (embedded or catalog) chaining to a Microsoft root **and** path class `system` (a system process name at a non-canonical path is caught by HR-002) | +45 | |
| SIG-002 | `pinned_publisher_valid` | Valid Authenticode, trusted chain, not revoked, signer matches a pinned publisher (`rules/publishers.toml`) | +40 | |
| SIG-003 | `valid_unpinned_signer` | Valid Authenticode, trusted chain, not revoked, signer not pinned | +25 | |
| SIG-004 | `company_matches_signer` | VersionInfo `CompanyName` consistent with signer organisation | +8 | |
| LOC-001 | `path_program_files_or_system` | Path class `system` or `program_files` | +5 | |
| REP-001 | `vt_clean_established` | VirusTotal enabled: 0 detections, first seen ≥ 30 days | +10 | |

SIG-001, SIG-002 and SIG-003 are mutually exclusive (`exclusive_group = "signer_trust"`, highest `priority` that matches wins: SIG-001 = 3, SIG-002 = 2, SIG-003 = 1).

### 2.2 Risk signals

| ID | Name | Condition | Δ | Cap |
|---|---|---|---|---|
| SIG-010 | `unsigned_user_writable` | Unsigned and path class `user_writable` (Temp, AppData, Downloads, Desktop, Public, ProgramData) | −15 | |
| SIG-011 | `unsigned_other` | Unsigned elsewhere | −5 | |
| SIG-012 | `expired_no_timestamp` | Valid chain except expired certificate without trusted countersignature timestamp | −15 | |
| SIG-013 | `untrusted_root_or_self_signed` | Signature present but root not trusted / self-signed | −20 | |
| SIG-014 | `publisher_company_mismatch` | VersionInfo CompanyName conflicts with signer organisation | −25 | |
| SIG-015 | `os_binary_out_of_place` | Windows-signed OS binary (OS certificate or OS catalog) located in `user_writable`, `removable` or `network_share` paths, e.g. `powershell.exe` copied to Downloads | −30 | |
| SIG-020 | `typosquat_name` | Image name within Levenshtein distance ≤ 2 of a canonical/popular name, or uses confusable characters, and is not that name | −50 | |
| LOC-010 | `network_share_or_removable` | Path on UNC share or removable drive | −15 | |
| BEH-001 | `lolbin_outbound` | LOLBin (`rules/lolbins.toml`) with an outbound connection to a public destination, unless a `context_allow` entry matches the verified parent chain (e.g. Intune/SCCM agents whose own verdict is Safe) | −25 | 70 |
| BEH-002 | `beaconing` | ≥ 6 connections to the same destination in 30 min with interval coefficient of variation < 0.15 | −30 | |
| BEH-003 | `public_dest_no_dns` | Public IP destination with no preceding DNS resolution for that PID within 60 s | −10 | |
| BEH-004 | `risky_port_or_tld` | Destination port in the risky list or DNS name TLD in the risky list (`config/default-policy.toml`) | −10 | |
| BEH-005 | `unbacked_exec_memory` | Executable private memory region not backed by an image file (M6, optional) | −40 | |
| REP-010 | `vt_low_detections` | VirusTotal 1–4 detections | −20 | |
| REP-011 | `vt_high_detections` | VirusTotal 5–9 detections | −60 | |

### 2.3 Hard rules (terminal)

| ID | Name | Condition | Result |
|---|---|---|---|
| HR-001 | `signature_tampered` | Signature present but digest mismatch / `TRUST_E_BAD_DIGEST` / `TRUST_E_SUBJECT_NOT_TRUSTED` for a catalog-listed file | malicious |
| HR-002 | `masquerade_path` | Name in `system_processes.toml` but file not at a canonical path | malicious |
| HR-003 | `masquerade_parent` | Protected system process name with parent ≠ expected (parent check enabled for that entry) | malicious |
| HR-004 | `cert_revoked` | Signer or chain certificate revoked | malicious |
| HR-005 | `vt_consensus_malicious` | VirusTotal enabled and ≥ 10 detections | malicious |
| HR-006 | `user_denylist` | Hash in user deny list | malicious |
| HR-007 | `publisher_impersonation` | VersionInfo/Product claims a pinned publisher (e.g. "Microsoft Corporation") but signature is missing or signed by a different organisation | malicious |

### 2.4 Hard allow and safe-guards

| ID | Name | Condition | Result |
|---|---|---|---|
| HA-001 | `vigil_self` | Vigil binary under its install dir whose signer thumbprint equals the self-pin recorded at install | safe |
| HA-002 | `user_allow_identity` | Unexpired user `allow` decision matching the identity (`file`: sha256+path, or `publisher`: signer thumbprint + product) and no HR-* | safe |
| SG-001 | `never_kill_set` | Identity flagged `never_kill` in `system_processes.toml` and not under HR-001/002/003 | blocks kill/deny actions; never lowers a verdict |

## 3. Worked examples (these are golden tests)

| Case | Signals | Score | Verdict |
|---|---|---|---|
| `C:\Windows\System32\svchost.exe`, MS-signed, parent `services.exe` | SIG-001, SIG-004, LOC-001 | 100 | safe |
| Chrome in Program Files, pinned Google signer | SIG-002, SIG-004, LOC-001 | 100 | safe |
| Small vendor app, valid unpinned signer, Program Files | SIG-003, SIG-004, LOC-001 | 88 | safe |
| Per-user signed app in AppData (e.g. chat client) | SIG-003, SIG-004 | 83 | safe |
| Signed, unpinned, VersionInfo conflicts with signer | SIG-003, SIG-014 | 50 | unknown |
| Unsigned tool in Downloads → public host with DNS | SIG-010 | 35 | unknown |
| Unsigned in Temp, beaconing | SIG-010, BEH-002 | 5 | malicious |
| `svch0st.exe` unsigned in Temp | SIG-010, SIG-020 | 0 | malicious |
| `svchost.exe` in `C:\Users\x\AppData\Local\Temp` | HR-002 | 0 | malicious |
| `powershell.exe` (MS-signed) → public host | SIG-001, SIG-004, LOC-001, BEH-001 | 70 (capped) | unknown |
| MS-signed `powershell.exe` copied to Downloads → public host | SIG-002, SIG-004, SIG-015, BEH-001 | 43 | unknown |
| Binary with "Microsoft Corporation" metadata, unsigned | HR-007 | 0 | malicious |
| Allowed unknown app whose file is replaced (new hash) | re-evaluate, HA-002 no longer matches | — | re-scored |

For rows decided by a hard rule the table shows only the deciding rule; every other signal that fired (for example SIG-002 or LOC-001 on a tampered but otherwise normal file) is still recorded in the evaluation's `signals` array and shown in the UI.

## 4. Publisher trust and pinning

- `rules/publishers.toml` defines built-in publishers by **subject organisation + required issuer chain** (not by hard-coded thumbprints in source).
- At install and on demand, `vigilctl trust bootstrap` (and the installer) reads reference binaries listed in each entry's `bootstrap_from` and records the observed **leaf and intermediate thumbprints** into `%ProgramData%\Vigil\publishers.lock`. Pins are then matched by thumbprint family so certificate renewals by the same CA chain do not create prompts, while a different CA issuing the same subject text does not match.

> **Open finding (M1 scan on a real machine):** when none of a publisher's `bootstrap_from` binaries exists (for example Intel LMS lives in `DriverStore`, not under `%ProgramFiles%`), the publisher has no pins, `signer_pinned` stays false and HR-007 flags genuine, validly signed software as `malicious`. Proposed fix, pending approval because it changes hard-rule semantics: HR-007 only applies to publishers with at least one pin; an un-pinned publisher claim falls back to the ordinary valid-signer signals.
- The admin can add/remove pins in the UI (Rules & Trust) → stored in `trust_publishers` with audit.
- Pin match requires: valid signature **and** subject organisation equal **and** chain issuer in the entry's allowed issuers **and** not revoked.

## 5. Anti-forgery algorithms

1. **Name ↔ path:** normalise (case-fold, strip trailing dots/spaces, resolve 8.3 names, reparse points, `\\?\` prefixes, `\Device\HarddiskVolumeN` → drive letters). If `basename` ∈ canonical table and path ∉ `canonical_paths` → HR-002. Compare with `%SystemRoot%` expansion for the actual Windows directory (not a hard-coded `C:`).
2. **Name ↔ parent:** for entries with `parent = "..."`, compare the parent image identity (path + start time to defeat PID reuse). Entries whose real parent exits (e.g. `csrss.exe`, `wininit.exe`, `winlogon.exe`) set `parent_check = false`.
3. **Publisher ↔ metadata (HR-007/SIG-014):** extract VersionInfo `CompanyName`, `ProductName`, `OriginalFilename`, `LegalCopyright`. Normalise (strip legal suffixes, punctuation, case). If metadata claims a pinned publisher alias and the signer organisation is not that publisher → HR-007 (unsigned or wrong signer). If the signer is valid but organisations differ loosely → SIG-014.
4. **Typosquat (SIG-020):** compare normalised basename (strip extension) against canonical names and top publisher executable names using Levenshtein ≤ 2 **and** a confusables map (`0/o`, `1/l/i`, `rn/m`, `vv/w`, Cyrillic/Greek homoglyphs via Unicode skeleton). Exact canonical names are excluded.
5. **Signature integrity:** verify with `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`), catalog path via `CryptCATAdmin*`; revocation `WTD_REVOKE_WHOLECHAIN` using cache-only first, then async online refresh; record `signature_status` ∈ `valid_embedded | valid_catalog | unsigned | invalid | expired | revoked | untrusted_root`. Re-verify on hash change; revocation re-check at most every 24 h for Safe identities.
6. **PID reuse and image replacement:** identity is bound to `(pid, process start time)`; on image start, the on-disk file hash is re-read if `(size, mtime)` changed.
7. **Signed host, malicious DLL (sideloading):** v2 (M6) — verify signatures of modules loaded by Safe processes in user-writable paths and downgrade on unsigned/invalid modules.

## 6. Beaconing detector (pure function in `vigil-core`)

Input: timestamps of new connections per `(identity, dest_ip, dest_port)` in a sliding 30-minute window. If `n ≥ 6`, compute intervals `Δ`, mean `μ`, standard deviation `σ`; flag when `σ/μ < 0.15` and `μ ≥ 5 s`. Ignore destinations in `beacon_ignore` (NTP, Windows Update, configured telemetry) and loopback/LAN unless configured.

## 7. Path classes

`system` (`%SystemRoot%`, `WinSxS`), `program_files` (both Program Files dirs, `WindowsApps` package roots), `user_writable` (`%TEMP%`, `%LOCALAPPDATA%`, `%APPDATA%`, `Downloads`, `Desktop`, `Public`, `%ProgramData%` excluding Vigil), `network_share`, `removable`, `other`. Classification is computed after normalisation and symlink/junction resolution.

## 8. Rule engine format

Rules live in TOML (`rules/default.toml`); the schema:

```toml
[[rule]]
id              = "SIG-010"
name            = "unsigned_user_writable"
kind            = "signal"       # signal | hard_rule | hard_allow | guard
description     = "Unsigned executable in a user-writable path"
when            = { signature = "unsigned", path_class = "user_writable" }
score           = -15            # signals: delta
cap             = 70             # optional maximum final score
verdict         = "malicious"    # hard_rule / hard_allow only: forced verdict
terminal        = true           # hard_rule / hard_allow only
exclusive_group = "signer_trust" # optional: only the highest priority match in the group applies
priority        = 3              # used with exclusive_group
guard           = "never_kill"   # guard rules only
```

`when` is a conjunction (AND) of predicates; a list value means "any of". Supported keys:

| Key | Values |
|---|---|
| `signature` | `valid_embedded`, `valid_catalog`, `valid` (either), `unsigned`, `invalid`, `expired`, `revoked`, `untrusted_root` |
| `signer_pinned`, `signer_ms_root`, `os_signed`, `at_canonical_path`, `name_in_canonical_set`, `parent_ok`, `parent_check_applies`, `never_kill_set` | bool |
| `company_matches_signer`, `company_conflicts_signer`, `claims_pinned_publisher` | bool |
| `path_class` | one class from §7, or a list of classes |
| `lolbin`, `has_outbound`, `dest_public`, `beaconing`, `public_dest_no_dns`, `risky_port_or_tld`, `typosquat`, `unbacked_exec_memory` | bool |
| `vt_detections_gte`, `vt_detections_lte`, `vt_first_seen_days_gte` | integer; false when VirusTotal is disabled or has no result |
| `user_denylisted`, `user_allowed`, `vigil_self` | bool |

`at_canonical_path` is true when the name is not in the canonical table, or the file sits at one of its `canonical_paths`. `os_signed` is true for files signed with the Windows OS certificate or listed in an OS catalog.

Unknown keys, unknown `kind` values, a `terminal` rule without `verdict`, or an `exclusive_group` without `priority` make the rule pack invalid (load fails closed to the previous pack, with audit).

## 9. Caching and invalidation

- Hash cache key `(path, size, mtime_ns)`; evaluation cache key identity + `rule_pack_version`.
- Invalidate on: file change, rule pack change, trust list change, revocation refresh result change, 7-day TTL for Safe identities.
