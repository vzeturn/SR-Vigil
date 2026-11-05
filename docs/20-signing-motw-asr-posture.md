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

## 5. Not done: network attestation databases

NSRL, CIRCL hashlookup, MalwareBazaar and Defender cloud reputation need outbound hash lookups, which rule 10 forbids. Adding them requires a user-approved change to rule 10 (see `docs/10`, M15).
