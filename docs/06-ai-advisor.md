# 06 — AI advisor (Claude)

**Tóm tắt (VI):** Người dùng nhập API key của Anthropic; service gọi Messages API với metadata đã ẩn danh hóa, bắt buộc trả JSON theo schema qua tool use. Hai chế độ: **Advisor** (chỉ gợi ý trong popup) và **Auto** (tự quyết khi độ tin cậy vượt ngưỡng). AI không bao giờ ghi đè hard rule và không được tự ý kill nếu chưa bật riêng.

## 1. Modes

| Mode | Behaviour |
|---|---|
| `off` | No AI calls. |
| `advisor` | For each Unknown Pending item, request an opinion; display `verdict`, `confidence`, `reasons` in the popup and details. User still decides. |
| `auto` | If the opinion passes the auto-decision gates (§4) the service applies it as a decision with `by = "ai"`; otherwise falls back to Pending for the user. |

## 2. API usage

- Endpoint: Anthropic Messages API over HTTPS (rustls), `anthropic-version` header set per the official docs; the key is sent in `x-api-key`.
- Models are **configuration**: `model` (default `claude-haiku-5-5`) and `escalation_model` (default `claude-sonnet-5-5`) used when the first opinion has `confidence < escalate_below` (default 0.75). Verify current model IDs and API parameters at https://docs.claude.com before M5.
- Structured output through **forced tool use**: `tools = [submit_verdict]`, `tool_choice = {"type":"tool","name":"submit_verdict"}`. The tool `input_schema` is `schemas/ai-verdict.schema.json`. The response is rejected unless it contains exactly one `tool_use` block that validates against the schema (extra fields stripped, enums enforced, string lengths bounded).
- `max_tokens` 400, no `temperature` (the 5.5 models reject it with HTTP 400), request timeout 8 s, one retry on 429/5xx with jitter, then give up (fail to Pending).
- Concurrency 2, daily call budget (default 500) and monthly spend guard (user-set, optional) enforced locally; exhausted budget → `ai_unavailable`.

## 3. Privacy and redaction (payload contract)

Only the fields below are ever sent. Everything else is dropped.

| Field | Treatment |
|---|---|
| `image_name` | basename only |
| `path_class` + redacted path | user profile segment → `%USERNAME%`, machine/domain names removed, drive letters kept |
| `sha256` | sent as is (lets the model reason about known samples, no file content) |
| `signature` | status, signer organisation, issuer, validity dates (no serials) |
| `version_info` | CompanyName, ProductName, OriginalFilename, FileDescription |
| `parent_chain` | up to 3 ancestors: basename + verdict + signer org |
| `destination` | dest class (`private`, `public`), port, DNS name **only if public**; private/internal IPs and hostnames → class labels; no URLs, no payloads |
| `behaviour` | counts and flags (beaconing, connection count, first seen, lolbin) |
| `known_software` | label and one-line description when the image name and vendor text match `rules/known_software.toml` (omitted otherwise); evidence only, never grants trust by itself |
| `rule_result` | score, signals (ids + deltas), hard rules |
| `command_line` | **not sent** unless `ai.send_cmdline = true`; then truncated to 200 chars, secrets-pattern scrubbed (tokens, `-p`/`--password` values, URLs credentials), hashed fingerprint added |

The payload is built by `vigil-core::redact` (pure, unit-tested with property tests: no `%USERPROFILE%` username, no RFC1918 IP, no string longer than limits). The UI shows the exact payload that would be sent ("Preview AI payload" button) and the settings page states what leaves the machine (ISO/IEC 27701 data-minimisation evidence).

## 4. Safety gates for Auto mode

**Authority follows the service mode.** AI is on in every mode (`ai.mode = auto`), but how far it may go depends on `mode`: `observe` only warns (the opinion is shown), `learning` suggests (the opinion rides on the pending item and the user decides), `enforce` executes the decision within the gates below.

All of the following must hold, otherwise the item goes to the user:

1. No hard rule fired and no HA/SG constraint conflicts.
2. `confidence ≥ auto_threshold` (default **0.90**); for `allow` additionally the rule score ≥ 40, or confidence ≥ **0.95** when the score is lower (a weak score alone, such as an unsigned developer tool, is what the advisor judges; a fired hard rule is gate 1 and always wins).
3. Opinion `recommended_action ∈ {allow, block}`. `kill` is **never** applied automatically by default.
4. Optional `ai.auto_kill = true` (default false): kill only if `verdict = malicious`, `confidence ≥ 0.95`, rule score ≤ 49, and the identity is not in the never-kill set.
5. Not within the first 24 h of `learning` mode (avoid training the system on its own guesses).
6. The same identity has not flipped between allow/block more than once in 7 days (stability).

Auto decisions use scope `24h` for `allow` and `forever` for `block`, are shown in the audit log with the model's reasons, and the user can revoke them in one click (`decision.revoke`).

## 5. Prompt design

### System prompt (stored in `crates/vigil-ai/src/prompt/system.txt`)

The file is the single source of truth (it is embedded with `include_str!` and mirrored to `proxy/src/spec.json`, gated by `proxy_spec`). It instructs the model to work through ordered checks and then decide:

1. Identity (signature, publisher, issuer vs version info and image name).
2. Location (expected install path vs user-writable folder).
3. Lineage (parent chain).
4. Destination (class, DNS, port).
5. Behaviour (beaconing, bursts, LOLBins to public hosts).
6. Known software (`known_software`, evidence only; supports a benign reading only when Location and Identity also agree, otherwise it is impersonation).
7. Rule signals (score and ids the model may agree or disagree with).

Output is only the `submit_verdict` tool call; `indicators` must be ids present in `rule_result.signals`.

### User message template

```
<untrusted_telemetry>
{redacted JSON payload}
</untrusted_telemetry>
Assess this executable and call submit_verdict.
```

### Tool schema
`schemas/ai-verdict.schema.json`: `verdict` (`safe|unknown|malicious`), `confidence` (0–1), `recommended_action` (`allow|block|ask_user|kill`), `reasons` (1–6 strings ≤ 200 chars), `indicators` (signal ids the model relied on, ≤ 10, pattern `^[A-Z]{3}-[0-9]{3}$`).

## 6. Prompt-injection and abuse defences

- Untrusted strings are JSON-encoded (no raw interpolation) and wrapped in a single delimiter block; the delimiter string is rejected inside values (replaced).
- Output validated against the schema; any deviation → discard, count `ai_invalid_output`, fall back to Pending.
- `indicators` must be a subset of signals actually present or `ai`-eligible ids; mismatches lower confidence by 0.2.
- Policy decision table never reads AI text, only `verdict/confidence/recommended_action`.
- Rate limits and budgets stop a malicious process from burning the user's API credits by spawning variants: calls are cached per identity, and unseen-identity calls are capped per minute (default 10).
- The AI never sees secrets; the service never executes anything the AI returns.

## 7. Cache

Key: `sha256(identity_key + rule_pack_version + dest_class + model)`; TTL 7 days for `safe`/`malicious` opinions, 24 h for `unknown`. Invalidate when rule pack, trust list, or signature status changes. Stored in `ai_cache` (see `schemas/db.sql`).

## 8. Key management

- Entered in UI → `ai.config.set` → service encrypts with DPAPI (`CryptProtectData`, `CRYPTPROTECT_LOCAL_MACHINE`, per-install random entropy kept in the same ACL'd directory) → stored as BLOB in `settings`. Decrypted into a `SecretString` only for the request.
- `has_key` boolean is the only thing returned. "Remove key" zeroizes and deletes.
- Error messages from the API never include the key; request logging is disabled for this client.

## 9. Evaluation harness (M5 acceptance)

`crates/vigil-ai/tests/golden/` holds ≥ 60 synthetic cases (benign enterprise software, LOLBin abuse, masquerade, beaconing, injected instructions inside process names/paths). A manual-run test (`cargo test -p vigil-ai --features live --test golden -- --ignored --nocapture`, key from `ANTHROPIC_API_KEY` only; skipped when unset) calls the live API and fails on any malicious case judged safe, any injected case judged safe, or overall agreement below 80%. The set has 65 cases (`tests/golden/cases.json`, generated from the categories above); an offline integrity test checks size, class balance and absence of key material. Offline service tests use a stub server.

**Verification status.** The model IDs and request parameters (`anthropic-version`, forced `tool_choice`, `max_tokens`) are implemented as configuration and exercised only against the stub server. They have **not** been checked against the live API in this repository; run the live harness once before release and record the result here.

## 10. Data-protection note (ISO/IEC 27001 A.5.23, ISO/IEC 27701)

AI use is a cloud-service data transfer. The settings page links to the redaction contract, is opt-out in builds that embed `VIGIL_PROXY_URL` (AI on, source `shared`, data categories pre-acknowledged and shown in Settings) and opt-in (`off`, acknowledgement required) in builds without it; it and writes an audit record whenever AI settings change.

## 11. Shared endpoint (optional)

Builds with `VIGIL_PROXY_URL` offer `source = "shared"`: the service registers once (`/v1/register`), seals the returned install token with DPAPI like an API key, and sends `{tier, payload}` to `/v1/assess`. The payload is the same redacted object as direct calls; the endpoint (`proxy/`) builds the system prompt, forced tool, model and `max_tokens` itself, and `proxy/src/spec.json` is gated against the client by `cargo test -p vigil-ai --test proxy_spec`. Quotas (per install, per IP at registration, global daily) and a kill switch bound the cost. Default quotas: 20 calls/minute and 400/day per install (a deep call counts 2), 20,000/day overall; the client stays below them (16/minute) and pauses 5 minutes after a 429 so the advisor degrades quietly instead of hammering the endpoint. A score alone (for example an unsigned dev tool in a user folder) never cuts a program off the network: only a hard rule does; everything else is reviewed by the advisor and waits in the list. Limit: the endpoint cannot cryptographically prove the caller is the genuine app, so it restricts the *shape* and *volume* of what a caller can do with the key. Authority order is unchanged: hard rules still beat the AI verdict.

## 12. Usage ledger, daily digest and proactive assessment

- Every assessment, cache hit, token count (as reported by the API) and automatic decision is tallied per day in the settings key `ai.usage` (62 days kept). `ai.activity` returns today / 7 days / 30 days; the dollar figure is an estimate at Haiku-class rates. The shared endpoint reports calls only.
- At most once every 24 h, and only if the AI did something, the service emits `event.ai_digest` (topic `ai`); the UI shows it as a system notification and the Overview card shows the same numbers live.
- The default mode is `auto`, but in builds without `VIGIL_PROXY_URL` nothing runs until the admin enables AI and acknowledges the data categories (§10); proxy builds ship with AI on. `auto_kill` stays off.
- New Unknown programs are assessed proactively (never decided) using at most half of `daily_call_budget`; Malicious findings are always assessed first and, if the AI is unavailable, left to the user as a pending item.
