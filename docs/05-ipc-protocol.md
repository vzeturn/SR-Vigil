# 05 — IPC protocol (service ↔ UI/CLI)

**Tóm tắt (VI):** Named pipe `\\.\pipe\vigil-control`, khung `u32 LE length + JSON`, kiểu JSON-RPC 2.0, protocol version `1`. Vai trò (`admin`/`viewer`) xác định bằng token của client. Schema chuẩn: `schemas/ipc.schema.json`.

## 1. Transport

- Named pipe `\\.\pipe\vigil-control`, `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE`, overlapped I/O, `PIPE_REJECT_REMOTE_CLIENTS`, first-instance flag set to prevent pipe squatting (`FILE_FLAG_FIRST_PIPE_INSTANCE`).
- DACL: `SYSTEM` full, `Administrators` full, `Authenticated Users` connect-only (viewer). No `Everyone`, no network.
- Framing: 4-byte little-endian unsigned length (max **1 MiB**, larger → close) followed by UTF-8 JSON.
- One request/response channel per connection plus server-initiated notifications on the same connection after `subscribe`.
- Heartbeat: server sends `event.health` at least every 15 s; client closes and reconnects if silent for 45 s.

## 2. Authentication and roles

After connect the server calls `GetNamedPipeClientProcessId`, opens the client process token, reads its elevation (`TokenElevation`) and assigns the role (any error resolves to `viewer`):

| Role | Condition | Allowed |
|---|---|---|
| `admin` | client process token is elevated | all methods |
| `viewer` | other authenticated users | every method marked **R** in §4 (read, list, query, subscribe); mutating methods return `-32001`, unless `allow_standard_user_decisions = true` permits `decision.submit` |

The server also records the client image path and signer in the audit log on connect and refuses connections from images not signed by the Vigil self-pin when `strict_client = true` (default `false` in dev, `true` in release builds).

## 3. Envelope

JSON-RPC 2.0 subset: `{"jsonrpc":"2.0","id":<int|string>,"method":"...","params":{...}}` → `{"jsonrpc":"2.0","id":...,"result":{...}}` or `{"error":{"code":-32xxx,"message":"...","data":{...}}}`. Notifications omit `id`. Unknown fields are ignored; unknown methods → `-32601`.

### Error codes

| Code | Name | Meaning |
|---|---|---|
| -32700 / -32600 / -32601 / -32602 / -32603 | JSON-RPC standard | parse, invalid request, method not found, invalid params, internal |
| -32001 | `unauthorized` | role lacks permission |
| -32002 | `invalid_state` | e.g. arming enforce before bootstrap check passes |
| -32003 | `not_found` | unknown id |
| -32004 | `conflict` | stale `pending_id` or already resolved |
| -32005 | `rate_limited` | too many requests |
| -32006 | `ai_unavailable` | AI disabled, no key, budget exhausted or upstream error |
| -32007 | `protected_target` | never-kill/PPL target |
| -32008 | `enforcement_off` | action needs `enforce` mode |

## 4. Methods

`params`/`result` types are in `schemas/ipc.schema.json` (`$defs`). **R** = viewer allowed, **A** = admin only.

| Method | Role | Params → Result |
|---|---|---|
| `hello` | R | `{client, client_version, protocol}` → `{protocol, service_version, role, mode, health}` |
| `status.get` | R | `{}` → `Status` (mode, health, counts, rule_pack_version, ai state, learning_started_at) |
| `mode.set` | A | `{mode, override_learning_minimum?}` → `Status` |
| `process.list` | R | `{filter?, cursor?, limit?}` → `{items: ProcessInfo[], next_cursor?}` |
| `process.get` | R | `{pid, start_time}` → `ProcessDetail` (evaluation, parent chain, connections, hosted services) |
| `process.kill` | A | `{pid, start_time, tree?, block?: bool}` → `ActionResult` |
| `connection.list` | R | `{filter?, cursor?, limit?}` → `{items: ConnectionInfo[], next_cursor?}` |
| `pending.list` | R | `{}` → `{items: PendingItem[]}` |
| `decision.submit` | A | `{pending_id?, identity_id?, action, scope, apply_to, note?}` → `DecisionResult` |
| `decision.list` | R | `{}` → `{items: Decision[]}` |
| `decision.revoke` | A | `{decision_id}` → `{}` |
| `identity.get` | R | `{identity_id}` → `IdentityDetail` (signals, history) |
| `rule.list` | R | `{}` → `{rule_pack_version, rules: Rule[]}` |
| `rule.upsert` | A | `{rule}` → `Rule` (written as override; validated) |
| `rule.delete` | A | `{rule_id}` → `{}` (override only) |
| `trust.list` | R | `{}` → `{publishers: TrustedPublisher[]}` |
| `trust.pin` | A | `{signer_thumbprint, subject_org, note?}` → `TrustedPublisher` |
| `trust.revoke` | A | `{publisher_id}` → `{}` |
| `persistence.scan` | A | `{target_image_path?}` → `{findings: PersistenceItem[]}` |
| `persistence.apply` | A | `{item_id, action: "disable"|"restore"|"delete"}` → `ActionResult` |
| `ai.config.get` | R | `{}` → `{enabled, mode, model, escalation_model, thresholds, has_key, budget}` (never the key) |
| `ai.config.set` | A | `{enabled?, mode?, model?, escalation_model?, api_key?, thresholds?, budget?}` → `AiConfig` |
| `ai.test` | A | `{}` → `{ok, latency_ms, model}` |
| `ai.explain` | A | `{identity_id}` → `AiOpinion` (forces a fresh opinion, shows in UI) |
| `audit.query` | R | `{since?, until?, kind?, cursor?, limit?}` → `{items: AuditEntry[], next_cursor?, chain_ok}` |
| `audit.export` | A | `{format: "json"|"csv", since?, until?}` → `{path}` (written under `%ProgramData%\Vigil\exports`) |
| `settings.get` / `settings.set` | R / A | policy settings (see `config/default-policy.toml`) |
| `enforcement.panic` | A | `{}` → `Status` |
| `subscribe` | R | `{topics: Topic[]}` → `{subscribed: Topic[]}` |
| `unsubscribe` | R | `{topics}` → `{}` |

`ai.config.set` accepts `api_key` write-only; after storing (DPAPI) the key is zeroized in the request buffer.

### Topics and notifications

| Topic | Notification | Payload |
|---|---|---|
| `processes` | `event.process_started`, `event.process_exited` | `ProcessInfo` / `{pid, start_time, exit_time}` |
| `connections` | `event.connection_opened`, `event.connection_closed` | `ConnectionInfo` |
| `verdicts` | `event.verdict_changed` | `{identity_id, old, new, score, signals[]}` |
| `pending` | `event.pending_created`, `event.pending_resolved` | `PendingItem` / `{pending_id, action, by}` |
| `enforcement` | `event.enforcement_changed` | `{mode, filters_armed, reason}` |
| `alerts` | `event.alert` | `{severity, kind, message_key, identity_id?, data}` |
| `health` | `event.health` | `{state, details, ts}` |

Notifications for the `processes` and `connections` topics are **batched** into a single `event.batch` notification, `{"method":"event.batch","params":{"events":[{"method":"event.process_started","params":{...}}, ...]}}`, flushed every 100 ms or 200 items, whichever comes first (NFR-005). Other topics are sent individually.

## 5. Data types (summary)

`schemas/ipc.schema.json` is authoritative. Key shapes:

- `Identity`: `id`, `sha256`, `path`, `signer_thumbprint?`, `publisher?`, `company?`, `product?`, `signature_status`.
- `Evaluation`: `score`, `verdict`, `signals: Signal[]`, `hard_rule?`, `rule_pack_version`, `source` (`rules|ai|user|cache`), `evaluated_at`.
- `Signal`: `id`, `name`, `delta`, `detail?`.
- `PendingItem`: `id`, `identity`, `evaluation`, `process?`, `destination`, `ai_opinion?`, `created_at`.
- `Decision`: `id`, `identity_id`, `action`, `scope`, `apply_to`, `expires_at?`, `by` (`user|ai|rule`), `note?`.

## 6. Tauri bridge contract

- The Tauri Rust side keeps one admin or viewer connection, reconnecting with exponential backoff (250 ms → 5 s).
- Commands exposed to JS: one `invoke` per IPC method with identical names (`ipc_status_get`, …); events forwarded as Tauri events `vigil://<topic>`; payloads typed by generated TypeScript (`json-schema-to-typescript` from `schemas/ipc.schema.json` during `pnpm gen`).
- The bridge adds no business logic and never persists data; the API key only flows UI → bridge → service on `ai.config.set` and is zeroized after sending.

## 7. Compatibility rules

- Additive changes (new optional fields, new methods/events) do not bump `protocol`.
- Removing/renaming/retyping bumps `protocol`; the server supports `N` and `N-1` for one minor release.
- Contract tests in `vigil-ipc` validate golden payloads for every method and event against the schema.


## Implementation notes (v1)

- `process.get` requires both `pid` and `start_time`; it returns `invalid_state` until the process has been evaluated once.
- After the first evaluation of a process the service re-emits `event.process_started` as an upsert; `event.verdict_changed` fires only when a previous verdict existed and differs.
- `event.connection_closed` carries `{id, last_seen}` only.
