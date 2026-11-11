# 24 — Suspicious network behaviour

**Tóm tắt (VI):** Phát hiện chương trình "gọi về nhà" đều đặn (beaconing) chỉ từ siêu dữ liệu kết nối, không bao giờ đọc nội dung lưu lượng; hỏi người dùng trước khi gửi bất cứ điều gì về hành vi đó cho AI.

## 1. Goal

Catch a backdoor or trojan that hides by splitting its traffic into small, regular calls to one server, and do it without reading anyone's data. Vigil looks at *when* and *where* a program connects, never at *what* it sends.

## 2. Why not decrypt traffic

A "VPN-style" gateway that decrypts HTTPS would need Vigil to install its own root certificate and re-sign every site. That is rejected:

- A local interception root is a single key that, if stolen, lets an attacker impersonate every site to the user. US-CERT alert TA17-075A documents how interception products weaken TLS (broken validation, downgraded ciphers, hidden certificate errors).
- Certificate pinning (banking apps, updaters, Windows Update, Vigil's own Anthropic client) breaks or silently bypasses the proxy.
- Transparent redirection of all flows needs a WFP callout driver, which non-negotiable #1 forbids.
- Reading content contradicts the user decision that Vigil must never read data on purpose (non-negotiable #6: host data stays data).

Metadata is enough for the pattern that matters: a malware heartbeat is regular in time even when its content is encrypted and fragmented.

## 3. How it works

1. Every new outbound connection to a public address (not loopback, private, link-local, multicast or unspecified) is recorded as one sample for the flow *(program path, remote IP, remote port)*. Connection rows come from the existing table poll; no packet is captured.
2. `vigil_core::analysis::beacon::BeaconTracker` keeps the samples of the last 30 min per flow, at most 4096 flows (the stalest is evicted, silent flows are forgotten). A flow is beaconing when it has at least 6 samples, a mean interval of at least 5 s and an interval coefficient of variation below 0.15 (`docs/03`, BEH-002). Each flow is reported once.
3. On the first report for a program in this run, the service:
   - marks the program so its next evaluation carries BEH-002 (−30) and queues it for re-evaluation;
   - writes an audit row (`verdict`, signal `BEH-002`, destination and interval);
   - unless the program's verdict is already `safe`, sends `event.threat_detected` (`docs/05`) and keeps the prompt in `threat.list` until it is answered.

A program verified as safe (signed, known) is only re-scored; it raises no prompt, because update checks and telemetry of trusted software are often periodic.

## 4. Consent before AI

Nothing about the network pattern reaches the AI advisor until the user answers the prompt with **Analyze**:

| Answer | Effect |
|---|---|
| `analyze` | records consent for that program for this run, then runs `ai.explain`; the payload then carries `behaviour.beaconing = true` and the destination (redacted per `docs/06 §3`). The prompt stays open so the user can still block or ignore. |
| `block` | submits a `block` / `forever` / `file` decision with a note; the normal decision path applies (hard rules and the never-kill set still win). |
| `dismiss` | closes the prompt; the program keeps its BEH-002 score. |

Without consent `ai_payload` reports `beaconing = false` and no destination, so a background AI assessment never learns about the pattern. Every answer is audited.

## 5. Limits

- Connections shorter than the poll interval (about 500 ms) can be missed; an ETW-based capture is tracked in `docs/10` backlog.
- Only regular intervals are detected. Jittered beacons (CV ≥ 0.15) and data hidden inside long-lived connections are out of scope.
- Detection state lives in memory and resets when the service restarts.
- TLS handshake metadata (SNI, JA4) is not inspected yet; tracked in `docs/10` backlog.
