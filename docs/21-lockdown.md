# 21 - Lockdown

On demand, Vigil stops every untrusted background program and keeps it from running again for a fixed window (default 5 minutes, 1-30). A program that keeps coming back is put to the advisor, which says what it is and whether the cause deserves an investigation.

## Scope

- Method names: `purge.start {minutes?}` (Admin), `purge.stop` (Admin), `purge.status` (Viewer). Events: `event.purge`.
- The hold is in memory only. It ends by itself, and a crashed or restarted service never leaves the machine locked.
- No file, registry key, task or service is deleted or changed. No permanent rule is written.

## What is left running

`spare_reason` returns the first match, in this order: Vigil's own binaries (`self`), the never-kill set (`never_kill`), processes not yet classified (`unclassified`), verdict Safe (`safe`), identities the user allowed (`allowed`), programs the user started (`user`). Everything else is stopped through `ProcessControl::terminate`. A protected process is reported and not retried (rule 5).

## Hold and escalation

- The observer tick calls `purge_scan`. A held image that starts again is stopped again and counted as a comeback; its parent is recorded.
- At 3 comebacks the program is flagged `persistent` and `purge_review` asks the advisor through the normal `ai_assess` path (same privacy, mode and gating rules as `docs/06`). The opinion is shown; it never acts by itself.
- The UI offers two follow-ups per program: "Trace the cause" (read-only `persistence.scan` for the image) and "Block for good" (an ordinary `decision.submit`, scope `forever`, so the usual audit and confirmation apply).

## Audit

Every stop writes an audit row (`kill`, phase `purge`, actor). Start and release are audited too.

## UI

Lockdown page: countdown ring, four counters (stopped, held off, persistent, kept running), the per-program list with verdict, score, publisher, parent, comeback meter and advisor opinion, and the list of what was left running and why.
