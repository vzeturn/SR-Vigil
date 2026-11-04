---
description: Self-review the current changes against the Vigil review checklist
---

Review the working tree and the commits on this branch against `docs/12-handoff-prompts.md` §4 and the non-negotiables in `CLAUDE.md`.

Check specifically:
- `unsafe` appears only in `vigil-win`, each block has a `// SAFETY:` comment and a safe wrapper.
- Hard-rule precedence, never-kill set and fail-open behaviour are covered by tests.
- No secret (API key, token) is logged, returned over IPC, sent to the UI, or present in fixtures.
- Untrusted strings are never interpolated into commands, SQL, log formats, or AI instructions.
- New enforcement or configuration actions write audit entries.
- Docs, `schemas/`, and `rules/` changed in the same commit as any behaviour they describe.
- No placeholder text, no TODO without an entry in the backlog of `docs/10-roadmap-milestones.md`.

Report findings as a list ordered by severity with file and line references, then fix the ones that are clearly within scope and re-run fmt, clippy and tests.
