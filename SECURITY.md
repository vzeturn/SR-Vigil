# Security Policy

Vigil is pre-1.0. Only the latest commit on `main` receives fixes.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") on this repository. Include the affected component, reproduction steps and impact. You can expect an acknowledgement within 7 days.

## Scope

In scope: privilege escalation through the service or control pipe, bypass of the never-kill guard or hard rules, API-key exposure, injection through untrusted host strings (SQL, shell, AI prompt), audit-log tampering.

Out of scope: attacks requiring prior administrator or SYSTEM compromise, and denial of service by a user who already controls the machine.

## If you contributed a secret by mistake

Rotate it immediately, then tell the maintainers so the history can be cleaned.
