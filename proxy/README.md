# Vigil AI endpoint

A small Cloudflare Worker that lets Vigil users get a Claude second opinion **without their own API key**. The maintainer's key lives only here (Worker secret); the app holds a signed per-install token.

## What it will and will not do

- Accepts only Vigil's redacted telemetry object (`image_name`, `path`, `sha256`, `signature`, `version_info`, `parent_chain`, `destination`, `behaviour`, `rule_result`, `command_line`), size- and depth-capped.
- Builds the system prompt, forced `submit_verdict` tool, model (`fast` = Haiku, `deep` = Sonnet) and `max_tokens` itself. A caller cannot choose any of them, so the key is not a general-purpose Claude proxy.
- Returns only `{model, verdict}`. Upstream errors become a generic 503.
- Quotas (strongly consistent, one Durable Object): per install per minute/day, global calls/day, registrations per IP/day and globally. `DISABLED=1` stops everything.

**Honest limit:** anyone can extract the public URL and register a token, and can then send telemetry-shaped requests. The design makes that useless for anything but Vigil-style verdicts and caps the cost; it cannot prove the caller is the genuine app. Treat the key as a bounded, revocable donation.

## Deploy

Two equivalent options; pick one. Both use the same handler (`src/handler.js`).

### A. Self-hosted on your own machine (Node ≥ 20, no cloud account)

```
cd proxy
ANTHROPIC_API_KEY=… TOKEN_SECRET=<24+ random chars> npm start   # listens on 127.0.0.1:8787
```

Quotas persist in `quota.json` (override with `QUOTA_FILE`). The server speaks plain HTTP on loopback; expose it over HTTPS with a tunnel or reverse proxy (the app refuses non-https URLs) and set `TRUST_PROXY=1` only when such a proxy supplies `X-Forwarded-For`. Set `PORT`/`HOST` as needed. Keep the secrets in your shell or a launchd `EnvironmentVariables` entry, never in the repo.

### B. Cloudflare Workers

```
cd proxy
wrangler secret put ANTHROPIC_API_KEY   # key from a dedicated Console workspace with a spend limit
wrangler secret put TOKEN_SECRET        # long random string
wrangler deploy
```

Build releases with `VIGIL_PROXY_URL=https://<your-worker>` to enable the "shared" option in the app.

- Put the key in its own Console **workspace** with a monthly spend limit equal to the free credit you are willing to spend, so a leak cannot touch other balances. Check that your key's terms allow this use.
- Rotate `TOKEN_SECRET` to invalidate every issued token. Rotate the API key from the Console.

## Develop

`npm test` runs the pure-logic tests. `proxy/src/spec.json` is generated from the Rust client and gated by `cargo test -p vigil-ai --test proxy_spec`; regenerate with `VIGIL_WRITE_SPEC=1`.
