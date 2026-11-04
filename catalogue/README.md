# vigil-catalogue

Cloudflare Worker that builds the signed version snapshot described in `docs/16-version-freshness.md`.

- `products.json` maps catalogue labels (as in `rules/known_software.toml`) to winget ids; `overrides.json` holds curated `min_supported` / `vulnerable_below`.
- Daily cron (`wrangler.toml`) reads `microsoft/winget-pkgs`, signs `{v, issued, products}` with Ed25519 and stores `{kid, payload, sig}` in KV. A run where fewer than half of the products resolve keeps the last good snapshot.
- `GET /v1/catalogue` serves it; `POST /v1/refresh` (Bearer `REFRESH_TOKEN`) forces a rebuild.

Secrets (`wrangler secret put`): `SNAPSHOT_SIGNING_KEY` (PKCS#8 base64), `REFRESH_TOKEN`, optional `GITHUB_TOKEN`.

Key rotation: add the new public key to `rules/catalogue_keys.toml` under a new `kid`, ship a release, then switch the Worker's `kid`/secret. Keep the old key until clients have updated.

Tests: `node --test` in this directory.
