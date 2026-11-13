// Operator tool: sign a rule pack and print the envelope to store under the KV key `rulepack`.
// Usage: SNAPSHOT_SIGNING_KEY=<pkcs8 base64> [SNAPSHOT_KID=k1] node sign-rulepack.js pack.toml > rulepack.json
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { rulepackPayload } from './src/rulepack.js';
import { sign } from './src/sign.js';

globalThis.crypto ??= webcrypto;

const [file] = process.argv.slice(2);
const key = process.env.SNAPSHOT_SIGNING_KEY;
if (!file || !key) {
  console.error('usage: SNAPSHOT_SIGNING_KEY=<pkcs8 base64> node sign-rulepack.js <pack.toml>');
  process.exit(2);
}
const payload = rulepackPayload(readFileSync(file, 'utf8'), Date.now());
process.stdout.write(JSON.stringify(await sign(payload, key, process.env.SNAPSHOT_KID ?? 'k1')));
