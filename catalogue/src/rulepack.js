/** Largest rule-pack TOML the publisher accepts; the client caps the whole envelope at 256 KiB. */
export const MAX_PACK = 128 * 1024;

/**
 * Payload of a signed rule pack (`docs/03 §8.1`). The `type` tag keeps it from ever being read as
 * a catalogue snapshot. The client re-checks every rule: only new score-lowering signals pass.
 */
export function rulepackPayload(packToml, now) {
  if (typeof packToml !== 'string' || packToml.length === 0 || packToml.length > MAX_PACK) {
    throw new Error(`rule pack must be 1..${MAX_PACK} characters of TOML`);
  }
  return { v: 1, type: 'rulepack', issued: new Date(now).toISOString(), pack: packToml };
}

/** KV key served for a public GET, or null for anything else (only these two documents exist). */
export function servedKey(method, pathname) {
  if (method !== 'GET') return null;
  return { '/v1/catalogue': 'snapshot', '/v1/rulepack': 'rulepack' }[pathname] ?? null;
}
