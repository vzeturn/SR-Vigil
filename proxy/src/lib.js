// Pure helpers for the Vigil AI endpoint. No I/O here so they can be unit-tested with node:test.

const ALLOWED_KEYS = new Set([
  'image_name',
  'path',
  'sha256',
  'signature',
  'version_info',
  'parent_chain',
  'destination',
  'behaviour',
  'rule_result',
  'known_software',
  'command_line',
]);
export const MAX_PAYLOAD_BYTES = 12_000;
const MAX_STRING = 400;
const MAX_DEPTH = 5;
const MAX_NODES = 400;

/** Returns an error code for a payload that is not a Vigil telemetry object, else null. */
export function payloadError(p) {
  if (p === null || typeof p !== 'object' || Array.isArray(p)) return 'shape';
  const keys = Object.keys(p);
  if (!keys.every((k) => ALLOWED_KEYS.has(k))) return 'keys';
  if (typeof p.image_name !== 'string' || typeof p.rule_result !== 'object' || p.rule_result === null) {
    return 'required';
  }
  if (new TextEncoder().encode(JSON.stringify(p)).length > MAX_PAYLOAD_BYTES) return 'size';
  let nodes = 0;
  const walk = (v, depth) => {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) return false;
    if (typeof v === 'string') return v.length <= MAX_STRING;
    if (v === null || typeof v === 'number' || typeof v === 'boolean') return true;
    if (Array.isArray(v)) return v.every((x) => walk(x, depth + 1));
    if (typeof v === 'object') return Object.values(v).every((x) => walk(x, depth + 1));
    return false;
  };
  return walk(p, 0) ? null : 'content';
}

const enc = new TextEncoder();
const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

/** `v1.<install id>.<signature>`; the id is the quota identity. */
export async function issueToken(secret) {
  const id = b64url(crypto.getRandomValues(new Uint8Array(16)));
  return `v1.${id}.${await hmac(secret, id)}`;
}

/** Returns the install id for a genuine token, else null. */
export async function verifyToken(secret, token) {
  const [v, id, sig, extra] = String(token ?? '').split('.');
  if (v !== 'v1' || !id || !sig || extra !== undefined) return null;
  const want = await hmac(secret, id);
  if (want.length !== sig.length) return null;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= want.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0 ? id : null;
}

/** The only request this endpoint ever sends upstream. Prompt, tool and limits are fixed here. */
export function upstreamBody(spec, model, payload) {
  return {
    model,
    max_tokens: 500,
    system: spec.system,
    tools: [{ name: spec.tool, description: 'Submit the verdict for this executable.', input_schema: spec.tool_schema }],
    tool_choice: { type: 'tool', name: spec.tool },
    messages: [{ role: 'user', content: spec.user_template.replace('{payload}', () => JSON.stringify(payload)) }],
  };
}
