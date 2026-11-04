// Vigil AI endpoint (Cloudflare Worker). Holds the Anthropic key; clients only get a signed install
// token. It accepts nothing but Vigil's redacted telemetry object, so the key cannot be used as a
// general-purpose Claude proxy. See proxy/README.md for the threat model and limits.
import spec from './spec.json';
import { issueToken, payloadError, upstreamBody, verifyToken } from './lib.js';

const DAY = 86_400;
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);

/** One global instance: strongly consistent counters, so caps hold under concurrency. */
export class Quota {
  constructor(state) {
    this.state = state;
  }
  async fetch(req) {
    const { rules } = await req.json(); // [{ key, limit, windowSec, cost }]
    const now = Math.floor(Date.now() / 1000);
    const cells = [];
    for (const r of rules) {
      const slot = Math.floor(now / r.windowSec);
      const k = `${r.key}:${slot}`;
      const used = (await this.state.storage.get(k)) ?? 0;
      if (used + r.cost > r.limit) return json({ ok: false, key: r.key });
      cells.push([k, used + r.cost, r.windowSec]);
    }
    for (const [k, v] of cells) await this.state.storage.put(k, v);
    // Old windows are useless; drop anything not from the current day's keys.
    if (Math.random() < 0.02) await this.sweep(now);
    return json({ ok: true });
  }
  async sweep(now) {
    const all = await this.state.storage.list();
    for (const k of all.keys()) {
      const slot = Number(k.split(':').pop());
      if (Number.isFinite(slot) && slot < Math.floor(now / DAY) - 2 && slot < 1e6) await this.state.storage.delete(k);
    }
  }
}

async function take(env, rules) {
  const stub = env.QUOTA.get(env.QUOTA.idFromName('global'));
  const r = await stub.fetch('https://quota/take', { method: 'POST', body: JSON.stringify({ rules }) });
  return (await r.json()).ok;
}

async function register(req, env) {
  const ip = req.headers.get('cf-connecting-ip') ?? 'unknown';
  const ok = await take(env, [
    { key: `reg-ip:${ip}`, limit: num(env.REGISTER_PER_IP_DAY, 5), windowSec: DAY, cost: 1 },
    { key: 'reg-all', limit: num(env.REGISTER_GLOBAL_DAY, 2000), windowSec: DAY, cost: 1 },
  ]);
  return ok ? json({ token: await issueToken(env.TOKEN_SECRET) }) : json({ error: 'rate_limited' }, 429);
}

async function assess(req, env) {
  const id = await verifyToken(env.TOKEN_SECRET, (req.headers.get('authorization') ?? '').replace(/^Bearer /, ''));
  if (!id) return json({ error: 'unauthorized' }, 401);
  if (num(req.headers.get('content-length'), 0) > 16_000) return json({ error: 'too_large' }, 413);
  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: 'bad_json' }, 400);
  }
  const tier = body?.tier === 'deep' ? 'deep' : 'fast';
  const bad = payloadError(body?.payload);
  if (bad) return json({ error: 'bad_payload', why: bad }, 400);

  const cost = tier === 'deep' ? 2 : 1;
  const admitted = await take(env, [
    { key: `min:${id}`, limit: num(env.PER_INSTALL_MINUTE, 6), windowSec: 60, cost },
    { key: `day:${id}`, limit: num(env.PER_INSTALL_DAY, 60), windowSec: DAY, cost },
    { key: 'calls-all', limit: num(env.GLOBAL_CALLS_DAY, 4000), windowSec: DAY, cost },
  ]);
  if (!admitted) return json({ error: 'rate_limited' }, 429);

  const model = tier === 'deep' ? (env.MODEL_DEEP ?? 'claude-sonnet-5-5') : (env.MODEL_FAST ?? 'claude-haiku-5-5');
  const up = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify(upstreamBody(spec, model, body.payload)),
  });
  // Upstream detail (billing, key state) never reaches clients.
  if (!up.ok) return json({ error: 'upstream_unavailable' }, 503);
  const out = await up.json();
  const tool = (out.content ?? []).find((b) => b.type === 'tool_use' && b.name === spec.tool);
  if (!tool) return json({ error: 'upstream_invalid' }, 502);
  return json({ model, verdict: tool.input });
}

export default {
  async fetch(req, env) {
    if (env.DISABLED === '1') return json({ error: 'disabled' }, 503);
    if (req.method !== 'POST') return json({ error: 'not_found' }, 404);
    const { pathname } = new URL(req.url);
    if (pathname === '/v1/register') return register(req, env);
    if (pathname === '/v1/assess') return assess(req, env);
    return json({ error: 'not_found' }, 404);
  },
};
