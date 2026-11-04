// Runtime-neutral request handler: Cloudflare Worker and the self-hosted Node server both use it.
import { issueToken, payloadError, upstreamBody, verifyToken } from './lib.js';

const DAY = 86_400;
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);

async function register(req, env, take) {
  const ip = req.headers.get('cf-connecting-ip') ?? 'unknown';
  const ok = await take([
    { key: `reg-ip:${ip}`, limit: num(env.REGISTER_PER_IP_DAY, 5), windowSec: DAY, cost: 1 },
    { key: 'reg-all', limit: num(env.REGISTER_GLOBAL_DAY, 2000), windowSec: DAY, cost: 1 },
  ]);
  return ok ? json({ token: await issueToken(env.TOKEN_SECRET) }) : json({ error: 'rate_limited' }, 429);
}

async function assess(req, env, take, spec) {
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
  const admitted = await take([
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

/** `take(rules)` resolves true when every quota rule admits the call (and records it). */
export async function handle(req, env, take, spec) {
  if (env.DISABLED === '1') return json({ error: 'disabled' }, 503);
  if (req.method !== 'POST') return json({ error: 'not_found' }, 404);
  const { pathname } = new URL(req.url);
  if (pathname === '/v1/register') return register(req, env, take);
  if (pathname === '/v1/assess') return assess(req, env, take, spec);
  return json({ error: 'not_found' }, 404);
}

/** Fixed-window counters over a get/set store (sync or async). Values are `[count, expiresAt]`. */
export async function takeFrom(store, rules, now = Math.floor(Date.now() / 1000)) {
  const next = [];
  for (const r of rules) {
    const slot = Math.floor(now / r.windowSec);
    const k = `${r.key}:${slot}`;
    const [used] = (await store.get(k)) ?? [0];
    if (used + r.cost > r.limit) return false;
    next.push([k, [used + r.cost, (slot + 1) * r.windowSec]]);
  }
  for (const [k, v] of next) await store.set(k, v);
  return true;
}
