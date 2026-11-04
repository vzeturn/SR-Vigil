import products from '../products.json';
import overrides from '../overrides.json';
import { buildSnapshot } from './build.js';
import { sign } from './sign.js';

const KEY = 'snapshot';

async function refresh(env) {
  // Returns the number of products published, or 0 when the run was skipped.
  const { snapshot, failed } = await buildSnapshot({
    products,
    overrides,
    fetcher: fetch,
    token: env.GITHUB_TOKEN,
    now: Date.now(),
  });
  // Never publish a snapshot that lost most products to errors: keep serving the last good one.
  if (Object.keys(snapshot.products).length < Math.ceil(Object.keys(products).length / 2)) {
    console.log(JSON.stringify({ event: 'refresh_skipped', failed }));
    return 0;
  }
  const envelope = await sign(snapshot, env.SNAPSHOT_SIGNING_KEY, env.SNAPSHOT_KID ?? 'k1');
  await env.CATALOGUE.put(KEY, JSON.stringify(envelope));
  console.log(JSON.stringify({ event: 'refresh_ok', products: Object.keys(snapshot.products).length, failed }));
  return Object.keys(snapshot.products).length;
}

/** Constant-time string comparison for the operator token. */
function same(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return d === 0;
}

export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(refresh(env));
  },
  async fetch(req, env) {
    const { pathname } = new URL(req.url);
    if (req.method === 'POST' && pathname === '/v1/refresh') {
      const token = (req.headers.get('authorization') ?? '').replace(/^Bearer /, '');
      if (!env.REFRESH_TOKEN || !same(token, env.REFRESH_TOKEN)) return new Response('unauthorized', { status: 401 });
      const n = await refresh(env);
      return new Response(JSON.stringify({ products: n }), { headers: { 'content-type': 'application/json' } });
    }
    if (req.method !== 'GET' || pathname !== '/v1/catalogue') return new Response('not found', { status: 404 });
    const body = await env.CATALOGUE.get(KEY);
    if (!body) return new Response('{"error":"not_ready"}', { status: 503, headers: { 'content-type': 'application/json' } });
    return new Response(body, {
      headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' },
    });
  },
};
