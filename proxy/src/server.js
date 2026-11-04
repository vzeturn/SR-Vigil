// Self-hosted Vigil AI endpoint (Node >= 20): same logic as the Cloudflare Worker, quotas kept in a
// local JSON file. Run it behind a tunnel/reverse proxy that provides HTTPS. See proxy/README.md.
import { createServer } from 'node:http';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { handle, takeFrom } from './handler.js';

const env = process.env;
for (const k of ['ANTHROPIC_API_KEY', 'TOKEN_SECRET']) {
  if (!env[k]) {
    console.error(`${k} must be set`);
    process.exit(1);
  }
}
if (env.TOKEN_SECRET.length < 24) {
  console.error('TOKEN_SECRET must be at least 24 characters');
  process.exit(1);
}
const spec = JSON.parse(readFileSync(new URL('./spec.json', import.meta.url), 'utf8'));
const file = env.QUOTA_FILE ?? 'quota.json';
const data = new Map(existsSync(file) ? Object.entries(JSON.parse(readFileSync(file, 'utf8'))) : []);
const store = { get: (k) => data.get(k), set: (k, v) => data.set(k, v) };
let queue = Promise.resolve(); // serialise quota checks so concurrent calls cannot overshoot a cap

const persist = () => {
  const now = Math.floor(Date.now() / 1000);
  for (const [k, [, exp]] of data) if (exp < now) data.delete(k);
  writeFileSync(`${file}.tmp`, JSON.stringify(Object.fromEntries(data)));
  renameSync(`${file}.tmp`, file);
};
const take = (rules) => {
  const run = queue.then(async () => {
    const ok = await takeFrom(store, rules);
    if (ok) persist();
    return ok;
  });
  queue = run.catch(() => undefined);
  return run;
};

createServer(async (req, res) => {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 16_000) {
      res.writeHead(413).end();
      return;
    }
    chunks.push(c);
  }
  // Trust the socket address, or a forwarded header only when explicitly told a proxy is in front.
  const ip = (env.TRUST_PROXY === '1' && req.headers['x-forwarded-for']?.split(',')[0].trim()) || req.socket.remoteAddress;
  const headers = { ...req.headers, 'cf-connecting-ip': ip ?? 'unknown' };
  const request = new Request(`http://localhost${req.url}`, {
    method: req.method,
    headers,
    body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks),
  });
  const out = await handle(request, env, take, spec).catch(() => new Response('{"error":"internal"}', { status: 500 }));
  res.writeHead(out.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(await out.text());
}).listen(Number(env.PORT ?? 8787), env.HOST ?? '127.0.0.1', () => console.log('vigil-ai listening'));
