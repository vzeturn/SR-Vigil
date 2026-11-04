// Vigil AI endpoint on Cloudflare Workers. Holds the Anthropic key; clients only get a signed install
// token. See proxy/README.md for the threat model and limits.
import spec from './spec.json';
import { handle, takeFrom } from './handler.js';

/** One global instance: strongly consistent counters, so caps hold under concurrency. */
export class Quota {
  constructor(state) {
    this.state = state;
  }
  async fetch(req) {
    const { rules } = await req.json();
    const store = { get: (k) => this.state.storage.get(k), set: (k, v) => this.state.storage.put(k, v) };
    const ok = await takeFrom(store, rules);
    if (Math.random() < 0.02) await this.sweep();
    return new Response(JSON.stringify({ ok }), { headers: { 'content-type': 'application/json' } });
  }
  async sweep() {
    const now = Math.floor(Date.now() / 1000);
    for (const [k, [, exp]] of await this.state.storage.list()) if (exp < now) await this.state.storage.delete(k);
  }
}

export default {
  fetch(req, env) {
    const stub = env.QUOTA.get(env.QUOTA.idFromName('global'));
    const take = async (rules) =>
      (await (await stub.fetch('https://quota/take', { method: 'POST', body: JSON.stringify({ rules }) })).json()).ok;
    return handle(req, env, take, spec);
  },
};
