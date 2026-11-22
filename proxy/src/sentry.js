// Sentry options for the Cloudflare Worker (free plan). Pure module: no SDK import, unit-tested in Node.
// Events carry no personal data: callers send host telemetry (paths, command lines) and an install
// token, so request bodies, headers, query strings, IPs and user fields never leave the Worker.

const KEEP_SPAN_KEYS = /^(http\.request\.method|http\.response\.status_code|url\.path|http\.route|sentry\.|cloudflare\.|faas\.|server\.address)/;

/** `https://host/path?q` -> `https://host/path`; anything unparsable is dropped. */
export function stripUrl(url) {
  if (typeof url !== 'string') return undefined;
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return undefined;
  }
}

function scrubData(data) {
  if (!data || typeof data !== 'object') return undefined;
  const out = {};
  for (const [k, v] of Object.entries(data)) if (KEEP_SPAN_KEYS.test(k)) out[k] = v;
  return out;
}

/** Removes everything that could identify a caller or carry host telemetry. Mutates and returns `event`. */
export function scrubEvent(event) {
  if (event.request) event.request = { method: event.request.method, url: stripUrl(event.request.url) };
  delete event.user;
  delete event.extra;
  if (Array.isArray(event.breadcrumbs)) {
    event.breadcrumbs = event.breadcrumbs.map((b) => ({
      timestamp: b.timestamp,
      category: b.category,
      level: b.level,
      type: b.type,
      data: b.data ? { method: b.data.method, url: stripUrl(b.data.url), status_code: b.data.status_code } : undefined,
    }));
  }
  if (event.contexts?.trace) event.contexts.trace.data = scrubData(event.contexts.trace.data);
  if (Array.isArray(event.spans)) {
    for (const s of event.spans) {
      s.data = scrubData(s.data);
      if (typeof s.description === 'string') s.description = s.description.replace(/\?.*$/, '');
    }
  }
  if (typeof event.transaction === 'string') event.transaction = event.transaction.replace(/\?.*$/, '');
  return event;
}

/** Options for `withSentry`; `undefined` (SDK off) when the `SENTRY_DSN` secret is not set. */
export function sentryOptions(env) {
  if (!env.SENTRY_DSN) return undefined;
  return {
    dsn: env.SENTRY_DSN,
    environment: env.SENTRY_ENVIRONMENT ?? 'production',
    release: env.SENTRY_RELEASE,
    sendDefaultPii: false,
    tracesSampleRate: Number(env.SENTRY_TRACES_SAMPLE_RATE ?? 0.05),
    beforeSend: scrubEvent,
    beforeSendTransaction: scrubEvent,
    beforeBreadcrumb: (b) => (b.category === 'console' ? null : b),
  };
}

/** Constant-time string compare for the ops-only test route. */
export function sameSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length || a.length < 24) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
