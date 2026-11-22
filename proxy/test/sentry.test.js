import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sameSecret, scrubEvent, sentryOptions, stripUrl } from '../src/sentry.js';

test('SDK stays off without a DSN and never sends default PII', () => {
  assert.equal(sentryOptions({}), undefined);
  const o = sentryOptions({ SENTRY_DSN: 'https://k@o1.ingest.de.sentry.io/1' });
  assert.equal(o.sendDefaultPii, false);
  assert.equal(o.environment, 'production');
  assert.ok(o.tracesSampleRate > 0 && o.tracesSampleRate <= 0.1);
});

test('events lose bodies, headers, query strings, users and span attributes', () => {
  const e = scrubEvent({
    request: { method: 'POST', url: 'https://w.dev/v1/assess?x=C:\\Users\\bob', headers: { authorization: 'Bearer t' }, data: '{"path":"C:\\\\Users\\\\bob"}', cookies: { a: 1 } },
    user: { ip_address: '1.2.3.4' },
    extra: { payload: 'secret' },
    breadcrumbs: [{ category: 'fetch', data: { method: 'POST', url: 'https://api.anthropic.com/v1/messages?k=1', request_body: 'x' } }],
    contexts: { trace: { data: { 'http.request.method': 'POST', 'http.request.header.authorization': 'Bearer t', 'client.address': '1.2.3.4', 'url.full': 'https://w.dev/v1/assess?q=1' } } },
    spans: [{ description: 'POST https://api.anthropic.com/v1/messages?k=1', data: { 'user_agent.original': 'Vigil', 'url.path': '/v1/messages' } }],
  });
  assert.deepEqual(e.request, { method: 'POST', url: 'https://w.dev/v1/assess' });
  assert.equal(e.user, undefined);
  assert.equal(e.extra, undefined);
  assert.deepEqual(e.breadcrumbs[0].data, { method: 'POST', url: 'https://api.anthropic.com/v1/messages', status_code: undefined });
  assert.deepEqual(e.contexts.trace.data, { 'http.request.method': 'POST' });
  assert.deepEqual(e.spans[0].data, { 'url.path': '/v1/messages' });
  assert.equal(e.spans[0].description, 'POST https://api.anthropic.com/v1/messages');
  assert.ok(!JSON.stringify(e).includes('bob') && !JSON.stringify(e).includes('Bearer') && !JSON.stringify(e).includes('1.2.3.4'));
});

test('stripUrl and sameSecret', () => {
  assert.equal(stripUrl('nope'), undefined);
  assert.equal(sameSecret('a'.repeat(24), 'a'.repeat(24)), true);
  assert.equal(sameSecret('a'.repeat(24), 'b'.repeat(24)), false);
  assert.equal(sameSecret(undefined, undefined), false);
  assert.equal(sameSecret('short', 'short'), false);
});
