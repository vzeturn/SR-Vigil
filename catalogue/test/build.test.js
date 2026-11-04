import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, generateKeyPairSync, verify as nodeVerify } from 'node:crypto';
import { compareVersions, newest, parseVersion } from '../src/version.js';
import { buildSnapshot, manifestPath } from '../src/build.js';
import { sign } from '../src/sign.js';

globalThis.crypto ??= webcrypto;

test('parse and compare versions numerically', () => {
  assert.deepEqual(parseVersion('2.47.0.windows.1'), [2, 47, 0]);
  assert.equal(parseVersion('beta'), null);
  assert.equal(compareVersions([1, 2], [1, 2, 0]), 0);
  assert.equal(compareVersions([1, 10], [1, 9]), 1);
});

test('newest ignores pre-releases and picks numerically highest', () => {
  assert.equal(newest(['1.9.0', '1.10.0', '1.11.0-beta', '1.2']), '1.10.0');
  assert.equal(newest(['rc', 'preview']), null);
});

test('winget manifest path', () => {
  assert.equal(manifestPath('7zip.7zip'), '7/7zip/7zip');
  assert.equal(manifestPath('Microsoft.VisualStudioCode'), 'm/Microsoft/VisualStudioCode');
});

test('a failing product is left out, not guessed', async () => {
  const fetcher = async (url) =>
    url.includes('/g/Good/Pkg')
      ? { ok: true, json: async () => [{ type: 'dir', name: '1.0' }, { type: 'dir', name: '2.0' }] }
      : { ok: false, status: 404 };
  const { snapshot, failed } = await buildSnapshot({
    products: { Good: 'Good.Pkg', Bad: 'Bad.Pkg' },
    overrides: { Good: { min_supported: '1.5' } },
    fetcher,
    now: 0,
  });
  assert.deepEqual(snapshot.products, { Good: { latest: '2.0', min_supported: '1.5' } });
  assert.equal(failed.length, 1);
});

test('signature verifies over the exact payload bytes and breaks on tampering', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const env = await sign({ v: 1, issued: 'x', products: {} }, pkcs8, 'k1');
  const ok = (payload) => nodeVerify(null, Buffer.from(payload), publicKey, Buffer.from(env.sig, 'base64'));
  assert.equal(ok(env.payload), true);
  assert.equal(ok(env.payload.replace('"v":1', '"v":2')), false);
});
