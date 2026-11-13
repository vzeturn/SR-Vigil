import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, generateKeyPairSync, verify as nodeVerify } from 'node:crypto';
import { compareVersions, newest, parseVersion } from '../src/version.js';
import { buildSnapshot, manifestPath, releaseDetails } from '../src/build.js';
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
  assert.deepEqual(snapshot.products, {
    Good: { latest: '2.0', winget_id: 'Good.Pkg', min_supported: '1.5' },
  });
  assert.equal(failed.length, 1);
});

test('release details come from the winget manifests and skip malformed values', async () => {
  const hash = 'AB'.repeat(32);
  const files = {
    'Good.Pkg.installer.yaml': `Installers:
- Architecture: x64
  InstallerSha256: ${hash}
- Architecture: x86
  InstallerSha256: ${hash}
- InstallerSha256: nothex
`,
    'Good.Pkg.locale.en-US.yaml': `PublisherUrl: https://good.example
PackageUrl: "https://good.example/download"
`,
  };
  const fetcher = async (url) => {
    assert.ok(url.startsWith('https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/g/Good/Pkg/2.0/'));
    const body = files[url.split('/').pop()];
    return body ? { ok: true, text: async () => body } : { ok: false, status: 404 };
  };
  assert.deepEqual(await releaseDetails('Good.Pkg', '2.0', fetcher), {
    download_page: 'https://good.example/download',
    installer_sha256: ['ab'.repeat(32)],
  });
  const plain = async () => ({ ok: true, text: async () => 'PackageUrl: http://insecure.example\n' });
  assert.deepEqual(await releaseDetails('Good.Pkg', '2.0', plain), {});
});

test('signature verifies over the exact payload bytes and breaks on tampering', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const env = await sign({ v: 1, issued: 'x', products: {} }, pkcs8, 'k1');
  const ok = (payload) => nodeVerify(null, Buffer.from(payload), publicKey, Buffer.from(env.sig, 'base64'));
  assert.equal(ok(env.payload), true);
  assert.equal(ok(env.payload.replace('"v":1', '"v":2')), false);
});
