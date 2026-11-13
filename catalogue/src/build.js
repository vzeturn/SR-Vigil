import { newest } from './version.js';

const GITHUB = 'https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests';
const RAW = 'https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests';
const MAX_HASHES = 8;
const MAX_LINK = 300;

/** Manifest directory of a winget id: "7zip.7zip" -> "7/7zip/7zip". */
export function manifestPath(id) {
  const [publisher, ...rest] = id.split('.');
  const pkg = rest.join('/');
  return `${publisher[0].toLowerCase()}/${publisher}/${pkg}`;
}

async function wingetVersions(id, fetcher, token) {
  const headers = { 'user-agent': 'vigil-catalogue', accept: 'application/vnd.github+json' };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetcher(`${GITHUB}/${manifestPath(id)}`, { headers });
  if (!res.ok) throw new Error(`winget ${id}: HTTP ${res.status}`);
  const list = await res.json();
  return list.filter((e) => e.type === 'dir').map((e) => e.name);
}

/** Value of a top-level or list-item YAML key, quotes stripped; manifests are flat enough. */
function yamlValues(text, key) {
  const re = new RegExp(String.raw`^\s*-?\s*${key}:\s*['"]?([^'"\s#]+)`, 'gm');
  return [...text.matchAll(re)].map((m) => m[1]);
}

async function manifestText(url, fetcher) {
  try {
    const res = await fetcher(url, { headers: { 'user-agent': 'vigil-catalogue' } });
    return res.ok && typeof res.text === 'function' ? await res.text() : '';
  } catch {
    return '';
  }
}

/**
 * Installer hashes and vendor page for `id` at `version`, from the winget manifests. Anything
 * missing or malformed is left out; the service re-checks the link before showing it.
 */
export async function releaseDetails(id, version, fetcher) {
  const base = `${RAW}/${manifestPath(id)}/${version}/${id}`;
  const [installer, locale] = await Promise.all([
    manifestText(`${base}.installer.yaml`, fetcher),
    manifestText(`${base}.locale.en-US.yaml`, fetcher),
  ]);
  const hashes = [
    ...new Set(
      yamlValues(installer, 'InstallerSha256')
        .filter((h) => /^[0-9A-Fa-f]{64}$/.test(h))
        .map((h) => h.toLowerCase()),
    ),
  ].slice(0, MAX_HASHES);
  const page = [...yamlValues(locale, 'PackageUrl'), ...yamlValues(locale, 'PublisherUrl')].find(
    (u) => u.startsWith('https://') && u.length <= MAX_LINK,
  );
  return {
    ...(page ? { download_page: page } : {}),
    ...(hashes.length ? { installer_sha256: hashes } : {}),
  };
}

/**
 * Build the unsigned snapshot. A product whose lookup fails is simply left out, so a transient
 * error never publishes a wrong value; `overrides` carries the curated min_supported,
 * vulnerable_below and end_of_support data and wins over manifest values.
 */
export async function buildSnapshot({ products, overrides, fetcher, token, now }) {
  const out = {};
  const failed = [];
  for (const [label, id] of Object.entries(products)) {
    try {
      const latest = newest(await wingetVersions(id, fetcher, token));
      if (!latest) throw new Error('no stable version');
      const details = await releaseDetails(id, latest, fetcher);
      out[label] = { latest, winget_id: id, ...details, ...(overrides[label] ?? {}) };
    } catch (e) {
      failed.push(`${label}: ${e.message}`);
    }
  }
  return { snapshot: { v: 1, issued: new Date(now).toISOString(), products: out }, failed };
}
