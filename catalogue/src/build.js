import { newest } from './version.js';

const GITHUB = 'https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests';

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

/**
 * Build the unsigned snapshot. A product whose lookup fails is simply left out, so a transient
 * error never publishes a wrong value; `overrides` carries the curated min_supported and
 * vulnerable_below data.
 */
export async function buildSnapshot({ products, overrides, fetcher, token, now }) {
  const out = {};
  const failed = [];
  for (const [label, id] of Object.entries(products)) {
    try {
      const latest = newest(await wingetVersions(id, fetcher, token));
      if (!latest) throw new Error('no stable version');
      out[label] = { latest, ...(overrides[label] ?? {}) };
    } catch (e) {
      failed.push(`${label}: ${e.message}`);
    }
  }
  return { snapshot: { v: 1, issued: new Date(now).toISOString(), products: out }, failed };
}
