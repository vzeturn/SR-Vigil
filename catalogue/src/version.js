/** Leading dotted numbers of a version string ("2.47.0.windows.1" -> [2,47,0]); null when none. */
export function parseVersion(text) {
  const parts = [];
  for (const p of String(text ?? '').trim().split('.')) {
    const m = /^\d+/.exec(p);
    if (!m) break;
    parts.push(Number(m[0]));
  }
  return parts.length ? parts : null;
}

/** Numeric comparison; missing trailing parts count as zero. */
export function compareVersions(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** Highest stable version in `names` (pre-release suffixes after a digit part are ignored by parse). */
export function newest(names) {
  let best = null;
  for (const name of names) {
    if (/[a-z]/i.test(name.replace(/^\d[\d.]*/, '').replace(/^\.?(windows|win|x64)[.\d]*$/i, ''))) continue;
    const v = parseVersion(name);
    if (v && (!best || compareVersions(v, best.v) > 0)) best = { v, name };
  }
  return best?.name ?? null;
}
