import type { ConnectionInfo } from './types';

const names = new Intl.DisplayNames(undefined, { type: 'region' });

/** Localised country name for an ISO code; empty when the destination is private or unknown. */
export function countryName(code?: string | null): string {
  if (!code) return '';
  try {
    return names.of(code) ?? code;
  } catch {
    return code;
  }
}

/** The five countries with the most outbound connections. */
export function topCountries(conns: readonly ConnectionInfo[]): [string, number][] {
  const n = new Map<string, number>();
  for (const c of conns) if (c.country && c.direction === 'outbound') n.set(c.country, (n.get(c.country) ?? 0) + 1);
  return [...n].sort((a, b) => b[1] - a[1]).slice(0, 5);
}
