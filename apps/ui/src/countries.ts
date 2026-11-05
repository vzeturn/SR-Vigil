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

/** Outbound connections grouped by destination country, busiest first. */
export function connectionsByCountry(conns: readonly ConnectionInfo[]): [string, ConnectionInfo[]][] {
  const g = new Map<string, ConnectionInfo[]>();
  for (const c of conns) if (c.country && c.direction === 'outbound') g.set(c.country, [...(g.get(c.country) ?? []), c]);
  return [...g].sort((a, b) => b[1].length - a[1].length);
}

/** The five countries with the most outbound connections. */
export function topCountries(conns: readonly ConnectionInfo[]): [string, number][] {
  return connectionsByCountry(conns)
    .slice(0, 5)
    .map(([cc, list]) => [cc, list.length]);
}
