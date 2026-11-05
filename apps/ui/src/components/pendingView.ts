import type { PendingItem } from '../types';

export const itemName = (p: PendingItem): string =>
  p.identity.original_filename ?? p.identity.path.split(/[\\/]/).pop() ?? p.identity.path;

/** Port 0 marks a program flagged on start, before any connection exists. */
export const hasConnection = (p: PendingItem): boolean => p.destination.port !== 0;

export const destinationText = (p: PendingItem): string =>
  hasConnection(p)
    ? `${p.destination.dns_name ?? p.destination.addr}:${p.destination.port}`
    : 'no connection yet (flagged on start)';

/** Publisher-wide decisions need a validly signed publisher. */
export const hasPublisher = (p: PendingItem): boolean =>
  Boolean(p.identity.publisher) && p.identity.signature_status.startsWith('valid');
