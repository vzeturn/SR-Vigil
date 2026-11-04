import type { PendingItem } from '../types';

export const itemName = (p: PendingItem): string =>
  p.identity.original_filename ?? p.identity.path.split(/[\\/]/).pop() ?? p.identity.path;

export const destinationText = (p: PendingItem): string =>
  `${p.destination.dns_name ?? p.destination.addr}:${p.destination.port}`;

/** Publisher-wide decisions need a validly signed publisher. */
export const hasPublisher = (p: PendingItem): boolean =>
  Boolean(p.identity.publisher) && p.identity.signature_status.startsWith('valid');
