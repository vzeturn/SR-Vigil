import { useSyncExternalStore } from 'react';
import { getBridge } from './bridge';
import type { Link, PendingItem, Snapshot } from './types';

export interface VigilState {
  link: Link;
  snapshot: Snapshot | null;
  /** `null` until the first `pending.list` answers. */
  pending: PendingItem[] | null;
  pendingError: string | null;
  /** Epoch ms of the last panic, shown as a banner until dismissed. */
  panicAt: number | null;
}

let state: VigilState = { link: { up: false }, snapshot: null, pending: null, pendingError: null, panicAt: null };
const listeners = new Set<() => void>();

function set(next: Partial<VigilState>) {
  state = { ...state, ...next };
  listeners.forEach((l) => l());
}

/** Re-read the pending queue from the service. */
export async function refreshPending(): Promise<void> {
  try {
    const b = await getBridge();
    const { items } = await b.rpc<{ items: PendingItem[] }>('pending.list');
    set({ pending: items, pendingError: null });
  } catch (e) {
    set({ pendingError: e instanceof Error ? e.message : String(e) });
  }
}

export const markPanic = () => set({ panicAt: Date.now() });
export const dismissPanic = () => set({ panicAt: null });

let started = false;

/** Subscribe once to the shell's snapshot, link and pending events. */
export function start() {
  if (started) return;
  started = true;
  void getBridge().then((b) => {
    void b.onLink((link) => {
      const wasUp = state.link.up;
      set({ link });
      if (link.up && !wasUp) void refreshPending();
    });
    void b.onSnapshot((snapshot) => {
      const stale = state.pending?.length !== snapshot.status.counts.pending;
      set({ snapshot });
      if (stale) void refreshPending();
    });
    void b.onPending(() => void refreshPending());
  });
}

export function useVigil(): VigilState {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => state,
  );
}
