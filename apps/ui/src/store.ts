import { useSyncExternalStore } from 'react';
import { getBridge } from './bridge';
import type { Link, Snapshot } from './types';

export interface VigilState {
  link: Link;
  snapshot: Snapshot | null;
}

let state: VigilState = { link: { up: false }, snapshot: null };
const listeners = new Set<() => void>();

function set(next: Partial<VigilState>) {
  state = { ...state, ...next };
  listeners.forEach((l) => l());
}

let started = false;

/** Subscribe once to the shell's snapshot and link events. */
export function start() {
  if (started) return;
  started = true;
  void getBridge().then((b) => {
    void b.onLink((link) => set({ link }));
    void b.onSnapshot((snapshot) => set({ snapshot }));
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
