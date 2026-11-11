import { useSyncExternalStore } from 'react';
import { getBridge } from './bridge';
import type { AiOpinion, Link, PendingItem, LauncherPrompt, ReopenPrompt, Snapshot, ThreatPrompt } from './types';

export interface VigilState {
  link: Link;
  snapshot: Snapshot | null;
  /** `null` until the first `pending.list` answers. */
  pending: PendingItem[] | null;
  pendingError: string | null;
  /** Epoch ms of the last panic, shown as a banner until dismissed. */
  panicAt: number | null;
  /** Killed program waiting frozen for the user's answer. */
  reopen: ReopenPrompt | null;
  launcher: LauncherPrompt | null;
  /** Suspicious network patterns waiting for the user's consent or answer, oldest first. */
  threats: ThreatPrompt[];
}

let state: VigilState = { link: { up: false }, snapshot: null, pending: null, pendingError: null, panicAt: null, reopen: null, launcher: null, threats: [] };
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

/** Send the answer; the prompt is cleared whatever happens (the service kills on timeout anyway). */
export async function answerReopen(p: ReopenPrompt, allow: boolean): Promise<void> {
  set({ reopen: null });
  const b = await getBridge();
  await b.rpc('reopen.answer', { pid: p.pid, start_time: p.start_time, allow });
}

export type LauncherAction = 'allow' | 'stop' | 'disable' | 'wait';

export async function answerLauncher(p: LauncherPrompt, action: LauncherAction): Promise<void> {
  set({ launcher: null });
  const b = await getBridge();
  await b.rpc('launcher.answer', { launcher: p.launcher, action });
}

/** Re-read unanswered network prompts (a freshly built popup window missed the event). */
export async function refreshThreats(): Promise<void> {
  try {
    const { threats } = await (await getBridge()).rpc<{ threats: ThreatPrompt[] }>('threat.list');
    set({ threats });
  } catch {
    // No service yet: the next link-up retries.
  }
}

export type ThreatAction = 'analyze' | 'block' | 'dismiss';

/** `analyze` sends the program's metadata to the advisor (the user's consent) and resolves to its opinion. */
export async function answerThreat(p: ThreatPrompt, action: ThreatAction): Promise<AiOpinion | null> {
  const b = await getBridge();
  const out = await b.rpc<AiOpinion>('threat.answer', { threat_id: p.threat_id, action });
  // After an analysis the prompt stays: the user still decides between block and ignore.
  if (action === 'analyze') return out;
  set({ threats: state.threats.filter((t) => t.threat_id !== p.threat_id) });
  return null;
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
      if (link.up && !wasUp) {
        void refreshPending();
        void refreshThreats();
      }
    });
    void b.onSnapshot((snapshot) => {
      const stale = state.pending?.length !== snapshot.status.counts.pending;
      set({ snapshot });
      if (stale) void refreshPending();
    });
    void b.onPending(() => void refreshPending());
    void b.onLauncher((launcher) => set({ launcher }));
    void b.onReopen((reopen) => set({ reopen: { ...reopen, received_at: Date.now() } }));
    void b.onThreat((t) => {
      if (!state.threats.some((x) => x.threat_id === t.threat_id)) set({ threats: [...state.threats, t] });
    });
    void refreshThreats();
  });
}

/** Current state outside React (event handlers that run after an await). */
export const vigilState = (): VigilState => state;

export function useVigil(): VigilState {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => state,
  );
}
