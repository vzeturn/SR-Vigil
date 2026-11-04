import type { Link, Snapshot } from './types';

/** The only door to the service. In a browser (dev, tests) a mock stands in for the Tauri shell. */
export interface Bridge {
  rpc<T>(method: string, params?: unknown): Promise<T>;
  onSnapshot(cb: (s: Snapshot) => void): Promise<() => void>;
  onLink(cb: (l: Link) => void): Promise<() => void>;
}

const inTauri = '__TAURI_INTERNALS__' in globalThis;

async function tauriBridge(): Promise<Bridge> {
  const [{ invoke }, { listen }] = await Promise.all([
    import('@tauri-apps/api/core'),
    import('@tauri-apps/api/event'),
  ]);
  return {
    rpc: <T>(method: string, params?: unknown) => invoke<T>('rpc', { method, params }),
    onSnapshot: (cb) => listen<Snapshot>('vigil://snapshot', (e) => cb(e.payload)),
    onLink: (cb) => listen<Link>('vigil://link', (e) => cb(e.payload)),
  };
}

/** Tray menu text is owned by the i18n tables; no-op outside the Tauri shell. */
export async function syncTrayLabels(open: string, quit: string): Promise<void> {
  if (!inTauri) return;
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('set_tray_labels', { open, quit });
}

let current: Promise<Bridge> | undefined;

export function getBridge(): Promise<Bridge> {
  current ??= inTauri
    ? tauriBridge()
    : import('./mockBridge').then((m) => m.createMockBridge());
  return current;
}
