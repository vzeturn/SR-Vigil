import type { Link, PendingItem, Snapshot } from './types';

/** The only door to the service. In a browser (dev, tests) a mock stands in for the Tauri shell. */
export interface Bridge {
  rpc<T>(method: string, params?: unknown): Promise<T>;
  onSnapshot(cb: (s: Snapshot) => void): Promise<() => void>;
  onLink(cb: (l: Link) => void): Promise<() => void>;
  /** Fired when the service queues a new pending decision (payload may be absent). */
  onPending(cb: (p: PendingItem | null) => void): Promise<() => void>;
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
    onPending: (cb) => listen<PendingItem | null>('vigil://pending', (e) => cb(e.payload)),
  };
}

/** Tray menu text is owned by the i18n tables; no-op outside the Tauri shell. */
export async function syncTrayLabels(labels: Record<string, string>): Promise<void> {
  if (!inTauri) return;
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('set_tray_labels', { labels });
}

/** Tray tooltip carrying the pending-decision count. No-op outside the Tauri shell. */
export async function syncTrayPending(tooltip: string): Promise<void> {
  if (!inTauri) return;
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('set_tray_pending', { tooltip });
}

/** Hide the popup window (Esc / Later): the item stays pending and blocked. No-op outside Tauri. */
/** Installs the service via one UAC prompt (desktop shell only; resolves false when declined). */
export async function enableProtection(): Promise<boolean> {
  if (!('__TAURI_INTERNALS__' in window)) return false;
  const { invoke } = await import('@tauri-apps/api/core');
  try {
    await invoke('enable_protection');
    return true;
  } catch {
    return false;
  }
}

export async function hidePopup(): Promise<void> {
  if (!inTauri) return;
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  await getCurrentWindow().hide();
}

let current: Promise<Bridge> | undefined;

export function getBridge(): Promise<Bridge> {
  current ??= inTauri
    ? tauriBridge()
    : import('./mockBridge').then((m) => m.createMockBridge());
  return current;
}
