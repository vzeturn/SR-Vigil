import type { Link, PendingItem, Snapshot, Verdict } from './types';

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

export interface JunkCategory {
  id: string;
  files: number;
  bytes: number;
}

/** Survey reclaimable junk (read-only). Empty outside the desktop shell. */
export async function junkScan(): Promise<JunkCategory[]> {
  if (!inTauri) return [];
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<JunkCategory[]>('junk_scan');
}

/** Delete the approved categories; resolves to the bytes freed. */
export async function junkClean(ids: string[]): Promise<number> {
  if (!inTauri) return 0;
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<number>('junk_clean', { ids });
}

export interface LocalFinding {
  pid: number;
  name: string;
  image: string;
  score: number;
  verdict: Verdict;
  /** Creation time as a decimal string (exceeds JS safe integers); pins the PID to one instance. */
  start: string | null;
  reasons: LocalReason[];
  spoof: Spoof;
  known: { label: string; what: string } | null;
  advice: Advice;
  impact: Impact;
  ramMb: number;
  cpu: number;
  threads: number;
  identity: Identity;
}

export type Advice = "keep" | "watch" | "end";
export type Impact = "low" | "medium" | "high";
export type Spoof = "clear" | "doubtful" | "likely";

/** Who signed the file and what the file says about itself. */
export interface Identity {
  signature: string;
  publisher: string | null;
  chain: string[];
  msRoot: boolean;
  osSigned: boolean;
  company: string;
  product: string;
  original: string;
}

export type ReasonKind = "signal" | "hard_rule" | "hard_allow" | "guard";

export interface LocalReason {
  id: string;
  name: string;
  kind: ReasonKind;
  description: string;
  delta: number | null;
}

export interface LocalScan {
  safe: number;
  unknown: number;
  malicious: number;
  total: number;
  skipped: number;
  /** 0-100: trusted share (unknown counts half) minus 30 per malicious process. */
  posture: number;
  /** Process counts by score band: 0-29, 30-49, 50-79, 80-100. */
  buckets: [number, number, number, number];
  topReasons: (Omit<LocalReason, "delta"> & { count: number })[];
  findings: LocalFinding[];
}

/** Service-less survey of running processes; unavailable outside the desktop shell. */
export async function localScan(): Promise<LocalScan> {
  if (!inTauri) {
    return {
      safe: 0,
      unknown: 0,
      malicious: 0,
      total: 0,
      skipped: 0,
      posture: 0,
      buckets: [0, 0, 0, 0],
      topReasons: [],
      findings: [],
    };
  }
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<LocalScan>("local_scan");
}

export interface ScanProgress {
  done: number;
  total: number;
  scan: LocalScan;
}

/** Subscribe to partial scan results as they are classified; returns an unsubscribe function. */
export async function onScanProgress(cb: (p: ScanProgress) => void): Promise<() => void> {
  if (!inTauri) return () => undefined;
  const { listen } = await import("@tauri-apps/api/event");
  return listen<ScanProgress>("vigil://scan", (e) => cb(e.payload));
}

/** End one process the user chose; resolves to terminated | gone | access_denied | failed. */
export async function localKill(f: LocalFinding): Promise<string> {
  if (!inTauri || !f.start) return "failed";
  const { invoke } = await import("@tauri-apps/api/core");
  try {
    return await invoke<string>("local_kill", { pid: f.pid, start: f.start, image: f.image });
  } catch (e) {
    return String(e);
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
