import type { Bridge } from './bridge';
import type { ProcessInfo, Snapshot, Verdict } from './types';

/** Deterministic stand-in used outside Tauri: `pnpm dev` in a browser, Vitest, Playwright. */
export function createMockBridge(rows = 200): Bridge {
  const verdicts: Verdict[] = ['safe', 'safe', 'safe', 'unknown', 'malicious'];
  const processes: ProcessInfo[] = Array.from({ length: rows }, (_, i) => ({
    pid: 1000 + i,
    start_time: '2026-01-01T00:00:00Z',
    ppid: 4,
    name: `process-${i}.exe`,
    path: `C:\\Mock\\process-${i}.exe`,
    verdict: verdicts[i % verdicts.length],
    score: 20 + ((i * 7) % 80),
  }));
  const count = (v: Verdict) => processes.filter((p) => p.verdict === v).length;
  const snapshot: Snapshot = {
    status: {
      service_version: '0.1.0',
      mode: 'observe',
      health: 'healthy',
      filters_armed: false,
      counts: { safe: count('safe'), unknown: count('unknown'), malicious: count('malicious'), pending: 0 },
      rule_pack_version: '1.0.0',
    },
    processes,
    connections: [],
  };
  return {
    rpc: <T>(method: string) =>
      Promise.resolve(
        (method === 'rule.list'
          ? { rule_pack_version: '1.0.0', rules: [] }
          : method === 'trust.list'
            ? { publishers: [] }
            : snapshot.status) as T,
      ),
    onSnapshot: (cb) => {
      cb(snapshot);
      return Promise.resolve(() => undefined);
    },
    onLink: (cb) => {
      cb({ up: true, role: 'viewer' });
      return Promise.resolve(() => undefined);
    },
  };
}
