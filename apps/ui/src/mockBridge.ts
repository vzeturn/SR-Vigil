import type { Bridge } from './bridge';
import type { AiConfig, AuditEntry, DecisionParams, PendingItem, PersistenceItem, ProcessInfo, Snapshot, Verdict } from './types';

const HASH = 'a'.repeat(64);

function pendingItem(i: number): PendingItem {
  const signed = i % 2 === 0;
  return {
    id: `pending-${i}`,
    identity: {
      id: `identity-${i}`,
      sha256: HASH,
      path: `C:\\Users\\Mock\\Downloads\\tool-${i}.exe`,
      publisher: signed ? 'Mock Software Ltd' : null,
      signature_status: signed ? 'valid_embedded' : 'unsigned',
    },
    evaluation: {
      score: 42 - i,
      verdict: 'unknown',
      signals: [
        { id: 'SG-010', name: 'Unsigned in user-writable path', delta: -15 },
        { id: 'SG-011', name: 'Created recently', delta: 0, detail: '3 min ago' },
      ],
      rule_pack_version: '1.0.0',
    },
    process: null,
    destination: { addr: '203.0.113.7', port: 443, dns_name: 'api.example.net', dest_class: 'public' },
    ai_opinion: null,
    created_at: '2026-01-01T00:00:00Z',
  };
}

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
  let pending: PendingItem[] = [0, 1, 2].map(pendingItem);
  const audit: AuditEntry[] = Array.from({ length: 300 }, (_, i) => ({
    seq: i + 1,
    ts: '2026-01-01T00:00:00Z',
    actor: i % 3 === 0 ? 'user' : 'service',
    kind: i % 3 === 0 ? 'decision.submit' : 'verdict.changed',
    target: `identity-${i % 3}`,
    details: {},
    hash: i.toString(16).padStart(64, '0'),
  }));
  const snapshotListeners = new Set<(s: Snapshot) => void>();
  const status = (): Snapshot['status'] => ({
    service_version: '0.1.0',
    mode: 'observe',
    health: 'healthy',
    filters_armed: false,
    counts: { safe: count('safe'), unknown: count('unknown'), malicious: count('malicious'), pending: pending.length },
    rule_pack_version: '1.0.0',
  });
  const snapshot = (): Snapshot => ({ status: status(), processes, connections: [] });

  const persistence: PersistenceItem[] = [
    {
      id: '1',
      kind: 'run_key',
      location: String.raw`HKCU\Software\Microsoft\Windows\CurrentVersion\Run :: Updater`,
      image_path: String.raw`C:\Temp\updater.exe`,
      command: String.raw`C:\Temp\updater.exe /silent`,
      status: 'found',
      first_seen: '2026-01-01T00:00:00Z',
    },
  ];

  let ai: AiConfig = {
    enabled: false,
    mode: 'off',
    model: 'claude-haiku-5-5',
    escalation_model: 'claude-sonnet-5-5',
    has_key: false,
    auto_threshold: 0.9,
    escalate_below: 0.75,
    auto_kill: false,
    send_cmdline: false,
    daily_call_budget: 500,
    calls_today: 0,
  };

  const handlers: Record<string, (params: unknown) => unknown> = {
    'ai.config.get': () => ai,
    'ai.config.set': (params) => {
      const { api_key, acknowledge_data_categories, ...rest } = params as Partial<AiConfig> & {
        api_key?: string;
        acknowledge_data_categories?: boolean;
      };
      const has_key = api_key === undefined ? ai.has_key : api_key !== '';
      if (rest.enabled && !(has_key && acknowledge_data_categories)) throw new Error('invalid_state');
      ai = { ...ai, ...rest, has_key };
      return ai;
    },
    'ai.test': () => ({ ok: ai.has_key, latency_ms: 120, model: ai.model }),
    'process.kill': () => ({ ok: true, detail: 'terminated' }),
    'persistence.scan': () => ({ findings: persistence.map((p) => ({ ...p })) }),
    'persistence.apply': (params) => {
      const { item_id, action } = params as { item_id: string; action: string };
      const it = persistence.find((x) => x.id === item_id);
      if (!it) throw new Error('not_found');
      it.status = action === 'disable' ? 'disabled' : action === 'restore' ? 'restored' : 'deleted';
      return { ok: true, detail: it.status };
    },
    'rule.list': () => ({ rule_pack_version: '1.0.0', rules: [] }),
    'trust.list': () => ({ publishers: [] }),
    'pending.list': () => ({ items: pending }),
    'decision.list': () => ({ items: [] }),
    'audit.query': () => ({ items: audit, next_cursor: null, chain_ok: true }),
    'decision.submit': (params) => {
      const { pending_id, action, scope, apply_to } = params as DecisionParams;
      const item = pending.find((p) => p.id === pending_id);
      if (!item) throw new Error('conflict');
      pending = pending.filter((p) => p.id !== pending_id);
      snapshotListeners.forEach((cb) => cb(snapshot()));
      const decision = {
        id: `decision-${pending_id}`,
        identity_id: item.identity.id,
        action,
        scope,
        apply_to,
        by: 'user',
        created_at: '2026-01-01T00:00:00Z',
      };
      return { decision, applied: true };
    },
    'enforcement.panic': status,
  };

  return {
    rpc: <T>(method: string, params?: unknown) => {
      try {
        return Promise.resolve((handlers[method]?.(params) ?? status()) as T);
      } catch (e) {
        return Promise.reject(e instanceof Error ? e : new Error(String(e)));
      }
    },
    onSnapshot: (cb) => {
      snapshotListeners.add(cb);
      cb(snapshot());
      return Promise.resolve(() => void snapshotListeners.delete(cb));
    },
    onLink: (cb) => {
      cb({ up: true, role: 'admin' });
      return Promise.resolve(() => undefined);
    },
    onPending: () => Promise.resolve(() => undefined),
  };
}
