import type { Bridge } from './bridge';
import type {
  AiConfig,
  AuditEntry,
  DecisionParams,
  KeyedService,
  PendingItem,
  PersistenceItem,
  ProcessInfo,
  ReputationConfig,
  ServiceItem,
  Snapshot,
  Verdict,
} from './types';

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
      package_family: i === 1 ? 'https://github.com/awslabs/|c:\\users\\mock\\appdata\\roaming\\uv\\tools' : null,
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
    freshness:
      i === 0
        ? {
            product: 'Mock App',
            installed: '1.0',
            latest: '2.0',
            status: 'outdated',
            download_page: 'https://example.com/download',
          }
        : null,
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
    protection: true,
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

  const services: ServiceItem[] = [
    {
      pid: 900,
      name: 'WSearch',
      display_name: 'Windows Search',
      dll: String.raw`C:\Windows\System32\mssrch.dll`,
      suspicious: null,
      refusal: null,
      network_blocked: false,
      shared_with: ['MockHelper'],
    },
    {
      pid: 900,
      name: 'MockHelper',
      display_name: 'Mock Helper',
      dll: String.raw`C:\Users\Mock\AppData\Local\helper.dll`,
      suspicious: 'writable_location',
      refusal: 'no_service_sid',
      network_blocked: false,
      shared_with: ['WSearch'],
    },
    {
      pid: 800,
      name: 'Dnscache',
      display_name: 'DNS Client',
      dll: String.raw`C:\Windows\System32\dnsrslvr.dll`,
      suspicious: null,
      refusal: 'protected_target',
      network_blocked: false,
      shared_with: [],
    },
  ];

  let ai: AiConfig = {
    enabled: false,
    mode: 'off',
    model: 'claude-haiku-5-5',
    escalation_model: 'claude-sonnet-5-5',
    has_key: false,
    source: 'own_key',
    shared_available: true,
    auto_threshold: 0.9,
    escalate_below: 0.75,
    auto_kill: false,
    send_cmdline: false,
    daily_call_budget: 500,
    calls_today: 0,
  };

  let reputation: ReputationConfig = {
    virustotal: { enabled: false, has_key: false },
    malwarebazaar: { enabled: false, has_key: false },
  };
  let enforcement = { block_inbound: false };
  let urlfilter = { enabled: false, malware: true, phishing: true, adult: false, ads: false, allow: [] as string[] };
  const handlers: Record<string, (params: unknown) => unknown> = {
    'ai.activity': () => {
      const u = { assessed: 0, calls: 0, cached: 0, tokens_in: 0, tokens_out: 0, allowed: 0, blocked: 0, killed: 0, left_to_user: 0, cost_usd: 0 };
      return { today: u, week: u, month: u };
    },
    'ai.config.get': () => ai,
    'ai.config.set': (params) => {
      const { api_key, acknowledge_data_categories, ...rest } = params as Partial<AiConfig> & {
        api_key?: string;
        acknowledge_data_categories?: boolean;
      };
      const has_key = api_key === undefined ? ai.has_key : api_key !== '';
      const source = rest.source ?? ai.source;
      if (source === 'shared' && !ai.shared_available) throw new Error('invalid_params');
      if (rest.enabled && !((has_key || source === 'shared') && acknowledge_data_categories)) {
        throw new Error('invalid_state');
      }
      ai = { ...ai, ...rest, has_key, source };
      return ai;
    },
    'reputation.config.get': () => reputation,
    'reputation.config.set': (params) => {
      const { service, enabled, api_key } = params as { service: KeyedService; enabled?: boolean; api_key?: string };
      const cur = reputation[service];
      if (!cur) throw new Error('invalid_params');
      const has_key = api_key === undefined ? cur.has_key : api_key !== '';
      const on = api_key === '' ? false : (enabled ?? cur.enabled);
      if (on && !has_key) throw new Error('invalid_state');
      reputation = { ...reputation, [service]: { enabled: on, has_key } };
      return reputation;
    },
    'ai.explain': () => {
      if (!ai.enabled) throw new Error('off');
      return {
        verdict: 'unknown',
        confidence: 0.6,
        recommended_action: 'ask_user',
        reasons: ['Unsigned binary in a user-writable folder', 'Not seen on this machine before'],
        indicators: [],
        model: ai.model,
      };
    },
    'decision.export': () => ({ content: 'version = 1\n', count: 0 }),
    'decision.import': (params) => {
      const { content } = params as { content?: string };
      if (!content?.startsWith('version = 1')) throw new Error('invalid_params');
      return { imported: 0, skipped: 0 };
    },
    'audit.export': () => ({ format: 'csv', content: 'seq,ts,actor,kind,target,details,hash\r\n', count: 0 }),
    'ai.test':() => ({ ok: ai.has_key || ai.source === 'shared', latency_ms: 120, model: ai.model }),
    'process.kill': () => ({ ok: true, detail: 'terminated' }),
    'protection.set': () => status(),
    'purge.status': () => ({ active: false, spared: {}, kept: [], held: [] }),
    'persistence.scan': () => ({ findings: persistence.map((p) => ({ ...p })) }),
    'persistence.apply': (params) => {
      const { item_id, action } = params as { item_id: string; action: string };
      const it = persistence.find((x) => x.id === item_id);
      if (!it) throw new Error('not_found');
      it.status = action === 'disable' ? 'disabled' : action === 'restore' ? 'restored' : 'deleted';
      return { ok: true, detail: it.status };
    },
    'service.list': () => ({ items: services.map((s) => ({ ...s })) }),
    'service.block_network': (params) => {
      const { name, block } = params as { name: string; block: boolean };
      const s = services.find((x) => x.name.toLowerCase() === name.toLowerCase());
      if (!s) return { ok: false, error_code: 'not_found', detail: 'the service is not running' };
      if (block && s.refusal) return { ok: false, error_code: s.refusal, detail: 'this service cannot be blocked' };
      s.network_blocked = block;
      return { ok: true, error_code: null, detail: block ? 'blocked' : 'unblocked' };
    },
    'rule.list': () => ({ rule_pack_version: '1.0.0', rules: [] }),
    'trust.list': () => ({ publishers: [] }),
    'pending.list': () => ({ items: pending }),
    'decision.list': () => ({ items: [] }),
    'decision.revoke': () => ({}),
    'decision.exception': () => ({}),
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
    'threat.list': () => ({ threats: [] }),
    'settings.get': () => ({ urlfilter, enforcement }),
    'settings.set': (params) => {
      const p = (params as { settings?: { urlfilter?: Partial<typeof urlfilter>; enforcement?: Partial<typeof enforcement> } })
        .settings;
      urlfilter = { ...urlfilter, ...p?.urlfilter };
      enforcement = { ...enforcement, ...p?.enforcement };
      return { urlfilter, enforcement };
    },
    'dns.status': () => ({
      enabled: urlfilter.enabled,
      listening: urlfilter.enabled,
      categories: [],
      domains: 182_340,
      queries: 4_210,
      blocked: 37,
      by_category: { malware: 4, phishing: 2, adult: 0, ads: 31 },
      recent: [{ domain: 'ads.example.net', category: 'ads', at: new Date().toISOString() }],
      upstream: null,
      lists_loaded_at: null,
    }),
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
    onLauncher: () => Promise.resolve(() => undefined),
    onReopen: () => Promise.resolve(() => undefined),
    onThreat: () => Promise.resolve(() => undefined),
  };
}
