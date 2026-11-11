/** Subset of `schemas/ipc.schema.json` that the UI renders. */
export type Verdict = 'safe' | 'unknown' | 'malicious';
export type Mode = 'observe' | 'learning' | 'enforce';
export type Health = 'healthy' | 'degraded' | 'failed';

export interface Counts {
  safe: number;
  unknown: number;
  malicious: number;
  pending: number;
}

export interface Status {
  service_version: string;
  mode: Mode;
  /** false while the user has paused automatic blocking and killing. */
  protection?: boolean;
  health: Health;
  health_detail?: string | null;
  filters_armed: boolean;
  counts: Counts;
  rule_pack_version: string;
}

export interface ProcessInfo {
  pid: number;
  start_time: string;
  ppid: number;
  name: string;
  path?: string | null;
  identity_id?: string | null;
  verdict?: Verdict | null;
  score?: number | null;
  /** Set when this is a recognised program that is behind the newest release. */
  origin?: "user" | "script" | "autostart" | "service" | "agent" | null;
  freshness?: {
    product: string;
    installed: string;
    latest: string;
    status: 'outdated' | 'far_behind' | 'vulnerable';
  } | null;
}

export interface ConnectionInfo {
  id: string;
  pid: number;
  proto: 'tcp' | 'udp';
  direction: 'outbound' | 'inbound';
  local_addr: string;
  local_port: number;
  remote_addr?: string | null;
  remote_port?: number | null;
  dns_name?: string | null;
  state?: string | null;
  verdict?: Verdict | null;
  blocked: boolean;
  country?: string | null;
}

export interface Snapshot {
  status: Status;
  processes: ProcessInfo[];
  connections: ConnectionInfo[];
}

export interface Link {
  up: boolean;
  role?: 'admin' | 'viewer';
}

export interface Rule {
  id: string;
  name: string;
  kind: string;
  description?: string;
  source: string;
}

export interface TrustedPublisher {
  id: string;
  subject_org: string;
  source: string;
  note?: string | null;
}

export type Action = 'allow' | 'block' | 'kill';
export type Scope = 'once' | '1h' | '24h' | 'forever';
export type ApplyTo = 'file' | 'publisher';
export type SignatureStatus =
  | 'valid_embedded'
  | 'valid_catalog'
  | 'unsigned'
  | 'invalid'
  | 'expired'
  | 'revoked'
  | 'untrusted_root';

export interface Identity {
  id: string;
  sha256: string;
  path: string;
  publisher?: string | null;
  company?: string | null;
  product?: string | null;
  original_filename?: string | null;
  signature_status: SignatureStatus;
}

export interface Signal {
  id: string;
  name: string;
  delta: number;
  detail?: string;
}

export interface Evaluation {
  score: number;
  verdict: Verdict;
  signals: Signal[];
  hard_rule?: string | null;
  rule_pack_version: string;
}

export interface Destination {
  addr: string;
  port: number;
  dns_name?: string | null;
  dest_class: 'private' | 'public' | 'loopback';
}

export interface AiOpinion {
  verdict: Verdict;
  confidence: number;
  recommended_action: Action | 'ask_user';
  reasons: string[];
  indicators?: string[];
  model: string;
}

export type AiSource = 'own_key' | 'shared';

export type AiMode = 'off' | 'advisor' | 'auto';

/** `ai.config.get` result. The API key is write-only: only `has_key` is ever returned. */
export interface AiConfig {
  enabled: boolean;
  mode: AiMode;
  model: string;
  escalation_model: string;
  has_key: boolean;
  source: AiSource;
  /** True only in builds that ship a shared AI endpoint. */
  shared_available: boolean;
  auto_threshold: number;
  escalate_below: number;
  auto_kill: boolean;
  send_cmdline: boolean;
  daily_call_budget: number;
  calls_today: number;
}

export interface AiUsage {
  assessed: number;
  calls: number;
  cached: number;
  tokens_in: number;
  tokens_out: number;
  allowed: number;
  blocked: number;
  killed: number;
  left_to_user: number;
  cost_usd: number;
}

/** `ai.activity` result. Tokens come from the API; the dollar figure is an estimate. */
export interface AiActivityData {
  today: AiUsage;
  week: AiUsage;
  month: AiUsage;
}

export interface PendingItem {
  id: string;
  identity: Identity;
  evaluation: Evaluation;
  process?: ProcessInfo | null;
  destination: Destination;
  ai_opinion?: AiOpinion | null;
  created_at: string;
  /** Established incident: may interrupt the user. Otherwise the item waits in the list. */
  alert?: boolean;
}

export interface DecisionParams {
  pending_id: string;
  action: Action;
  scope: Scope;
  apply_to: ApplyTo;
}

/** `decision.list` item: a stored decision plus what is needed to review a kill. */
/** A killed program the user just reopened: frozen until answered or until the deadline kills it. */
export interface ReopenPrompt {
  pid: number;
  start_time: string;
  path: string;
  answer_within_secs: number;
  decision: DecisionItem | null;
  /** Epoch ms the prompt reached this window (the countdown base). */
  received_at?: number;
}

/** A program calls the same Internet address at a machine-regular interval (`docs/24`). */
export interface ThreatPrompt {
  threat_id: string;
  kind: 'beaconing';
  path: string;
  identity_id: string | null;
  dest_ip: string;
  dest_port: number;
  interval_secs: number;
  detected_at: string;
  /** AI analysis is configured; otherwise only block or ignore are offered. */
  ai_available: boolean;
}

/** A program keeps starting something Vigil stopped: ask what to do about the launcher. */
export interface LauncherPrompt {
  launcher: string;
  child: string;
  count: number;
  window_secs: number;
  autostart_entries: number;
  decision: DecisionItem | null;
}

export interface DecisionItem {
  id: string;
  identity_id: string;
  action: Action;
  scope: Scope;
  apply_to: ApplyTo;
  by: string;
  note?: string | null;
  created_at: string;
  identity: { path: string; publisher?: string | null; product?: string | null; signature_status: SignatureStatus } | null;
  evaluation: { score: number; verdict: Verdict; hard_rule?: string | null; signals: Signal[] } | null;
  ai_opinion?: AiOpinion | null;
  respawn_kills: number;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  kind: string;
  target?: string | null;
  details: Record<string, unknown>;
  hash: string;
}

export interface ActionResult {
  ok: boolean;
  error_code?: string | null;
  detail?: string | null;
}

export type PersistenceStatus = 'found' | 'disabled' | 'deleted' | 'restored';

export interface PersistenceItem {
  id: string;
  kind: string;
  location: string;
  image_path?: string | null;
  command?: string | null;
  status: PersistenceStatus;
  risk_note?: string | null;
  first_seen: string;
}

export interface AuditPage {
  items: AuditEntry[];
  next_cursor?: string | null;
  chain_ok: boolean;
}

export interface LockdownHeld {
  name: string;
  path: string;
  identity_id?: string | null;
  verdict?: Verdict | null;
  score?: number | null;
  publisher?: string | null;
  parent?: string | null;
  origin?: string | null;
  killed_at: string;
  respawns: number;
  last_respawn?: string | null;
  flagged: boolean;
  /** Advisor opinion once the program kept coming back; `unavailable` when it could not be asked. */
  ai?: (Partial<AiOpinion> & { unavailable?: string }) | null;
}

export interface LockdownReport {
  active: boolean;
  started_at?: string;
  window_s?: number;
  remaining_s?: number;
  stopped?: number;
  respawns?: number;
  flagged?: number;
  spared: Record<string, number>;
  kept: { name: string; path?: string | null; why: string }[];
  held: LockdownHeld[];
}
