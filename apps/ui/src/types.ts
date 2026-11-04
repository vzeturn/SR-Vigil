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
  verdict?: Verdict | null;
  score?: number | null;
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
  model: string;
}

export interface PendingItem {
  id: string;
  identity: Identity;
  evaluation: Evaluation;
  process?: ProcessInfo | null;
  destination: Destination;
  ai_opinion?: AiOpinion | null;
  created_at: string;
}

export interface DecisionParams {
  pending_id: string;
  action: Action;
  scope: Scope;
  apply_to: ApplyTo;
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
