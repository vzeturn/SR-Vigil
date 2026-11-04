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
