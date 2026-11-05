import { getBridge } from './bridge';
import type { ConnectionInfo, Evaluation, Identity, ProcessInfo } from './types';

export interface ProcessDetail {
  process: ProcessInfo;
  identity: Identity;
  evaluation: Evaluation;
  parent_chain: ProcessInfo[];
  connections: ConnectionInfo[];
}

const cache = new Map<string, Promise<ProcessDetail>>();

/** One `process.get` per process, shared by every hover card and expanded row. */
export function fetchDetail(pid: number, startTime: string): Promise<ProcessDetail> {
  const key = `${pid}:${startTime}`;
  let hit = cache.get(key);
  if (!hit) {
    hit = getBridge()
      .then((b) => b.rpc<ProcessDetail>('process.get', { pid, start_time: startTime }))
      .catch((e: unknown) => {
        cache.delete(key);
        throw e;
      });
    cache.set(key, hit);
  }
  return hit;
}
