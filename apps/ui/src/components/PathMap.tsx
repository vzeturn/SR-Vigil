import { AppWindow, ArrowDown, FileCode2, GitBranch, Globe, ShieldCheck, ShieldOff } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { countryName } from '../countries';
import { fetchDetail, type ProcessDetail } from '../processDetail';
import type { ConnectionInfo, ProcessInfo } from '../types';
import { LoadedFiles } from './LoadedFiles';
import { ScoreBar } from './ScoreBar';
import { ScoreTip } from './ScoreTip';
import { VerdictChip } from './VerdictChip';

const endpoint = (c: ConnectionInfo) =>
  `${c.dns_name ?? c.remote_addr ?? '-'}${c.remote_port ? `:${c.remote_port}` : ''}`;

/** Full picture for one program: where it sits in the process tree, who signed it, what it talks to. */
export function PathMap({ proc, conn }: { proc: ProcessInfo; conn?: ConnectionInfo }) {
  const { t } = useTranslation();
  const [d, setD] = useState<ProcessDetail | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let live = true;
    fetchDetail(proc.pid, proc.start_time)
      .then((x) => live && setD(x))
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
    };
  }, [proc.pid, proc.start_time]);

  if (failed) return <p className="muted">{t('pathmap.unavailable')}</p>;
  if (!d) return <p className="muted">{t('table.loading')}</p>;

  const id = d.identity;
  const signed = id.signature_status.startsWith('valid');
  const tree = [...d.parent_chain].reverse();
  return (
    <ol className="pathmap">
      {conn && (
        <li>
          <span className="pathmap-kind">
            <Globe size={12} aria-hidden="true" />
            {t('pathmap.connection')}
          </span>
          <span className="pathmap-main mono">
            {conn.proto.toUpperCase()} {conn.direction === 'outbound' ? '→' : '←'} {endpoint(conn)}
          </span>
          <span className="pathmap-sub">
            {[countryName(conn.country), conn.state, conn.blocked ? t('pathmap.blocked') : null]
              .filter(Boolean)
              .join(' · ')}
          </span>
        </li>
      )}
      <li>
        <span className="pathmap-kind">
          <AppWindow size={12} aria-hidden="true" />
          {t('pathmap.program')}
        </span>
        <span className="pathmap-main">
          <ScoreTip score={d.evaluation.score} verdict={d.evaluation.verdict} pid={proc.pid} startTime={proc.start_time}>
            <ScoreBar score={d.evaluation.score} verdict={d.evaluation.verdict} />
          </ScoreTip>
          <strong>{proc.name}</strong> <span className="muted mono">{proc.pid}</span>
          <VerdictChip verdict={d.evaluation.verdict} />
        </span>
        <span className="pathmap-sub mono">{id.path}</span>
      </li>
      <li>
        <span className="pathmap-kind">
          {signed ? <ShieldCheck size={12} aria-hidden="true" /> : <ShieldOff size={12} aria-hidden="true" />}
          {t('pathmap.origin')}
        </span>
        <span className="pathmap-main">
          {id.publisher ?? id.company ?? t('pathmap.unsigned')}
          {id.product ? ` · ${id.product}` : ''}
        </span>
        <span className="pathmap-sub">
          {t(`signature.${id.signature_status}`)} · <span className="mono">{id.sha256.slice(0, 16)}</span>
        </span>
      </li>
      {tree.length > 0 && (
        <li>
          <span className="pathmap-kind">
            <GitBranch size={12} aria-hidden="true" />
            {t('pathmap.launchedBy')}
          </span>
          <span className="pathmap-chain">
            {tree.map((p, i) => (
              <span key={`${p.pid}-${p.start_time}`} className="pathmap-node">
                {p.name}
                <span className="muted mono"> {p.pid}</span>
                {i < tree.length - 1 && <ArrowDown size={12} aria-hidden="true" className="pathmap-arrow" />}
              </span>
            ))}
          </span>
        </li>
      )}
      <li>
        <span className="pathmap-kind">
          <FileCode2 size={12} aria-hidden="true" />
          {t('pathmap.files')}
        </span>
        <LoadedFiles proc={proc} />
      </li>
    </ol>
  );
}
