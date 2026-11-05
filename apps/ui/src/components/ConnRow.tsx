import { ChevronRight } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ConnectionInfo, ProcessInfo } from '../types';
import { PathMap } from './PathMap';
import { ScoreBar } from './ScoreBar';
import { ScoreTip } from './ScoreTip';

/** One connection with its owning program's score; expands into the full path map. */
export function ConnRow({ conn, proc }: { conn: ConnectionInfo; proc?: ProcessInfo }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const host = conn.dns_name ?? conn.remote_addr ?? '-';
  return (
    <li className="connrow">
      <button type="button" className="expander" aria-expanded={open} disabled={!proc} onClick={() => setOpen(!open)}>
        <ChevronRight size={14} aria-hidden="true" className="chev" />
        <span className="connrow-main">
          <span>{proc?.name ?? `pid ${conn.pid}`}</span>
          <span className="muted mono">
            {host}
            {conn.remote_port ? `:${conn.remote_port}` : ''}
          </span>
        </span>
        {proc && (
          <ScoreTip score={proc.score} verdict={proc.verdict} pid={proc.pid} startTime={proc.start_time} program={proc.name}>
            <ScoreBar score={proc.score} verdict={proc.verdict} />
          </ScoreTip>
        )}
      </button>
      {open && proc && (
        <div className="connrow-detail" aria-label={t('overview.details')}>
          <PathMap proc={proc} conn={conn} />
        </div>
      )}
    </li>
  );
}
