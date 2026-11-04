import { useDeferredValue, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { KillDialog } from '../components/KillDialog';
import { VerdictChip } from '../components/VerdictChip';
import { VirtualTable, type Column } from '../components/VirtualTable';
import { useVigil } from '../store';
import type { ProcessInfo, Verdict } from '../types';

export function Processes() {
  const { t } = useTranslation();
  const { snapshot } = useVigil();
  const [query, setQuery] = useState('');
  const [verdict, setVerdict] = useState<Verdict | ''>('');
  const [target, setTarget] = useState<ProcessInfo | null>(null);
  const deferred = useDeferredValue(query);

  const rows = useMemo(() => {
    const q = deferred.trim().toLowerCase();
    return (snapshot?.processes ?? []).filter(
      (p) =>
        (!verdict || p.verdict === verdict) &&
        (!q || p.name.toLowerCase().includes(q) || (p.path ?? '').toLowerCase().includes(q)),
    );
  }, [snapshot, deferred, verdict]);

  const columns: Column<ProcessInfo>[] = [
    { header: t('table.name'), width: '2fr', cell: (p) => p.name },
    { header: t('table.pid'), width: '80px', cell: (p) => <span className="mono">{p.pid}</span> },
    { header: t('table.score'), width: '70px', cell: (p) => p.score ?? '' },
    { header: t('table.verdict'), width: '150px', cell: (p) => <VerdictChip verdict={p.verdict} /> },
    {
      header: '',
      width: '90px',
      cell: (p) => (
        <button type="button" className="btn" onClick={() => setTarget(p)}>
          {t('kill.action')}
        </button>
      ),
    },
    { header: t('table.path'), width: '3fr', cell: (p) => <span className="mono">{p.path ?? ''}</span> },
  ];

  return (
    <>
      <div className="toolbar">
        <input
          type="search"
          aria-label={t('table.search')}
          placeholder={t('table.search')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <select
          aria-label={t('table.allVerdicts')}
          value={verdict}
          onChange={(e) => setVerdict(e.target.value as Verdict | '')}
        >
          <option value="">{t('table.allVerdicts')}</option>
          {(['safe', 'unknown', 'malicious'] as const).map((v) => (
            <option key={v} value={v}>
              {t(`verdict.${v}`)}
            </option>
          ))}
        </select>
        <span className="muted">{t('table.rows', { count: rows.length })}</span>
      </div>
      <VirtualTable
        rows={rows}
        columns={columns}
        rowKey={(p) => `${p.pid}-${p.start_time}`}
        empty={snapshot ? t('table.empty') : t('table.loading')}
        label={t('nav.processes')}
      />
      {target && <KillDialog proc={target} onClose={() => setTarget(null)} />}
    </>
  );
}
