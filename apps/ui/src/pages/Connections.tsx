import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { VerdictChip } from '../components/VerdictChip';
import { VirtualTable, type Column } from '../components/VirtualTable';
import { useVigil } from '../store';
import type { ConnectionInfo } from '../types';

export function Connections() {
  const { t } = useTranslation();
  const { snapshot } = useVigil();
  const rows = snapshot?.connections ?? [];
  const names = useMemo(
    () => new Map((snapshot?.processes ?? []).map((p) => [p.pid, p.name])),
    [snapshot],
  );

  const columns: Column<ConnectionInfo>[] = [
    { header: t('table.process'), width: '2fr', cell: (c) => names.get(c.pid) ?? c.pid },
    { header: t('table.local'), width: '2fr', cell: (c) => <span className="mono">{c.local_addr}:{c.local_port}</span> },
    {
      header: t('table.remote'),
      width: '3fr',
      cell: (c) => (
        <span className="mono">
          {c.dns_name ?? c.remote_addr ?? ''}
          {c.remote_port ? `:${c.remote_port}` : ''}
        </span>
      ),
    },
    { header: t('table.state'), width: '130px', cell: (c) => c.state ?? '' },
    { header: t('table.verdict'), width: '150px', cell: (c) => <VerdictChip verdict={c.verdict} /> },
  ];

  return (
    <>
      <div className="toolbar">
        <span className="muted">{t('table.rows', { count: rows.length })}</span>
      </div>
      <VirtualTable
        rows={rows}
        columns={columns}
        rowKey={(c) => c.id}
        empty={snapshot ? t('table.empty') : t('table.loading')}
        label={t('nav.connections')}
      />
    </>
  );
}
