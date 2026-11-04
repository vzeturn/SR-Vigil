import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { Dialog } from '../components/Dialog';
import { VirtualTable, type Column } from '../components/VirtualTable';
import type { ActionResult, PersistenceItem } from '../types';

type Action = 'disable' | 'restore' | 'delete';

export function Startup() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<PersistenceItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<PersistenceItem | null>(null);

  const scan = useCallback(async () => {
    try {
      const b = await getBridge();
      const r = await b.rpc<{ findings: PersistenceItem[] }>('persistence.scan', {});
      setRows(r.findings);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const apply = useCallback(
    async (item: PersistenceItem, action: Action) => {
      try {
        const b = await getBridge();
        const r = await b.rpc<ActionResult>('persistence.apply', { item_id: item.id, action });
        if (!r.ok) {
          setError(
            r.error_code === 'protected_target'
              ? t('startup.protected_target')
              : (r.detail ?? r.error_code ?? ''),
          );
          return;
        }
        await scan();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [scan, t],
  );

  const columns: Column<PersistenceItem>[] = [
    { header: t('startup.kind'), width: '140px', cell: (r) => r.kind },
    {
      header: t('startup.location'),
      width: '4fr',
      cell: (r) => <span className="mono">{r.location}</span>,
    },
    { header: t('startup.status'), width: '110px', cell: (r) => t(`startup.states.${r.status}`) },
    {
      header: '',
      width: '220px',
      cell: (r) => (
        <span className="row-actions">
          {r.status === 'disabled' ? (
            <>
              <button type="button" className="btn" onClick={() => void apply(r, 'restore')}>
                {t('startup.restore')}
              </button>
              <button type="button" className="btn danger" onClick={() => setConfirmDelete(r)}>
                {t('startup.delete')}
              </button>
            </>
          ) : (
            r.status !== 'deleted' && (
              <button type="button" className="btn" onClick={() => void apply(r, 'disable')}>
                {t('startup.disable')}
              </button>
            )
          )}
        </span>
      ),
    },
  ];

  return (
    <>
      <div className="toolbar">
        <button type="button" className="btn primary" onClick={() => void scan()}>
          {t('startup.scan')}
        </button>
        <span className="muted">{t('table.rows', { count: rows?.length ?? 0 })}</span>
      </div>
      {error && (
        <p className="card error" role="alert">
          {t('startup.error', { message: error })}
        </p>
      )}
      <VirtualTable
        rows={rows ?? []}
        columns={columns}
        rowKey={(r) => r.id}
        empty={t('startup.empty')}
        label={t('nav.startup')}
      />
      {confirmDelete && (
        <Dialog title={t('startup.deleteTitle')} onClose={() => setConfirmDelete(null)}>
          <p>{t('startup.deleteBody')}</p>
          <div className="actions">
            <button type="button" className="btn" onClick={() => setConfirmDelete(null)}>
              {t('kill.cancel')}
            </button>
            <button
              type="button"
              className="btn danger"
              onClick={() => {
                const it = confirmDelete;
                setConfirmDelete(null);
                void apply(it, 'delete');
              }}
            >
              {t('startup.delete')}
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
