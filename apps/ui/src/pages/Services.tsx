import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { VirtualTable, type Column } from '../components/VirtualTable';
import { useVigil } from '../store';
import type { ActionResult, ServiceItem } from '../types';

/** Windows services with their host process and `ServiceDll`; block one service's network (FR-021). */
export function Services() {
  const { t } = useTranslation();
  const { link } = useVigil();
  const isAdmin = link.role === 'admin';
  const [rows, setRows] = useState<ServiceItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchRows = useCallback(
    async () => (await getBridge()).rpc<{ items: ServiceItem[] }>('service.list', {}),
    [],
  );
  const show = useCallback((p: Promise<{ items: ServiceItem[] }>, live: () => boolean = () => true) => {
    p.then(
      (r) => {
        if (!live()) return;
        setRows(r.items);
        setError(null);
      },
      (e: unknown) => live() && setError(e instanceof Error ? e.message : String(e)),
    );
  }, []);
  const load = useCallback(() => show(fetchRows()), [fetchRows, show]);

  useEffect(() => {
    let live = true;
    show(fetchRows(), () => live);
    return () => {
      live = false;
    };
  }, [fetchRows, show]);

  const toggle = useCallback(
    async (s: ServiceItem) => {
      try {
        const b = await getBridge();
        const r = await b.rpc<ActionResult>('service.block_network', {
          name: s.name,
          block: !s.network_blocked,
        });
        if (!r.ok) {
          const code = r.error_code ?? '';
          setError(t(`services.refusal.${code}`, { defaultValue: r.detail ?? code }));
          return;
        }
        load();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [load, t],
  );

  const columns: Column<ServiceItem>[] = [
    {
      header: t('services.name'),
      width: '2fr',
      cell: (s) => (
        <span>
          {s.display_name}
          <span className="muted mono"> {s.name}</span>
          {s.suspicious && (
            <span className="chip malicious">{t(`services.suspicious.${s.suspicious}`)}</span>
          )}
        </span>
      ),
    },
    { header: t('services.pid'), width: '80px', cell: (s) => s.pid ?? t('services.stopped') },
    {
      header: t('services.dll'),
      width: '3fr',
      cell: (s) => <span className="mono">{s.dll ?? t('services.noDll')}</span>,
    },
    {
      header: t('services.sharedWith'),
      width: '2fr',
      cell: (s) => (s.shared_with.length ? s.shared_with.join(', ') : t('services.alone')),
    },
    {
      header: t('table.actions'),
      hideHeader: true,
      width: '200px',
      cell: (s) => {
        const why = !isAdmin
          ? t('services.adminOnly')
          : !s.network_blocked && s.refusal
            ? t(`services.refusal.${s.refusal}`)
            : undefined;
        return (
          <button
            type="button"
            className={s.network_blocked ? 'btn' : 'btn danger'}
            disabled={why !== undefined}
            title={why}
            aria-label={t(s.network_blocked ? 'services.unblockFor' : 'services.blockFor', {
              name: s.display_name,
            })}
            onClick={() => void toggle(s)}
          >
            {t(s.network_blocked ? 'services.unblock' : 'services.block')}
          </button>
        );
      },
    },
  ];

  return (
    <>
      <div className="toolbar">
        <button type="button" className="btn" onClick={load}>
          {t('common.refresh')}
        </button>
        <span className="muted">{t('table.rows', { count: rows?.length ?? 0 })}</span>
      </div>
      <p className="muted">{t('services.hint')}</p>
      {error && (
        <p className="card error" role="alert">
          {t('services.error', { message: error })}
        </p>
      )}
      <VirtualTable
        rows={rows ?? []}
        columns={columns}
        rowKey={(s) => s.name}
        empty={t('services.empty')}
        label={t('nav.services')}
      />
    </>
  );
}
