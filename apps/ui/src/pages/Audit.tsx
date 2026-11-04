import { ShieldAlert, ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { VirtualTable, type Column } from '../components/VirtualTable';
import type { AuditEntry, AuditPage } from '../types';

const PAGE = 500;

export function Audit() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<AuditEntry[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [chainOk, setChainOk] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (after: string | null) => {
    try {
      const b = await getBridge();
      const page = await b.rpc<AuditPage>('audit.query', after ? { limit: PAGE, cursor: after } : { limit: PAGE });
      setRows((prev) => (after && prev ? [...prev, ...page.items] : page.items));
      setCursor(page.next_cursor ?? null);
      setChainOk(page.chain_ok);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    // State is set only after the awaited service call, never synchronously.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load(null);
  }, [load]);

  const columns: Column<AuditEntry>[] = [
    { header: t('audit.seq'), width: '70px', cell: (r) => <span className="mono">{r.seq}</span> },
    { header: t('audit.time'), width: '190px', cell: (r) => <span className="mono">{r.ts}</span> },
    { header: t('audit.actor'), width: '1fr', cell: (r) => r.actor },
    { header: t('audit.kind'), width: '2fr', cell: (r) => r.kind },
    { header: t('audit.target'), width: '2fr', cell: (r) => <span className="mono">{r.target ?? ''}</span> },
    { header: t('audit.hash'), width: '140px', cell: (r) => <span className="mono">{r.hash.slice(0, 12)}</span> },
  ];

  const Icon = chainOk === false ? ShieldAlert : ShieldCheck;
  return (
    <>
      <div className="toolbar">
        {chainOk !== null && (
          <span className={`chip ${chainOk ? 'safe' : 'malicious'}`} role="status">
            <Icon size={14} aria-hidden="true" />
            {chainOk ? t('audit.chainOk') : t('audit.chainBroken')}
          </span>
        )}
        <button type="button" className="btn" onClick={() => void load(null)}>
          {t('common.refresh')}
        </button>
        {cursor && (
          <button type="button" className="btn" onClick={() => void load(cursor)}>
            {t('audit.more')}
          </button>
        )}
        <span className="muted">{t('table.rows', { count: rows?.length ?? 0 })}</span>
      </div>
      {chainOk === false && (
        <p className="card banner" role="alert">
          {t('audit.chainBrokenHelp')}
        </p>
      )}
      {error && (
        <p className="card error" role="alert">
          {t('audit.error', { message: error })}
        </p>
      )}
      <VirtualTable
        rows={rows ?? []}
        columns={columns}
        rowKey={(r) => String(r.seq)}
        empty={rows ? t('audit.empty') : error ? t('table.empty') : t('table.loading')}
        label={t('nav.audit')}
      />
    </>
  );
}
