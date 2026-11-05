import { FileCode2, Lock } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { useVigil } from '../store';
import type { ProcessInfo } from '../types';

interface Modules {
  access: 'ok' | 'denied';
  items: { name: string; path: string }[];
  truncated: boolean;
}

/** Files a program has loaded. Read only when asked (one cheap snapshot), never polled. */
export function LoadedFiles({ proc }: { proc: ProcessInfo }) {
  const { t } = useTranslation();
  const { link } = useVigil();
  const [state, setState] = useState<Modules | 'loading' | 'failed' | null>(null);

  if (link.role !== 'admin') return <MissingPermission why={t('files.needAdmin')} />;
  if (state && typeof state === 'object' && state.access === 'denied') {
    return <MissingPermission why={t('files.denied')} />;
  }

  const load = () => {
    setState('loading');
    getBridge()
      .then((b) => b.rpc<Modules>('process.modules', { pid: proc.pid, start_time: proc.start_time }))
      .then(setState)
      .catch(() => setState('failed'));
  };

  if (state === null || state === 'failed' || state === 'loading') {
    return (
      <button type="button" className="btn" disabled={state === 'loading'} onClick={load}>
        <FileCode2 size={14} aria-hidden="true" />
        {state === 'loading' ? t('table.loading') : state === 'failed' ? t('files.retry') : t('files.show')}
      </button>
    );
  }
  return (
    <>
      <ul className="files">
        {state.items.map((f) => (
          <li key={f.path} title={f.path}>
            <FileCode2 size={12} aria-hidden="true" />
            <span>{f.name}</span>
            <span className="muted mono files-path">{f.path}</span>
          </li>
        ))}
      </ul>
      {state.truncated && <span className="pathmap-sub">{t('files.truncated')}</span>}
    </>
  );
}

function MissingPermission({ why }: { why: string }) {
  const { t } = useTranslation();
  return (
    <span className="chip unknown" role="status">
      <Lock size={12} aria-hidden="true" />
      {t('files.missing')}: {why}
    </span>
  );
}
