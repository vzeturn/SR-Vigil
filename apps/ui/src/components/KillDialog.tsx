import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import type { ActionResult, ProcessInfo } from '../types';
import { Dialog } from './Dialog';

/** Confirm-then-kill for one process; the service enforces the never-kill guard. */
export function KillDialog({ proc, onClose }: { proc: ProcessInfo; onClose: () => void }) {
  const { t } = useTranslation();
  const [tree, setTree] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    try {
      const b = await getBridge();
      const r = await b.rpc<ActionResult>('process.kill', {
        pid: proc.pid,
        start_time: proc.start_time,
        tree,
      });
      if (r.ok) onClose();
      else
        setMessage(
          r.error_code === 'protected_target'
            ? t('kill.protected_target')
            : t('kill.failed', { code: r.error_code ?? '' }),
        );
    } catch (e) {
      setMessage(t('kill.failed', { code: e instanceof Error ? e.message : String(e) }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog title={t('kill.title', { name: proc.name })} onClose={onClose}>
      <p>{t('kill.body', { pid: proc.pid })}</p>
      <label>
        <input type="checkbox" checked={tree} onChange={(e) => setTree(e.target.checked)} />{' '}
        {t('kill.tree')}
      </label>
      {message && (
        <p className="error" role="alert">
          {message}
        </p>
      )}
      <div className="actions">
        <button type="button" className="btn" onClick={onClose}>
          {t('kill.cancel')}
        </button>
        <button type="button" className="btn danger" disabled={busy} onClick={() => void run()}>
          {t('kill.confirm')}
        </button>
      </div>
    </Dialog>
  );
}
