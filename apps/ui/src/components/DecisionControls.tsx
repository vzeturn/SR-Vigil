import { Ban, Check, Skull } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { refreshPending, useVigil } from '../store';
import type { Action, ApplyTo, PendingItem, Scope } from '../types';
import { hasPublisher } from './pendingView';

const SCOPES: readonly Scope[] = ['once', '1h', '24h', 'forever'];
const ICONS = { allow: Check, block: Ban, kill: Skull } as const;

interface Props {
  item: PendingItem;
  onDone?: () => void;
  /** `A` / `B` / `K` shortcuts; the caller arms them only after a click inside its window. */
  shortcutsArmed?: boolean;
}

/**
 * Scope and apply-to selectors plus Allow / Block / Kill. No action is ever pre-selected:
 * each button is an explicit, immediate choice (Kill asks for one more click).
 */
export function DecisionControls({ item, onDone, shortcutsArmed = false }: Props) {
  const { t } = useTranslation();
  const { link } = useVigil();
  const [scope, setScope] = useState<Scope>('once');
  const [applyTo, setApplyTo] = useState<ApplyTo>('file');
  const [confirmKill, setConfirmKill] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isAdmin = link.role === 'admin';
  const publisherOk = hasPublisher(item);

  const submit = useCallback(async (action: Action) => {
    if (action === 'kill' && !confirmKill) {
      setConfirmKill(true);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const b = await getBridge();
      await b.rpc('decision.submit', {
        pending_id: item.id,
        action,
        scope,
        apply_to: publisherOk ? applyTo : 'file',
      });
      await refreshPending();
      onDone?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [confirmKill, scope, applyTo, publisherOk, item.id, onDone]);

  const enabled = isAdmin && !busy;

  useEffect(() => {
    if (!shortcutsArmed || !enabled) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || e.target instanceof HTMLSelectElement) return;
      const action = ({ a: 'allow', b: 'block', k: 'kill' } as const)[e.key.toLowerCase() as 'a' | 'b' | 'k'];
      if (action) void submit(action);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [shortcutsArmed, enabled, submit]);

  return (
    <div className="decision">
      <div className="decision-fields">
        <label className="field">
          <span className="muted">{t('decision.scope')}</span>
          <select
            value={scope}
            disabled={!enabled}
            onChange={(e) => {
              setScope(e.target.value as Scope);
              setConfirmKill(false);
            }}
          >
            {SCOPES.map((s) => (
              <option key={s} value={s}>
                {t(`decision.scopes.${s}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="muted">{t('decision.applyTo')}</span>
          <select
            value={publisherOk ? applyTo : 'file'}
            disabled={!enabled}
            onChange={(e) => setApplyTo(e.target.value as ApplyTo)}
          >
            <option value="file">{t('decision.applyFile')}</option>
            <option value="publisher" disabled={!publisherOk}>
              {t('decision.applyPublisher')}
            </option>
          </select>
        </label>
      </div>
      <div className="decision-actions" role="group" aria-label={t('decision.actions')}>
        {(['allow', 'block', 'kill'] as const).map((a) => {
          const Icon = ICONS[a];
          const confirming = a === 'kill' && confirmKill;
          return (
            <button
              key={a}
              type="button"
              className={`btn ${a}`}
              disabled={!enabled}
              title={isAdmin ? undefined : t('decision.adminOnly')}
              onClick={() => void submit(a)}
            >
              <Icon size={16} aria-hidden="true" />
              {confirming ? t('decision.confirmKill') : t(`decision.${a}`)}
            </button>
          );
        })}
      </div>
      {!isAdmin && <p className="muted note">{t('decision.adminOnly')}</p>}
      {error && (
        <p className="error" role="alert">
          {t('decision.error', { message: error })}
        </p>
      )}
    </div>
  );
}
