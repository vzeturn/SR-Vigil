import { Ban, Check, Skull } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { useVigil } from '../store';
import type { ProcessInfo } from '../types';
import { KillDialog } from './KillDialog';

/**
 * One-click decisions for a running process: Allow / Block remember the exact file (hash + path)
 * and can be undone in Rules & Trust; Kill asks for confirmation. Safe programs only offer Kill.
 */
export function ProcessActions({ proc }: { proc: ProcessInfo }) {
  const { t } = useTranslation();
  const { link } = useVigil();
  const [killing, setKilling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isAdmin = link.role === 'admin';
  const decidable = proc.verdict !== 'safe' && !!proc.identity_id;

  const decide = (action: 'allow' | 'block') => {
    setError(null);
    getBridge()
      .then((b) =>
        b.rpc('decision.submit', {
          identity_id: proc.identity_id,
          action,
          scope: 'forever',
          apply_to: 'file',
        }),
      )
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  };

  const btn = (kind: 'allow' | 'block' | 'kill', Icon: typeof Check, onClick: () => void) => (
    <button
      type="button"
      className={`btn icon ${kind}`}
      disabled={!isAdmin}
      aria-label={t(`act.${kind}For`, { name: proc.name })}
      title={isAdmin ? t(`act.${kind}Hint`) : t('link.viewer')}
      onClick={onClick}
    >
      <Icon size={16} aria-hidden="true" />
    </button>
  );

  return (
    <span className="row-actions">
      {decidable && btn('allow', Check, () => decide('allow'))}
      {decidable && btn('block', Ban, () => decide('block'))}
      {btn('kill', Skull, () => setKilling(true))}
      {error && (
        <span className="error" role="alert">
          {t('decision.error', { message: error })}
        </span>
      )}
      {killing && <KillDialog proc={proc} onClose={() => setKilling(false)} />}
    </span>
  );
}
