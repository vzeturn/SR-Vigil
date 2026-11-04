import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { DecisionControls } from '../components/DecisionControls';
import { destinationText, itemName } from '../components/pendingView';
import { ReviewWizard } from '../components/ReviewWizard';
import { VerdictChip } from '../components/VerdictChip';
import { refreshPending, useVigil } from '../store';

export function Pending() {
  const { t } = useTranslation();
  const { pending, pendingError } = useVigil();
  const [reviewing, setReviewing] = useState<string | null>(null);
  const current = pending?.find((p) => p.id === reviewing);

  if (pendingError && !pending) {
    return (
      <div className="card" role="alert">
        <p>{t('pending.error', { message: pendingError })}</p>
        <button type="button" className="btn" onClick={() => void refreshPending()}>
          {t('common.retry')}
        </button>
      </div>
    );
  }
  if (!pending) return <p className="muted">{t('table.loading')}</p>;
  if (pending.length === 0) return <p className="card muted">{t('pending.empty')}</p>;

  return (
    <>
      <ul className="stack" aria-label={t('nav.pending')}>
        {pending.map((p) => (
          <li key={p.id} className="card pending-row">
            <div className="pending-info">
              <div className="toolbar">
                <strong>{itemName(p)}</strong>
                <VerdictChip verdict={p.evaluation.verdict} />
                <span className="muted">{t('pending.score', { score: p.evaluation.score })}</span>
              </div>
              <div className="mono muted">{p.identity.path}</div>
              <div className="muted">
                {t('pending.publisher')}: {p.identity.publisher ?? t('pending.noPublisher')}
              </div>
              <div className="muted">
                {t('pending.destination')}: <span className="mono">{destinationText(p)}</span>
              </div>
              <div>
                <button type="button" className="btn" onClick={() => setReviewing(p.id)}>
                  {t('pending.review')}
                </button>
              </div>
            </div>
            <DecisionControls item={p} />
          </li>
        ))}
      </ul>
      {current && <ReviewWizard item={current} onClose={() => setReviewing(null)} />}
    </>
  );
}
