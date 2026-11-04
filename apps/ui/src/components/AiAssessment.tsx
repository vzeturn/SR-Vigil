import { useTranslation } from 'react-i18next';
import type { AiOpinion } from '../types';

/** Compact, read-only summary of the AI's full assessment. Advice only; the user still decides. */
export function AiAssessment({ opinion, compact = false }: { opinion: AiOpinion; compact?: boolean }) {
  const { t } = useTranslation();
  const pct = Math.round(Math.min(Math.max(opinion.confidence, 0), 1) * 100);
  const shown = compact ? opinion.reasons.slice(0, 3) : opinion.reasons;
  const hidden = opinion.reasons.length - shown.length;
  const indicators = opinion.indicators ?? [];
  return (
    <section className={`ai-card ${opinion.verdict}`} aria-label={t('assess.title')}>
      <header className="ai-head">
        <span className="ai-spark" aria-hidden="true">✦</span>
        <strong className="grow">{t('assess.title')}</strong>
        <span className={`chip ${opinion.verdict}`}>{t(`verdict.${opinion.verdict}`)}</span>
      </header>
      <div className="ai-meter-row">
        <div
          className="ai-meter"
          role="meter"
          aria-label={t('assess.confidence')}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
        >
          <span style={{ width: `${pct}%` }} />
        </div>
        <span className="mono">{pct}%</span>
      </div>
      <div className="ai-advice">
        {t('assess.suggests')}{' '}
        <strong>
          {opinion.recommended_action === 'ask_user'
            ? t('assess.yourCall')
            : t(`decision.${opinion.recommended_action}`)}
        </strong>
      </div>
      <ul className="ai-reasons">
        {shown.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
      {hidden > 0 && <div className="muted">{t('assess.more', { n: hidden })}</div>}
      {indicators.length > 0 && (
        <div className="ai-tags">
          {indicators.map((i) => (
            <span key={i} className="chip mono">{i}</span>
          ))}
        </div>
      )}
      <div className="muted ai-foot">
        {t('assess.via', { model: opinion.model })} · {t('assess.note')}
      </div>
    </section>
  );
}
