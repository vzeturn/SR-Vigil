import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { hidePopup } from '../bridge';
import { answerThreat, vigilState, type ThreatAction } from '../store';
import type { AiOpinion, ThreatPrompt } from '../types';
import { AiAssessment } from './AiAssessment';
import { useFitPopup } from './useFitPopup';

const base = (p: string) => p.split(/[\\/]/).pop() ?? p;

/** Suspicious network pattern: nothing reaches the AI until the user presses "Analyze" (`docs/24 §3`). */
export function ThreatView({ prompt }: { prompt: ThreatPrompt }) {
  const { t } = useTranslation();
  const box = useRef<HTMLDivElement>(null);
  useFitPopup(box);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [opinion, setOpinion] = useState<AiOpinion | null>(null);
  const every =
    prompt.interval_secs < 120
      ? t('threat.everySecs', { n: prompt.interval_secs })
      : t('threat.everyMins', { n: Math.round(prompt.interval_secs / 60) });

  const answer = async (action: ThreatAction) => {
    setBusy(true);
    setFailed(false);
    try {
      const o = await answerThreat(prompt, action);
      if (o) setOpinion(o);
      else if (vigilState().threats.length === 0) void hidePopup();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div ref={box} className="popup threat" role="alertdialog" aria-label={t('threat.title')} aria-busy={busy}>
      <span className="chip unknown">{t('threat.title')}</span>
      <strong>{t('threat.headline', { name: base(prompt.path), every })}</strong>
      <div className="mono muted">{prompt.path}</div>
      <div className="mono">
        {prompt.dest_ip}:{prompt.dest_port}
      </div>
      {opinion ? (
        <AiAssessment opinion={opinion} compact />
      ) : (
        <>
          <p>{t('threat.body')}</p>
          <p className="muted">{prompt.ai_available ? t('threat.consent') : t('threat.aiOff')}</p>
        </>
      )}
      {failed && (
        <div className="muted" role="status">
          {t('threat.failed')}
        </div>
      )}
      <div className="toolbar">
        <button type="button" className="btn" disabled={busy} onClick={() => void answer('dismiss')}>
          {t('threat.dismiss')}
        </button>
        <span className="spacer" />
        {prompt.ai_available && !opinion && (
          <button type="button" className="btn" disabled={busy} onClick={() => void answer('analyze')}>
            {busy ? t('threat.analyzing') : t('threat.analyze')}
          </button>
        )}
        <button type="button" className="btn block" disabled={busy} onClick={() => void answer('block')}>
          {t('threat.block')}
        </button>
      </div>
    </div>
  );
}
