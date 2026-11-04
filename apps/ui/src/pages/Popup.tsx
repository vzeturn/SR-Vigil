import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge, hidePopup } from '../bridge';
import type { AiOpinion } from '../types';
import { AiAssessment } from '../components/AiAssessment';
import { DecisionControls } from '../components/DecisionControls';
import { destinationText, itemName } from '../components/pendingView';
import { VerdictChip } from '../components/VerdictChip';
import { useVigil } from '../store';

/** Content of the always-on-top approval window. Esc or "Later" hides it; the item stays pending. */
export function Popup() {
  const { t } = useTranslation();
  const { pending } = useVigil();
  const [index, setIndex] = useState(0);
  const [armed, setArmed] = useState(false);
  const seen = useRef(0);

  const total = pending?.length ?? 0;
  const at = Math.min(index, Math.max(total - 1, 0));
  const item = pending?.[at];
  const [asked, setAsked] = useState<Record<string, AiOpinion>>({});
  const [asking, setAsking] = useState(false);
  const [aiError, setAiError] = useState(false);
  const opinion = item ? (item.ai_opinion ?? asked[item.identity.id]) : undefined;

  const askAi = async (identityId: string) => {
    setAsking(true);
    setAiError(false);
    try {
      const o = await (await getBridge()).rpc<AiOpinion>('ai.explain', { identity_id: identityId });
      setAsked((m) => ({ ...m, [identityId]: o }));
    } catch {
      setAiError(true);
    } finally {
      setAsking(false);
    }
  };

  useEffect(() => {
    // Queue drained after having items: nothing left to ask, so get out of the way.
    if (seen.current > 0 && total === 0) void hidePopup();
    seen.current = total;
  }, [total]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') void hidePopup();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="popup" onPointerDown={() => setArmed(true)} role="group" aria-label={t('popup.title')}>
      {!item ? (
        <p className="muted">{t('popup.empty')}</p>
      ) : (
        <>
          <div className="toolbar">
            <strong className="grow">{itemName(item)}</strong>
            <VerdictChip verdict={item.evaluation.verdict} />
            <span className="muted">{item.evaluation.score}</span>
          </div>
          <div className="mono muted">{item.identity.path}</div>
          <div>
            {t('popup.wants')} <span className="mono">{destinationText(item)}</span>
          </div>
          <ul className="list">
            {item.evaluation.signals.slice(0, 3).map((s) => (
              <li key={s.id}>
                <span>{s.name}</span>
                <span className="mono">{s.delta > 0 ? `+${s.delta}` : s.delta}</span>
              </li>
            ))}
          </ul>
          {opinion && <AiAssessment opinion={opinion} compact />}
          {!opinion && (
            <button type="button" className="btn" disabled={asking} onClick={() => void askAi(item.identity.id)}>
              {asking ? t('popup.aiAsking') : t('popup.aiAsk')}
            </button>
          )}
          {aiError && <div className="muted" role="status">{t('popup.aiUnavailable')}</div>}
          <DecisionControls key={item.id} item={item} shortcutsArmed={armed} />
        </>
      )}
      <div className="toolbar">
        <span className="muted" aria-live="polite">
          {t('popup.queue', { n: item ? at + 1 : 0, total })}
        </span>
        <button type="button" className="btn" disabled={total < 2} onClick={() => setIndex((at + 1) % total)}>
          {t('popup.next')}
        </button>
        <span className="spacer" />
        <button type="button" className="btn" onClick={() => void hidePopup()}>
          {t('popup.later')}
        </button>
      </div>
    </div>
  );
}
