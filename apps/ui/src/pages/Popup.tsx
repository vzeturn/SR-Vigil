import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge, hidePopup } from '../bridge';
import type { AiOpinion } from '../types';
import { AiAssessment } from '../components/AiAssessment';
import { DecisionControls } from '../components/DecisionControls';
import { destinationText, hasConnection, itemName } from '../components/pendingView';
import { ScoreBar } from '../components/ScoreBar';
import { ScoreTip } from '../components/ScoreTip';
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
  // Identity whose "Ask AI" failed: the notice belongs to that item, not to the next one.
  const [aiFailed, setAiFailed] = useState<string | null>(null);
  const opinion = item ? (item.ai_opinion ?? asked[item.identity.id]) : undefined;

  const askAi = async (identityId: string) => {
    setAsking(true);
    setAiFailed(null);
    try {
      const o = await (await getBridge()).rpc<AiOpinion>('ai.explain', { identity_id: identityId });
      setAsked((m) => ({ ...m, [identityId]: o }));
    } catch {
      setAiFailed(identityId);
    } finally {
      setAsking(false);
    }
  };

  useEffect(() => {
    // Shown with nothing to decide (already handled elsewhere): close itself after a short grace.
    if (!pending || total > 0) return;
    const id = window.setTimeout(() => void hidePopup(), 1500);
    return () => window.clearTimeout(id);
  }, [pending, total]);

  useEffect(() => {
    // Queue drained after having items: nothing left to ask, so get out of the way.
    if (seen.current > 0 && total === 0) void hidePopup();
    seen.current = total;
  }, [total]);

  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // Keep the window exactly as tall as its content so it never covers more screen than needed.
    const el = box.current;
    if (!el || !('__TAURI_INTERNALS__' in window)) return;
    const fit = () => {
      void import('@tauri-apps/api/core').then(({ invoke }) =>
        invoke('fit_popup', { height: Math.ceil(el.getBoundingClientRect().height) }),
      );
    };
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') void hidePopup();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div ref={box} className="popup" onPointerDown={() => setArmed(true)} role="group" aria-label={t('popup.title')}>
      {!item ? (
        <p className="muted">{t('popup.empty')}</p>
      ) : (
        <>
          <div className="toolbar">
            <strong className="grow">{itemName(item)}</strong>
            <VerdictChip verdict={item.evaluation.verdict} />
            <ScoreTip evaluation={item.evaluation} score={item.evaluation.score} verdict={item.evaluation.verdict}>
              <ScoreBar score={item.evaluation.score} verdict={item.evaluation.verdict} />
            </ScoreTip>
          </div>
          <div className="mono muted">{item.identity.path}</div>
          <div>
            {hasConnection(item) ? `${t('popup.wants')} ` : ''}
            <span className="mono">{destinationText(item)}</span>
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
          {item && aiFailed === item.identity.id && !opinion && <div className="muted" role="status">{t('popup.aiUnavailable')}</div>}
          <DecisionControls key={item.id} item={item} shortcutsArmed={armed} />
        </>
      )}
      <div className="toolbar">
        <span className="muted" aria-live="polite">
          {t('popup.queue', { n: item ? at + 1 : 0, total })}
        </span>
        <button type="button" className="btn" disabled={total < 2} onClick={() => setIndex((at + total - 1) % total)}>
          {t('popup.previous')}
        </button>
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
