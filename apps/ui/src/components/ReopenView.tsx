import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { hidePopup } from '../bridge';
import { answerReopen } from '../store';
import type { ReopenPrompt } from '../types';
import { useFitPopup } from './useFitPopup';

/** "You reopened a program Vigil stopped": frozen until the user answers or the countdown ends. */
export function ReopenView({ prompt }: { prompt: ReopenPrompt }) {
  const { t } = useTranslation();
  const box = useRef<HTMLDivElement>(null);
  useFitPopup(box);
  const [left, setLeft] = useState(prompt.answer_within_secs);
  const [base] = useState(() => prompt.received_at ?? Date.now());

  useEffect(() => {
    const tick = () => setLeft(Math.max(0, prompt.answer_within_secs - Math.floor((Date.now() - base) / 1000)));
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [base, prompt.answer_within_secs]);

  const answer = (allow: boolean) => {
    void answerReopen(prompt, allow).finally(() => void hidePopup());
  };
  const reasons = prompt.decision?.evaluation?.signals.slice(0, 3) ?? [];
  const name = prompt.path.split(/[\\/]/).pop() ?? prompt.path;

  return (
    <div ref={box} className="popup" role="alertdialog" aria-label={t('reopen.title')}>
      <div className="toolbar">
        <strong className="grow">{t('reopen.headline', { name })}</strong>
      </div>
      <div className="mono muted">{prompt.path}</div>
      <div>{t('reopen.body')}</div>
      {reasons.length > 0 && (
        <ul className="list">
          {reasons.map((s) => (
            <li key={s.id}>
              <span>{s.name}</span>
              <span className="mono">{s.delta > 0 ? `+${s.delta}` : s.delta}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="toolbar">
        <span className="muted" aria-live="polite">
          {t('reopen.countdown', { n: left })}
        </span>
        <span className="spacer" />
        <button type="button" className="btn" onClick={() => answer(false)}>
          {t('reopen.keep')}
        </button>
        <button type="button" className="btn primary" onClick={() => answer(true)}>
          {t('reopen.allow')}
        </button>
      </div>
    </div>
  );
}
