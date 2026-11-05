import { Sparkles } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import type { AiActivityData, AiConfig } from '../types';

const REFRESH_MS = 60_000;

/** What the AI did and what it cost, or a one-click way to switch it on. */
export function AiActivity() {
  const { t } = useTranslation();
  const [cfg, setCfg] = useState<AiConfig | null>(null);
  const [act, setAct] = useState<AiActivityData | null>(null);

  useEffect(() => {
    let live = true;
    const load = () =>
      getBridge()
        .then(async (b) => {
          const [c, a] = await Promise.all([b.rpc<AiConfig>('ai.config.get', {}), b.rpc<AiActivityData>('ai.activity', {})]);
          if (live) {
            // Keep the old objects when nothing changed so the card does not re-render.
            setCfg((o) => (JSON.stringify(o) === JSON.stringify(c) ? o : c));
            setAct((o) => (JSON.stringify(o) === JSON.stringify(a) ? o : a));
          }
        })
        .catch(() => undefined);
    void load();
    const id = setInterval(() => document.hidden || void load(), REFRESH_MS);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, []);

  if (!cfg) return null;
  const goSettings = () => window.dispatchEvent(new CustomEvent('vigil:goto', { detail: 'settings' }));
  const today = act?.today;
  const decisions = today ? today.allowed + today.blocked + today.killed : 0;
  const tokens = today ? today.tokens_in + today.tokens_out : 0;

  return (
    <section className="card ai-activity">
      <h2>
        <Sparkles size={16} aria-hidden="true" /> {t('aiact.title')}
      </h2>
      {!cfg.enabled || cfg.mode === 'off' ? (
        <>
          <p className="muted">{t('aiact.off')}</p>
          <button type="button" className="btn" onClick={goSettings}>
            {t('aiact.setup')}
          </button>
        </>
      ) : today && today.assessed > 0 ? (
        <>
          <p>{t('aiact.summary', { assessed: today.assessed, decisions, left: today.left_to_user })}</p>
          {tokens > 0 && <p className="muted">{t('aiact.cost', { tokens: tokens.toLocaleString('en-US'), cost: today.cost_usd.toFixed(3) })}</p>}
          {act && (
            <p className="muted">
              {t('aiact.month', {
                assessed: act.month.assessed,
                decisions: act.month.allowed + act.month.blocked + act.month.killed,
                cost: act.month.cost_usd.toFixed(2),
              })}
            </p>
          )}
          <progress max={cfg.daily_call_budget} value={cfg.calls_today} aria-label={t('aiact.budget', { used: cfg.calls_today, budget: cfg.daily_call_budget })} />
          <p className="muted">{t('aiact.budget', { used: cfg.calls_today, budget: cfg.daily_call_budget })}</p>
        </>
      ) : (
        <p className="muted">{t('aiact.quiet')}</p>
      )}
    </section>
  );
}
