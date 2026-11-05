import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import type { AiOpinion, DecisionItem } from '../types';

export function Kills() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<DecisionItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    try {
      const b = await getBridge();
      const r = await b.rpc<{ items: DecisionItem[] }>('decision.list');
      setRows(r.items.filter((d) => d.action === 'kill'));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    // State is set only after the awaited service call, never synchronously.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  const act = async (method: 'decision.revoke' | 'decision.exception', id: string) => {
    try {
      await (await getBridge()).rpc(method, { decision_id: id });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const review = async (d: DecisionItem) => {
    setNotes((n) => ({ ...n, [d.id]: t('kills.reviewing') }));
    try {
      const o = await (await getBridge()).rpc<AiOpinion>('ai.explain', { identity_id: d.identity_id });
      const text = t('kills.reviewed', {
        verdict: t(`verdict.${o.verdict}`),
        confidence: Math.round(o.confidence * 100),
        reason: o.reasons[0] ?? '',
      });
      setNotes((n) => ({ ...n, [d.id]: text }));
    } catch {
      setNotes((n) => ({ ...n, [d.id]: t('kills.reviewOff') }));
    }
  };

  if (error) return <p role="alert">{t('kills.error', { message: error })}</p>;
  if (!rows) return <p className="muted">{t('table.loading')}</p>;
  if (rows.length === 0) return <p className="muted">{t('kills.empty')}</p>;

  return (
    <>
      {rows.map((d) => (
        <section className="card" key={d.id}>
          <h2 className="mono">{d.identity?.path ?? d.identity_id}</h2>
          <p className="muted">
            {t('kills.decidedBy', { by: d.by, when: d.created_at })}
            {d.identity?.publisher ? ` · ${d.identity.publisher}` : ''}
          </p>
          {d.evaluation && (
            <>
              <p>{t('kills.score', { score: d.evaluation.score, verdict: t(`verdict.${d.evaluation.verdict}`) })}</p>
              <ul className="list">
                {d.evaluation.signals.length === 0 && <li>{t('kills.noReasons')}</li>}
                {d.evaluation.signals.map((s) => (
                  <li key={s.id}>
                    <span>
                      <span className="mono">{s.id}</span> {s.name}
                    </span>
                    <span className="mono">{s.delta > 0 ? `+${s.delta}` : s.delta}</span>
                  </li>
                ))}
              </ul>
              {d.evaluation.hard_rule && <p>{t('kills.hardRule', { rule: d.evaluation.hard_rule })}</p>}
            </>
          )}
          {d.ai_opinion && (
            <p>
              {t('kills.aiSays', {
                verdict: t(`verdict.${d.ai_opinion.verdict}`),
                confidence: Math.round(d.ai_opinion.confidence * 100),
              })}
              {d.ai_opinion.reasons[0] ? ` ${d.ai_opinion.reasons[0]}` : ''}
            </p>
          )}
          {d.respawn_kills > 0 && <p>{t('kills.respawns', { count: d.respawn_kills })}</p>}
          {notes[d.id] && <p role="status">{notes[d.id]}</p>}
          <div className="toolbar">
            <button type="button" className="btn" onClick={() => void act('decision.revoke', d.id)}>
              {t('kills.lift')}
            </button>
            <button type="button" className="btn" onClick={() => void act('decision.exception', d.id)}>
              {t('kills.except')}
            </button>
            <button type="button" className="btn" onClick={() => void review(d)}>
              {t('kills.review')}
            </button>
          </div>
        </section>
      ))}
    </>
  );
}
