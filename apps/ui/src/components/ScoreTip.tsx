import { OctagonAlert, ShieldCheck, ShieldQuestion } from 'lucide-react';
import { useCallback, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchDetail } from '../processDetail';
import type { Evaluation, Verdict } from '../types';

const BASELINE = 50;
const SAFE_MIN = 80;
const MALICIOUS_MAX = 29;

interface ScoreTipProps {
  score?: number | null;
  verdict?: Verdict | null;
  /** Which process to look up; omit when `evaluation` is already at hand. */
  pid?: number;
  startTime?: string;
  evaluation?: Evaluation;
  /** Set on a connection row: it carries the rating of the program that opened it. */
  program?: string;
  children: ReactNode;
}

const signed = (n: number) => (n > 0 ? `+${n}` : `${n}`);

/** Hover/focus card that explains a score: starting point, every signal with its points, the band and any hard rule. */
export function ScoreTip({ score, verdict, pid, startTime, evaluation, program, children }: ScoreTipProps) {
  const { t } = useTranslation();
  const [fetched, setEv] = useState<Evaluation | undefined>();
  const ev = evaluation ?? fetched;
  const [failed, setFailed] = useState(false);

  const load = useCallback(() => {
    if (ev || pid === undefined || startTime === undefined) return;
    fetchDetail(pid, startTime)
      .then((d) => {
        setEv(d.evaluation);
        setFailed(false);
      })
      .catch(() => setFailed(true));
  }, [ev, pid, startTime]);

  const shown = ev?.score ?? score ?? 0;
  const tone = ev?.verdict ?? verdict ?? 'unknown';
  const Icon = tone === 'safe' ? ShieldCheck : tone === 'malicious' ? OctagonAlert : ShieldQuestion;
  const signals = [...(ev?.signals ?? [])].sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));
  const computed = Math.max(0, Math.min(100, BASELINE + signals.reduce((n, s) => n + s.delta, 0)));

  return (
    <span className="rtip rtip-bottom scoretip" onMouseEnter={load} onFocus={load}>
      {children}
      <span className="rtip-card scoretip-card" role="tooltip">
        <strong className="rtip-title scoretip-head">
          <Icon size={16} aria-hidden="true" className={`tone-${tone}`} />
          {t('scoretip.title', { score: shown, verdict: t(`verdict.${tone}`) })}
        </strong>
        <span className="scoretip-scale" aria-hidden="true">
          <span className="scoretip-band tone-malicious" style={{ width: `${MALICIOUS_MAX + 1}%` }} />
          <span className="scoretip-band tone-unknown" style={{ width: `${SAFE_MIN - MALICIOUS_MAX - 1}%` }} />
          <span className="scoretip-band tone-safe" style={{ width: `${100 - SAFE_MIN}%` }} />
          <span className="scoretip-pin" style={{ insetInlineStart: `${Math.max(0, Math.min(100, shown))}%` }} />
        </span>
        <span className="scoretip-legend">
          <span>{t('scoretip.bandMalicious', { max: MALICIOUS_MAX })}</span>
          <span>{t('scoretip.bandUnknown', { min: MALICIOUS_MAX + 1, max: SAFE_MIN - 1 })}</span>
          <span>{t('scoretip.bandSafe', { min: SAFE_MIN })}</span>
        </span>
        {program && <span className="rtip-summary">{t('scoretip.viaProgram', { program })}</span>}
        {ev?.hard_rule && <span className="scoretip-rule">{t('scoretip.hardRule', { rule: ev.hard_rule })}</span>}
        {signals.length > 0 ? (
          <ul className="scoretip-signals">
            <li className="scoretip-base">
              <span>{t('scoretip.baseline')}</span>
              <span className="mono">{BASELINE}</span>
            </li>
            {signals.map((s) => (
              <li key={s.id}>
                <span>
                  {s.name}
                  {s.detail && <span className="scoretip-detail">{s.detail}</span>}
                </span>
                <span className={`mono ${s.delta < 0 ? 'neg' : 'pos'}`}>{signed(s.delta)}</span>
              </li>
            ))}
            <li className="scoretip-total">
              <span>{t('scoretip.total')}</span>
              <span className="mono">{ev?.hard_rule ? shown : computed}</span>
            </li>
          </ul>
        ) : (
          <span className="rtip-summary">
            {failed ? t('scoretip.unavailable') : ev ? t('scoretip.noSignals') : t('scoretip.loading')}
          </span>
        )}
        <span className="rtip-note">{t('scoretip.note')}</span>
      </span>
    </span>
  );
}
