import { OctagonAlert } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { Dialog } from '../components/Dialog';
import { VerdictChip } from '../components/VerdictChip';
import { dismissPanic, markPanic, useVigil } from '../store';
import type { Mode } from '../types';

const MODES: readonly Mode[] = ['observe', 'learning', 'enforce'];

export function Overview() {
  const { t } = useTranslation();
  const { snapshot, link, panicAt } = useVigil();
  const [confirming, setConfirming] = useState(false);
  const [panicError, setPanicError] = useState<string | null>(null);
  const [modeError, setModeError] = useState<string | null>(null);
  if (!snapshot) return <p className="muted">{t('table.loading')}</p>;
  const { status, processes } = snapshot;
  const isAdmin = link.role === 'admin';
  const review = processes.filter((p) => p.verdict && p.verdict !== 'safe').slice(0, 8);

  const setMode = (mode: Mode) => {
    setModeError(null);
    getBridge()
      .then((b) => b.rpc('mode.set', { mode }))
      .catch((e: unknown) => setModeError(e instanceof Error ? e.message : String(e)));
  };

  const panic = async () => {
    try {
      const b = await getBridge();
      await b.rpc('enforcement.panic', {});
      markPanic();
      setConfirming(false);
      setPanicError(null);
    } catch (e) {
      setPanicError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <>
      {panicAt !== null && (
        <div className="card banner" role="status">
          <strong>{t('panic.bannerTitle')}</strong>
          {t('panic.bannerBody')}{' '}
          <button type="button" className="btn" onClick={dismissPanic}>
            {t('panic.dismiss')}
          </button>
        </div>
      )}
      <div className="toolbar">
        <div className="segmented" role="group" aria-label={t('mode.label')}>
          {MODES.map((m) => (
            <button
              key={m}
              type="button"
              aria-pressed={status.mode === m}
              disabled={!isAdmin}
              title={isAdmin ? undefined : t('link.viewer')}
              onClick={() => setMode(m)}
            >
              {t(`mode.${m}`)}
            </button>
          ))}
        </div>
        {modeError !== null && (
          <span className="chip malicious" role="alert">
            {t('overview.modeFailed')}: {modeError}
          </span>
        )}
        <span className={`chip ${status.health === 'healthy' ? 'safe' : 'unknown'}`}>
          {t(`health.${status.health}`)}
        </span>
        <button
          type="button"
          className="btn block"
          disabled={!isAdmin}
          title={isAdmin ? undefined : t('link.viewer')}
          onClick={() => setConfirming(true)}
        >
          <OctagonAlert size={16} aria-hidden="true" />
          {t('panic.button')}
        </button>
        <span className="muted">{t('overview.rulePack', { version: status.rule_pack_version })}</span>
      </div>

      <div className="kpis">
        {(['safe', 'unknown', 'malicious', 'pending'] as const).map((k) => (
          <div key={k} className="card">
            <div className="kpi-label">{t(`kpi.${k}`)}</div>
            <div className="kpi-value">{status.counts[k]}</div>
          </div>
        ))}
      </div>

      <section className="card">
        <h2>{t('overview.recent')}</h2>
        {review.length === 0 ? (
          <p className="muted">{t('overview.none')}</p>
        ) : (
          <ul className="list">
            {review.map((p) => (
              <li key={`${p.pid}-${p.start_time}`}>
                <span>
                  {p.name} <span className="muted mono">{p.pid}</span>
                </span>
                <VerdictChip verdict={p.verdict} />
              </li>
            ))}
          </ul>
        )}
      </section>
      {confirming && (
        <Dialog title={t('panic.confirmTitle')} onClose={() => setConfirming(false)}>
          <p>{t('panic.confirmBody')}</p>
          {panicError && (
            <p className="error" role="alert">
              {t('decision.error', { message: panicError })}
            </p>
          )}
          <div className="dialog-foot">
            <button type="button" className="btn" onClick={() => setConfirming(false)}>
              {t('wizard.cancel')}
            </button>
            <span className="spacer" />
            <button type="button" className="btn block" onClick={() => void panic()}>
              {t('panic.confirm')}
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
