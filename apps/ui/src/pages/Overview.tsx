import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { VerdictChip } from '../components/VerdictChip';
import { useVigil } from '../store';
import type { Mode } from '../types';

const MODES: readonly Mode[] = ['observe', 'learning', 'enforce'];

export function Overview() {
  const { t } = useTranslation();
  const { snapshot, link } = useVigil();
  if (!snapshot) return <p className="muted">{t('table.loading')}</p>;
  const { status, processes } = snapshot;
  const isAdmin = link.role === 'admin';
  const review = processes.filter((p) => p.verdict && p.verdict !== 'safe').slice(0, 8);

  const setMode = (mode: Mode) => {
    void getBridge().then((b) => b.rpc('mode.set', { mode }));
  };

  return (
    <>
      <div className="toolbar">
        <div className="segmented" role="group" aria-label={t('mode.label')}>
          {MODES.map((m) => (
            <button
              key={m}
              type="button"
              aria-pressed={status.mode === m}
              disabled={!isAdmin || m === 'enforce'}
              title={m === 'enforce' ? t('overview.enforceOff') : isAdmin ? undefined : t('link.viewer')}
              onClick={() => setMode(m)}
            >
              {t(`mode.${m}`)}
            </button>
          ))}
        </div>
        <span className={`chip ${status.health === 'healthy' ? 'safe' : 'unknown'}`}>
          {t(`health.${status.health}`)}
        </span>
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
    </>
  );
}
