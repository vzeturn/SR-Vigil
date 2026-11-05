import { ChevronRight, Globe2, OctagonAlert, ShieldAlert } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { Dialog } from '../components/Dialog';
import { AiActivity } from '../components/AiActivity';
import { Gauge } from '../components/Gauge';
import { ProcessActions } from '../components/ProcessActions';
import { ScoreBar } from '../components/ScoreBar';
import { VerdictChip } from '../components/VerdictChip';
import { ConnRow } from '../components/ConnRow';
import { ScoreTip } from '../components/ScoreTip';
import { connectionsByCountry, countryName } from '../countries';
import { dismissPanic, markPanic, useVigil } from '../store';
import type { Mode } from '../types';

import { RichTip, tipOf } from '../components/RichTip';

const MODES: readonly Mode[] = ['observe', 'learning', 'enforce'];

export function Overview() {
  const { t } = useTranslation();
  const { snapshot, link, panicAt } = useVigil();
  const [showAll, setShowAll] = useState(false);
  const [openCountry, setOpenCountry] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [panicError, setPanicError] = useState<string | null>(null);
  const [modeError, setModeError] = useState<string | null>(null);
  if (!snapshot) return <p className="muted">{t('table.loading')}</p>;
  const { status, processes } = snapshot;
  const isAdmin = link.role === 'admin';
  const byCountry = connectionsByCountry(snapshot.connections).slice(0, 5);
  const byPid = new Map(processes.map((p) => [p.pid, p]));
  const rank = { malicious: 0, unknown: 1, safe: 2 } as const;
  const attention = processes
    .filter((p) => p.verdict && p.verdict !== 'safe')
    .sort((a, b) => rank[a.verdict ?? 'safe'] - rank[b.verdict ?? 'safe'] || (a.score ?? 0) - (b.score ?? 0));
  const total = status.counts.safe + status.counts.unknown + status.counts.malicious;
  const score = total === 0 ? 100 : Math.round((status.counts.safe / total) * 100);
  const tone = status.counts.malicious > 0 ? 'malicious' : status.counts.unknown > 0 || status.counts.pending > 0 ? 'unknown' : 'safe';

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
            <RichTip key={m} tip={tipOf(t, `modeTip.${m}`)}>
            <button
              type="button"
              aria-pressed={status.mode === m}
              disabled={!isAdmin}
              onClick={() => setMode(m)}
            >
              {t(`mode.${m}`)}
            </button>
            </RichTip>
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

      <section className={`card hero tone-${tone}`}>
        <Gauge value={score} label={t('overview.score')} tone={tone} large />
        <div className="hero-text">
          <h2>{t(`overview.headline.${tone}`, { count: attention.length })}</h2>
          <p className="muted">{t('overview.scoreHelp', { safe: status.counts.safe, total })}</p>
          {status.counts.pending > 0 && (
            <button
              type="button"
              className="btn"
              onClick={() => window.dispatchEvent(new CustomEvent('vigil:goto', { detail: 'pending' }))}
            >
              {t('overview.pending', { count: status.counts.pending })}
            </button>
          )}
        </div>
      </section>

      <AiActivity />

      <div className="kpis">
        {(['safe', 'unknown', 'malicious'] as const).map((k) => (
          <div key={k} className={`card kpi tone-${k}`}>
            <div className="kpi-label">{t(`kpi.${k}`)}</div>
            <div className="kpi-value">{status.counts[k]}</div>
          </div>
        ))}
      </div>

      <section className="card">
        <h2 className="h2-icon">
          <ShieldAlert size={18} aria-hidden="true" />
          {t('overview.recent')}
        </h2>
        {attention.length === 0 ? (
          <p className="muted">{t('overview.none')}</p>
        ) : (
          <ul className="list attention">
            {(showAll ? attention : attention.slice(0, 6)).map((p) => (
              <li key={`${p.pid}-${p.start_time}`}>
                <span className="attention-name">
                  {p.name} <span className="muted mono">{p.pid}</span>
                </span>
                <ScoreTip score={p.score} verdict={p.verdict} pid={p.pid} startTime={p.start_time}>
                  <ScoreBar score={p.score} verdict={p.verdict} />
                </ScoreTip>
                <VerdictChip verdict={p.verdict} />
                <ProcessActions proc={p} />
              </li>
            ))}
          </ul>
        )}
        {attention.length > 6 && (
          <button type="button" className="expander" aria-expanded={showAll} onClick={() => setShowAll(!showAll)}>
            <ChevronRight size={14} aria-hidden="true" className="chev" />
            {showAll ? t('overview.less') : t('overview.more', { count: attention.length - 6 })}
          </button>
        )}
      </section>
      {byCountry.length > 0 && (
        <section className="card">
          <h2 className="h2-icon">
            <Globe2 size={18} aria-hidden="true" />
            {t('overview.countries')}
          </h2>
          <ul className="list">
            {byCountry.map(([cc, list]) => (
              <li key={cc} className="country">
                <button
                  type="button"
                  className="expander"
                  aria-expanded={openCountry === cc}
                  onClick={() => setOpenCountry(openCountry === cc ? null : cc)}
                >
                  <ChevronRight size={14} aria-hidden="true" className="chev" />
                  <span>{countryName(cc)}</span>
                  <span className="spacer" />
                  <span className="muted mono">{list.length}</span>
                </button>
                {openCountry === cc && (
                  <ul className="conn-list">
                    {list.map((c) => (
                      <ConnRow key={c.id} conn={c} proc={byPid.get(c.pid)} />
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
          <p className="muted">{t('overview.countriesNote')}</p>
        </section>
      )}
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
