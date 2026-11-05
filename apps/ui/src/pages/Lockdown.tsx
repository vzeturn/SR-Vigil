import { Crosshair, ShieldAlert, Siren, Timer } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { Dialog } from '../components/Dialog';
import { VerdictChip } from '../components/VerdictChip';
import type { LockdownHeld, LockdownReport, PersistenceItem } from '../types';

const EMPTY: LockdownReport = { active: false, spared: {}, kept: [], held: [] };
const CIRCLE = 2 * Math.PI * 52;

const clock = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;

function Ring({ report }: { report: LockdownReport }) {
  const { t } = useTranslation();
  const total = report.window_s ?? 300;
  const left = report.remaining_s ?? 0;
  return (
    <div className="ld-ring" role="timer" aria-label={t('lockdown.remaining')}>
      <svg viewBox="0 0 120 120" aria-hidden="true">
        <circle className="ld-ring-track" cx="60" cy="60" r="52" />
        <circle
          className="ld-ring-fill"
          cx="60"
          cy="60"
          r="52"
          strokeDasharray={CIRCLE}
          strokeDashoffset={CIRCLE * (1 - (report.active ? left / total : 0))}
        />
      </svg>
      <div className="ld-ring-text">
        <strong className="mono">{report.active ? clock(left) : '--:--'}</strong>
        <span>{report.active ? t('lockdown.holding') : t('lockdown.idle')}</span>
      </div>
    </div>
  );
}

function Tile({ label, value, tone }: { label: string; value: number; tone?: 'bad' | 'warn' | 'ok' }) {
  return (
    <div className={`ld-tile${tone ? ` ${tone}` : ''}`}>
      <strong className="mono">{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function Intel({ h }: { h: LockdownHeld }) {
  const { t } = useTranslation();
  if (!h.flagged) return <span className="muted">{t('lockdown.intelWait', { count: h.respawns })}</span>;
  if (!h.ai) return <span className="muted">{t('lockdown.intelPending')}</span>;
  if (h.ai.unavailable || !h.ai.verdict) return <span className="muted">{t('lockdown.intelOff')}</span>;
  return (
    <span>
      <VerdictChip verdict={h.ai.verdict} /> {Math.round((h.ai.confidence ?? 0) * 100)}%
      <br />
      <span className="muted">{h.ai.reasons?.[0]}</span>
    </span>
  );
}

export function Lockdown() {
  const { t } = useTranslation();
  const [report, setReport] = useState<LockdownReport>(EMPTY);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [trace, setTrace] = useState<Record<string, PersistenceItem[]>>({});

  const call = useCallback(async <T,>(method: string, params?: unknown): Promise<T | null> => {
    try {
      const r = await (await getBridge()).rpc<T>(method, params);
      setError(null);
      return r;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    }
  }, []);

  const refresh = useCallback(async () => {
    const r = await call<LockdownReport>('purge.status');
    if (r) setReport({ ...EMPTY, ...r });
  }, [call]);

  useEffect(() => {
    // State is set only after the awaited service call, never synchronously.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
    const id = setInterval(() => void refresh(), report.active ? 1000 : 5000);
    return () => clearInterval(id);
  }, [refresh, report.active]);

  const toggle = async () => {
    setBusy(true);
    setConfirm(false);
    const r = await call<LockdownReport>(report.active ? 'purge.stop' : 'purge.start', {});
    if (r) setReport({ ...EMPTY, ...r });
    setBusy(false);
  };

  const investigate = async (h: LockdownHeld) => {
    const r = await call<{ findings: PersistenceItem[] }>('persistence.scan', { target_image_path: h.path });
    if (r) setTrace((m) => ({ ...m, [h.path]: r.findings }));
  };

  const blockForGood = async (h: LockdownHeld) => {
    await call('decision.submit', {
      identity_id: h.identity_id,
      action: 'kill',
      scope: 'forever',
      apply_to: 'file',
      note: 'lockdown: kept coming back',
    });
  };

  const sparedTotal = Object.values(report.spared).reduce((a, b) => a + b, 0);

  return (
    <>
      {error && <p role="alert">{t('lockdown.error', { message: error })}</p>}
      <section className={`card ld-command${report.active ? ' live' : ''}`}>
        <Ring report={report} />
        <div className="ld-brief">
          <h2>
            <ShieldAlert size={18} aria-hidden="true" /> {t('lockdown.title')}
          </h2>
          <p>{t('lockdown.brief')}</p>
          <div className="ld-actions">
            <button
              type="button"
              className={`btn ${report.active ? 'subtle' : 'danger'}`}
              disabled={busy}
              onClick={() => (report.active ? void toggle() : setConfirm(true))}
            >
              <Siren size={16} aria-hidden="true" /> {report.active ? t('lockdown.release') : t('lockdown.start')}
            </button>
            {report.started_at && <span className="muted mono">{t('lockdown.since', { when: report.started_at })}</span>}
          </div>
        </div>
        <div className="ld-tiles">
          <Tile label={t('lockdown.stopped')} value={report.stopped ?? 0} tone="warn" />
          <Tile label={t('lockdown.heldOff')} value={report.respawns ?? 0} tone="ok" />
          <Tile label={t('lockdown.flagged')} value={report.flagged ?? 0} tone="bad" />
          <Tile label={t('lockdown.spared')} value={sparedTotal} />
        </div>
      </section>

      {report.held.length === 0 ? (
        <p className="muted">{t('lockdown.empty')}</p>
      ) : (
        <section className="card">
          <h2>
            <Crosshair size={16} aria-hidden="true" /> {t('lockdown.targets')}
          </h2>
          <ul className="ld-targets">
            {report.held.map((h) => (
              <li key={h.path} className={h.flagged ? 'flagged' : ''}>
                <div className="ld-target-main">
                  <strong>{h.name}</strong> <VerdictChip verdict={h.verdict} />{' '}
                  <span className="muted mono">{h.score ?? '-'}</span>
                  <div className="mono muted ld-path">{h.path}</div>
                  <div className="muted">
                    {h.publisher ?? t('lockdown.unsigned')}
                    {h.parent && <> · {t('lockdown.parent', { path: h.parent })}</>}
                  </div>
                </div>
                <div className="ld-meter" title={t('lockdown.comebacks', { count: h.respawns })}>
                  <Timer size={14} aria-hidden="true" />
                  <strong className="mono">{h.respawns}</strong>
                  <span className="muted">{t('lockdown.comebackLabel')}</span>
                  <div className="ld-bar">
                    <i style={{ width: `${Math.min(100, h.respawns * 20)}%` }} />
                  </div>
                </div>
                <div className="ld-intel">
                  <Intel h={h} />
                </div>
                <div className="ld-row-actions">
                  <button type="button" className="btn subtle" onClick={() => void investigate(h)}>
                    {t('lockdown.investigate')}
                  </button>
                  {h.identity_id && (
                    <button type="button" className="btn subtle" onClick={() => void blockForGood(h)}>
                      {t('lockdown.blockForGood')}
                    </button>
                  )}
                </div>
                {(() => {
                  const found = trace[h.path];
                  return (
                    found && (
                      <ul className="ld-trace mono">
                        {found.length === 0 && <li>{t('lockdown.noTrace')}</li>}
                        {found.map((f) => (
                          <li key={f.id}>
                            {f.kind}: {f.location}
                          </li>
                        ))}
                        {found.length > 0 && <li className="muted">{t('lockdown.traceHint')}</li>}
                      </ul>
                    )
                  );
                })()}
              </li>
            ))}
          </ul>
        </section>
      )}

      {sparedTotal > 0 && (
        <section className="card">
          <h2>{t('lockdown.keptTitle')}</h2>
          <p className="ld-chips">
            {Object.entries(report.spared).map(([why, n]) => (
              <span className="chip" key={why}>
                {t(`lockdown.why.${why}`)} · {n}
              </span>
            ))}
          </p>
          <ul className="list">
            {report.kept.map((k) => (
              <li key={`${k.name}-${k.path}`}>
                <span className="mono">{k.name}</span>
                <span className="muted">{t(`lockdown.why.${k.why}`)}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {confirm && (
        <Dialog title={t('lockdown.confirmTitle')} onClose={() => setConfirm(false)}>
          <p>{t('lockdown.confirmBody')}</p>
          <div className="dialog-foot">
            <button type="button" className="btn subtle" onClick={() => setConfirm(false)}>
              {t('lockdown.cancel')}
            </button>
            <button type="button" className="btn danger" onClick={() => void toggle()}>
              {t('lockdown.confirmGo')}
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
