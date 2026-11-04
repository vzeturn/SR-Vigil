import { ChevronDown } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { localKill, localScan, onScanProgress, type LocalFinding, type LocalScan, } from '../bridge';
import { Gauge } from './Gauge';
import { Num } from './Num';
import { ReasonBadge, title } from './ReasonBadge';
import { VerdictChip } from './VerdictChip';

const REFRESH_MS = 10_000;
const DISMISS_KEY = 'vigil.dismissed';
const BANDS = ['malicious', 'unknown', 'unknown', 'safe'] as const;

/** Trust score on a 0-10 scale, one decimal. */
const outOf10 = (score: number) => (score / 10).toFixed(1);

const keyOf = (f: LocalFinding) => f.image.toLowerCase();

function loadDismissed(): string[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(DISMISS_KEY) ?? '[]');
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function saveDismissed(v: string[]): void {
  try {
    localStorage.setItem(DISMISS_KEY, JSON.stringify(v));
  } catch {
    /* storage unavailable: dismissal lasts for this session only */
  }
}

interface CellProps {
  label: string;
  value: string | number;
  hint?: string;
  tone?: 'safe' | 'unknown' | 'malicious';
}

/** One quote-board style cell: caption above a tabular figure. */
function Cell({ label, value, hint, tone }: CellProps) {
  return (
    <div className={`tick${tone ? ` tone-${tone}` : ''}`} title={hint}>
      <span className="tick-label">{label}</span>
      <strong className="tick-value">{typeof value === 'number' ? <Num value={value} /> : value}</strong>
    </div>
  );
}

/** Watching-only view: dense market-style indicators plus an actionable list of unverified processes. */
export function LiveScan({ onCleanup }: { onCleanup: () => void }) {
  const { t } = useTranslation();
  const [scan, setScan] = useState<LocalScan | null>(null);
  const [failed, setFailed] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState<string[]>(loadDismissed);
  const [confirm, setConfirm] = useState<LocalFinding | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [order, setOrder] = useState<ReadonlyMap<string, number>>(new Map());
  const full = useRef(false);
  const lastPaint = useRef(0);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);

  const adopt = useCallback((r: LocalScan) => {
    setOrder((prev) => {
      const fresh = r.findings.map((f) => `${f.pid}-${f.image}`).filter((k) => !prev.has(k));
      if (fresh.length === 0) return prev;
      const next = new Map(prev);
      for (const k of fresh) next.set(k, next.size);
      return next;
    });
    setScan(r);
  }, []);
  const refresh = useCallback(
    () =>
      localScan().then(
        (r) => {
          full.current = true;
          adopt(r);
          setProgress(null);
          setFailed(false);
        },
        () => setFailed(true),
      ),
    [adopt],
  );
  useEffect(() => {
    let off: (() => void) | undefined;
    let gone = false;
    // Stream only the first scan; later refreshes swap in at once so numbers never fall back to zero.
    onScanProgress((p) => {
      const now = Date.now();
      if (full.current || (now - lastPaint.current < 500 && p.done < p.total)) return;
      lastPaint.current = now;
      adopt(p.scan);
      setProgress({ done: p.done, total: p.total });
    })
      .then((un) => (gone ? un() : (off = un)))
      .catch(() => undefined);
    return () => {
      gone = true;
      off?.();
    };
  }, [adopt]);
  useEffect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), REFRESH_MS);
    return () => clearInterval(id);
  }, [refresh]);

  const dismiss = (f: LocalFinding) => {
    const next = [...new Set([...dismissed, keyOf(f)])];
    setDismissed(next);
    saveDismissed(next);
  };
  const restore = () => {
    setDismissed([]);
    saveDismissed([]);
  };
  const endIt = async (f: LocalFinding) => {
    setConfirm(null);
    const r = await localKill(f);
    setNotice(t(`live.result.${['terminated', 'gone', 'access_denied', 'protected_target', 'now_safe'].includes(r) ? r : 'failed'}`, { name: f.name }));
    void refresh();
  };

  /** One issue per line: score, signer, impersonation, load, advice, then every rule with its effect. */
  const tipOf = (f: LocalFinding) =>
    [
      `${outOf10(f.score)}/10 · ${t(`verdict.${f.verdict}`)}`,
      f.identity.signature.startsWith("Valid") || f.identity.publisher
        ? t(f.identity.signature.startsWith("Valid") ? "live.tipSigned" : "live.tipInvalid", { who: f.identity.publisher ?? "-" })
        : t("live.tipUnsigned"),
      t(`live.spoof.${f.spoof}`),
      t("live.impactTip", { level: t(`live.impact.${f.impact}`), ram: f.ramMb, cpu: f.cpu, threads: f.threads }),
      t(`live.advice.${f.advice}`),
      ...f.reasons.map((r) => `${r.delta === null ? "·" : r.delta > 0 ? `+${r.delta}` : r.delta}  ${title(r.name)}`),
    ].join('\n');

  const rows = useMemo(
    () =>
      scan
        ? scan.findings
            .filter((f) => showAll || !dismissed.includes(keyOf(f)))
            .sort(
              (a, b) =>
                (order.get(`${a.pid}-${a.image}`) ?? 0) - (order.get(`${b.pid}-${b.image}`) ?? 0),
            )
        : [],
    [scan, dismissed, showAll, order],
  );

  if (failed && !scan) return <p className="error">{t('live.failed')}</p>;
  if (!scan) return <p className="muted">{t('live.scanning')}</p>;

  const total = Math.max(scan.total, 1);
  const hidden = scan.findings.length - scan.findings.filter((f) => !dismissed.includes(keyOf(f))).length;
  const tone = scan.malicious > 0 || scan.posture < 50 ? 'malicious' : scan.posture < 80 ? 'unknown' : 'safe';
  const avg = Math.round(scan.findings.reduce((a, f) => a + f.score, 0) / Math.max(scan.findings.length, 1));
  const lowest = scan.findings.reduce((m, f) => Math.min(m, f.score), 100);
  const rulesFired = new Set(scan.findings.flatMap((f) => f.reasons.map((r) => r.id))).size;
  const highImpact = scan.findings.filter((f) => f.impact === 'high').length;
  const ramMb = scan.findings.reduce((a, f) => a + f.ramMb, 0);
  const toEnd = scan.findings.filter((f) => f.advice === 'end').length;
  const doubtful = scan.findings.filter((f) => f.spoof !== 'clear').length;
  const maxReason = Math.max(...scan.topReasons.map((r) => r.count), 1);
  const pct = (n: number) => `${Math.round((n * 100) / total)}%`;

  return (
    <>
      <section className="board" aria-label={t('live.indicators')}>
        <div className="tick tick-gauge" title={t('live.postureHelp')}>
          <Gauge value={scan.posture} label={t('live.posture')} tone={tone} />
          <span className="tick-label">{t('live.posture')}</span>
        </div>
        <Cell label={t('live.processes')} value={scan.total} />
        <Cell label={t('verdict.safe')} value={scan.safe} hint={pct(scan.safe)} tone="safe" />
        <Cell label={t('verdict.unknown')} value={scan.unknown} hint={pct(scan.unknown)} tone="unknown" />
        <Cell label={t('verdict.malicious')} value={scan.malicious} hint={pct(scan.malicious)} tone="malicious" />
        <Cell label={t('live.trusted')} value={Math.round(((scan.safe * 100) / total))} hint={t('live.trustedHelp')} tone="safe" />
        <Cell label={t('live.review')} value={scan.findings.length - hidden} hint={t('live.reviewHelp')} />
        <Cell label={t('live.lowest')} value={scan.findings.length ? lowest : '-'} hint={t('live.lowestHelp')} tone={lowest < 30 ? 'malicious' : undefined} />
        <Cell label={t('live.rules')} value={rulesFired} hint={t('live.rulesHelp')} />
        <Cell label={t('live.avgScore')} value={scan.findings.length ? avg : '-'} hint={t('live.avgScoreHelp')} />
        <Cell label={t('live.toEnd')} value={toEnd} hint={t('live.toEndHelp')} tone={toEnd ? 'malicious' : undefined} />
        <Cell label={t('live.highImpact')} value={highImpact} hint={t('live.highImpactHelp')} tone={highImpact ? 'unknown' : undefined} />
        <Cell label={t('live.ramUnverified')} value={ramMb} hint={t('live.ramUnverifiedHelp')} />
        <Cell label={t('live.doubtful')} value={doubtful} hint={t('live.doubtfulHelp')} />
        <Cell label={t('live.hiddenProcs')} value={scan.skipped} hint={t('live.hiddenHelp')} />
        <div className="tick tick-wide">
          <span className="tick-label">{t('live.distribution', { total: scan.total })}</span>
          <div className="stackbar" role="img" aria-label={t('live.distribution', { total: scan.total })}>
            {scan.buckets.map((n, i) => (
              <span key={i} className={`seg tone-${BANDS[i]} band-${i}`} style={{ flexGrow: n }} title={`${n}`} />
            ))}
          </div>
        </div>
      </section>

      {scan.topReasons.length > 0 && (
        <details className="card tight fold">
          <summary>{t('live.topReasons')}</summary>
          <ul className="reasons">
            {scan.topReasons.map((r) => (
              <li key={r.id}>
                <span className="reason-text">
                  <ReasonBadge reason={{ ...r, delta: null }} label />
                </span>
                <span className="meter" aria-hidden="true">
                  <span style={{ width: `${(r.count * 100) / maxReason}%` }} />
                </span>
                <strong>
                  <Num value={r.count} />
                </strong>
              </li>
            ))}
          </ul>
        </details>
      )}

      <section className="card tight" aria-labelledby="live-title">
        <div className="toolbar">
          <h2 id="live-title" className="grow">
            {t('live.title')} <span className="muted">{rows.length}</span>
          </h2>
          <span className="muted note" role="status">
            {progress ? t('live.progress', { done: progress.done, total: progress.total }) : t('live.updated')}
          </span>
          {hidden > 0 && (
            <button type="button" className="btn subtle" onClick={() => setShowAll(!showAll)}>
              {showAll ? t('live.hideDismissed') : t('live.showDismissed', { count: hidden })}
            </button>
          )}
          {dismissed.length > 0 && (
            <button type="button" className="btn subtle" onClick={restore}>
              {t('live.restore')}
            </button>
          )}
          <button type="button" className="btn" onClick={onCleanup}>
            {t('link.f3Action')}
          </button>
        </div>
        {notice && (
          <p className="note" role="status">
            {notice}
          </p>
        )}
        {rows.length === 0 ? (
          <p className="muted">{t('live.clean')}</p>
        ) : (
          <ul className="findings">
            {rows.map((f) => {
              const key = `${f.pid}-${f.image}`;
              const expanded = open === key;
              const isDismissed = dismissed.includes(keyOf(f));
              return (
                <li key={key} className={isDismissed ? 'is-dismissed' : undefined}>
                  <div className="finding-row">
                    <VerdictChip verdict={f.verdict} />
                    <button
                      type="button"
                      className="finding-main"
                      aria-expanded={expanded}
                      onClick={() => setOpen(expanded ? null : key)}
                    >
                      <strong title={f.image}>{f.name}</strong>
                      <span className="sub muted">{f.known ? `${f.known.label} · ${f.known.what}` : (f.identity.publisher ?? t("live.tipUnsigned"))}</span>
                    </button>
                    <span className="score tip" data-tip={tipOf(f)} tabIndex={0} aria-label={tipOf(f).replaceAll('\n', '. ')}>
                      <span className="meter" aria-hidden="true">
                        <span style={{ width: `${f.score}%` }} className={`fill-${f.verdict}`} />
                      </span>
                      <span className="mono">{outOf10(f.score)}/10</span>
                    </span>
                    <button type="button" className={`btn ${f.advice === "end" ? "danger" : "subtle"} kill`} disabled={!f.start} onClick={() => setConfirm(f)}>
                      {t("live.end")}
                    </button>
                    <ChevronDown size={16} aria-hidden="true" className={expanded ? 'flip' : ''} />
                  </div>
                  {expanded && (
                    <ul className="why">
                      <li className="mono muted">{f.image}</li>
                      <li className="identity">
                        <span className="muted">{t('live.id.signature')}</span>
                        <span>
                          {t(`live.id.state.${f.identity.signature}`, { defaultValue: f.identity.signature })}
                          {f.identity.osSigned ? ` · ${t('live.id.windows')}` : ''}
                          {f.identity.msRoot ? ` · ${t('live.id.msRoot')}` : ''}
                        </span>
                        <span className="muted">{t('live.id.publisher')}</span>
                        <span>{f.identity.publisher ?? '-'}</span>
                        <span className="muted">{t('live.id.claims')}</span>
                        <span>{[f.identity.company, f.identity.product].filter(Boolean).join(' · ') || '-'}</span>
                        <span className="muted">{t('live.id.original')}</span>
                        <span className="mono">{f.identity.original || '-'}</span>
                        <span className="muted">{t('live.id.impact')}</span>
                        <span>{t('live.impactTip', { level: t(`live.impact.${f.impact}`), ram: f.ramMb, cpu: f.cpu, threads: f.threads })}</span>
                        <span className="muted">{t('live.id.advice')}</span>
                        <strong>{t(`live.advice.${f.advice}`)}</strong>
                        <span className="muted">{t('live.id.verdict')}</span>
                        <span>{t(`live.spoof.${f.spoof}`)}</span>
                      </li>
                      {!isDismissed && (
                        <li>
                          <button type="button" className="btn subtle" onClick={() => dismiss(f)}>
                            {t("live.dismiss")}
                          </button>
                        </li>
                      )}
                      {f.reasons.map((r) => (
                        <li key={r.id}>
                          <span className={`delta ${(r.delta ?? 0) < 0 ? 'neg' : 'pos'}`}>
                            {r.delta === null ? '·' : r.delta > 0 ? `+${r.delta}` : r.delta}
                          </span>
                          <ReasonBadge reason={r} label />
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {confirm && (
        <div className="overlay" role="presentation">
          <div className="dialog" role="alertdialog" aria-modal="true" aria-labelledby="end-title">
            <h2 id="end-title" className="dialog-title">
              {t('live.endTitle', { name: confirm.name })}
            </h2>
            <p className="mono">{confirm.image}</p>
            <p>{t(`live.adviceHelp.${confirm.advice}`)}</p>
            <p>{t('live.endBody')}</p>
            <div className="dialog-foot">
              <button type="button" className="btn" autoFocus onClick={() => setConfirm(null)}>
                {t('live.cancel')}
              </button>
              <button type="button" className="btn primary" onClick={() => void endIt(confirm)}>
                {t('live.end')}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
