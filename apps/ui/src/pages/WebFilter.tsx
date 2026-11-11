import { Globe, X } from 'lucide-react';
import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import { useVigil } from '../store';
import type { DnsStatus, UrlCategory, UrlFilterSettings } from '../types';

const CATEGORIES: UrlCategory[] = ['malware', 'phishing', 'adult', 'ads'];
const POLL_MS = 5000;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

/** `https://www.Example.com/x` → `www.example.com`; null when it is not a domain name. */
export function toDomain(input: string): string | null {
  const host = input
    .trim()
    .toLowerCase()
    .replace(/^[a-z]+:\/\//, '')
    .replace(/^\*\./, '')
    .split(/[/?#:]/)[0]
    ?.replace(/\.$/, '');
  return host && DOMAIN.test(host) ? host : null;
}

const time = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

/** URL filter (`docs/23`): switch, categories, exceptions and recent blocks. */
export function WebFilter() {
  const { t } = useTranslation();
  const { link, snapshot } = useVigil();
  const isAdmin = link.role === 'admin';
  const paused = snapshot?.status.protection === false;
  const [cfg, setCfg] = useState<UrlFilterSettings | null>(null);
  const [status, setStatus] = useState<DnsStatus | null>(null);
  const [draft, setDraft] = useState('');
  const [msg, setMsg] = useState('');

  const refresh = useCallback(async () => {
    try {
      setStatus(await (await getBridge()).rpc<DnsStatus>('dns.status', {}));
    } catch {
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    void getBridge()
      .then((b) => b.rpc<{ urlfilter?: UrlFilterSettings }>('settings.get', {}))
      .then((s) => setCfg(s.urlfilter ?? null))
      .catch(() => undefined);
    // State is set only after the awaited service call, never synchronously.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
    const id = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  const save = async (patch: Partial<UrlFilterSettings>) => {
    setMsg('');
    try {
      await (await getBridge()).rpc('settings.set', { settings: { urlfilter: patch } });
      setCfg((c) => (c ? { ...c, ...patch } : c));
      void refresh();
    } catch (e) {
      setMsg(t('webfilter.failed', { code: e instanceof Error ? e.message : String(e) }));
    }
  };

  const allow = (raw: string) => {
    const d = toDomain(raw);
    if (!d) return setMsg(t('webfilter.badDomain'));
    if (cfg && !cfg.allow.includes(d)) void save({ allow: [...cfg.allow, d] });
    setDraft('');
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    allow(draft);
  };

  if (!cfg) return <p className="muted">{t('table.loading')}</p>;
  const state = paused ? 'paused' : !cfg.enabled ? 'off' : status?.listening ? 'on' : 'starting';
  const locked = !isAdmin;

  return (
    <>
      <section className="hero">
        <span className="hero-icon" aria-hidden="true">
          <Globe size={24} />
        </span>
        <div>
          <h2>
            {t('webfilter.title')}{' '}
            <span className={`status-pill${state === 'on' ? ' up' : ''}`} role="status">
              {t(`webfilter.state.${state}`)}
            </span>
          </h2>
          <p>{t('webfilter.intro')}</p>
        </div>
        <div className="hero-actions">
          <button
            type="button"
            className={`btn${cfg.enabled ? '' : ' primary'}`}
            disabled={locked}
            aria-pressed={cfg.enabled}
            onClick={() => void save({ enabled: !cfg.enabled })}
          >
            {t(cfg.enabled ? 'webfilter.turnOff' : 'webfilter.turnOn')}
          </button>
        </div>
      </section>
      {locked && <p className="muted note">{t('webfilter.adminOnly')}</p>}
      <p className="error" role="alert">
        {msg}
      </p>

      <div className="ld-tiles">
        <Stat label={t('webfilter.domains')} value={status?.domains} />
        <Stat label={t('webfilter.queries')} value={status?.queries} />
        <Stat label={t('webfilter.blocked')} value={status?.blocked} />
      </div>

      <section className="card">
        <h2>{t('webfilter.categories')}</h2>
        <ul className="plain">
          {CATEGORIES.map((c) => (
            <li key={c} className="wf-cat">
              <label>
                <input
                  type="checkbox"
                  checked={cfg[c]}
                  disabled={locked}
                  onChange={(e) => void save({ [c]: e.target.checked })}
                />
                <span>
                  <strong>{t(`webfilter.cat.${c}`)}</strong>
                  <small className="muted">{t(`webfilter.catHelp.${c}`)}</small>
                </span>
              </label>
              <span className="mono muted">{t('webfilter.blockedCount', { count: status?.by_category[c] ?? 0 })}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <h2>{t('webfilter.exceptions')}</h2>
        <p className="muted">{t('webfilter.exceptionsHelp')}</p>
        <form className="wf-add" onSubmit={submit}>
          <input
            aria-label={t('webfilter.domainLabel')}
            placeholder="example.com"
            value={draft}
            disabled={locked}
            onChange={(e) => setDraft(e.target.value)}
          />
          <button type="submit" className="btn" disabled={locked || !draft.trim()}>
            {t('webfilter.add')}
          </button>
        </form>
        {cfg.allow.length === 0 ? (
          <p className="muted">{t('webfilter.noExceptions')}</p>
        ) : (
          <ul className="plain">
            {cfg.allow.map((d) => (
              <li key={d} className="wf-row">
                <span className="mono">{d}</span>
                <button
                  type="button"
                  className="btn subtle"
                  disabled={locked}
                  aria-label={t('webfilter.remove', { domain: d })}
                  onClick={() => void save({ allow: cfg.allow.filter((x) => x !== d) })}
                >
                  <X size={16} aria-hidden="true" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="card">
        <h2>{t('webfilter.recent')}</h2>
        {!status?.recent.length ? (
          <p className="muted">{t('webfilter.noRecent')}</p>
        ) : (
          <ul className="plain">
            {[...status.recent].reverse().map((r) => (
              <li key={`${r.domain}-${r.at}`} className="wf-row">
                <span className="mono">{r.domain}</span>
                <span className="muted">
                  {t(`webfilter.cat.${r.category}`)} · {time(r.at)}
                </span>
                <button
                  type="button"
                  className="btn subtle"
                  disabled={locked || cfg.allow.includes(r.domain)}
                  onClick={() => allow(r.domain)}
                >
                  {t('webfilter.allow')}
                </button>
              </li>
            ))}
          </ul>
        )}
        <p className="muted note">{t('webfilter.dohNote')}</p>
      </section>
    </>
  );
}

function Stat({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="ld-tile">
      <strong className="mono">{value === undefined ? '–' : value.toLocaleString()}</strong>
      <span>{label}</span>
    </div>
  );
}
