import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import type { AiConfig, AiMode, AiSource } from '../types';
import { LANGUAGES, setLang, type Lang } from '../i18n';
import { useVigil } from '../store';

type Theme = 'system' | 'light' | 'dark';

function applyTheme(theme: Theme) {
  if (theme === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
  try {
    localStorage.setItem('vigil.theme', theme);
  } catch {
    /* preference simply isn't remembered */
  }
}

export function loadTheme() {
  try {
    const saved = localStorage.getItem('vigil.theme');
    if (saved === 'light' || saved === 'dark') applyTheme(saved);
  } catch {
    /* default to the OS theme */
  }
}

function AiCard() {
  const { t } = useTranslation();
  const [cfg, setCfg] = useState<AiConfig | null>(null);
  const [key, setKey] = useState('');
  const [ack, setAck] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    void getBridge()
      .then((b) => b.rpc<AiConfig>('ai.config.get', {}))
      .then(setCfg)
      .catch(() => undefined);
  }, []);

  if (!cfg) return null;

  const save = async (patch: Partial<AiConfig> & { api_key?: string }) => {
    try {
      const next = await (await getBridge()).rpc<AiConfig>('ai.config.set', {
        ...patch,
        acknowledge_data_categories: ack,
      });
      setCfg(next);
      setKey('');
      setMsg(t('ai.saved'));
    } catch (e) {
      setMsg(t('ai.failed', { code: e instanceof Error ? e.message : String(e) }));
    }
  };

  const test = async () => {
    try {
      const r = await (await getBridge()).rpc<{ ok: boolean; latency_ms: number; model: string }>('ai.test', {});
      setMsg(r.ok ? t('ai.testOk', { ms: r.latency_ms, model: r.model }) : t('ai.testFail'));
    } catch {
      setMsg(t('ai.testFail'));
    }
  };

  return (
    <section className="card">
      <h2>{t('ai.title')}</h2>
      <p className="muted">{t('ai.intro')}</p>
      <label>
        {t('ai.mode')}
        <select
          value={cfg.mode}
          onChange={(e) => {
            const mode = e.target.value as AiMode;
            void save({ mode, enabled: mode !== 'off', ...(key ? { api_key: key } : {}) });
          }}
        >
          <option value="off">{t('ai.off')}</option>
          <option value="advisor">{t('ai.advisor')}</option>
          <option value="auto">{t('ai.auto')}</option>
        </select>
      </label>
      {cfg.shared_available && (
        <label>
          {t('ai.source')}
          <select value={cfg.source} onChange={(e) => void save({ source: e.target.value as AiSource })}>
            <option value="shared">{t('ai.sourceShared')}</option>
            <option value="own_key">{t('ai.sourceOwn')}</option>
          </select>
        </label>
      )}
      {cfg.source === 'shared' ? (
        <p className="muted">{t('ai.sharedNote')}</p>
      ) : (
        <>
          <label>
            {t('ai.key')}
            <input
              type="password"
              autoComplete="off"
              value={key}
              placeholder={t('ai.keyPlaceholder')}
              onChange={(e) => setKey(e.target.value)}
            />
          </label>
          {cfg.has_key && <p className="muted">{t('ai.keySaved')}</p>}
        </>
      )}
      <label>
        <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> {t('ai.ack')}
      </label>
      <div className="row">
        <button type="button" onClick={() => void save(key ? { api_key: key } : {})}>
          {t('ai.save')}
        </button>
        <button type="button" disabled={!cfg.has_key && cfg.source !== 'shared'} onClick={() => void test()}>
          {t('ai.test')}
        </button>
        {cfg.has_key && cfg.source === 'own_key' && (
          <button type="button" onClick={() => void save({ api_key: '', enabled: false, mode: 'off' })}>
            {t('ai.keyRemove')}
          </button>
        )}
      </div>
      <p className="muted" role="status">
        {msg || t('ai.calls', { n: cfg.calls_today })}
      </p>
    </section>
  );
}

interface Exported {
  content: string;
  count: number;
}

function saveText(name: string, mime: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function DataCard() {
  const { t } = useTranslation();
  const [msg, setMsg] = useState('');
  const fail = (e: unknown) => setMsg(t('data.failed', { code: e instanceof Error ? e.message : String(e) }));

  const exportAs = async (method: string, params: object, name: string, mime: string) => {
    try {
      const r = await (await getBridge()).rpc<Exported>(method, params);
      saveText(name, mime, r.content);
      setMsg(t('data.exported', { n: r.count }));
    } catch (e) {
      fail(e);
    }
  };

  const importFile = async (file: File) => {
    try {
      const r = await (await getBridge()).rpc<{ imported: number; skipped: number }>('decision.import', {
        content: await file.text(),
      });
      setMsg(t('data.imported', r));
    } catch (e) {
      fail(e);
    }
  };

  return (
    <section className="card">
      <h2>{t('data.title')}</h2>
      <p className="muted">{t('data.intro')}</p>
      <div className="row">
        <button type="button" onClick={() => void exportAs('decision.export', {}, 'vigil-decisions.toml', 'application/toml')}>
          {t('data.exportDecisions')}
        </button>
        <label className="button">
          {t('data.importDecisions')}
          <input
            type="file"
            accept=".toml"
            hidden
            onChange={(e) => {
              const f = e.target.files?.[0];
              e.target.value = '';
              if (f) void importFile(f);
            }}
          />
        </label>
        <button type="button" onClick={() => void exportAs('audit.export', { format: 'csv' }, 'vigil-audit.csv', 'text/csv')}>
          {t('data.exportAudit')}
        </button>
      </div>
      <p className="muted" role="status">
        {msg}
      </p>
    </section>
  );
}

export function Settings() {
  const { t, i18n } = useTranslation();
  const { snapshot } = useVigil();
  const [theme, setTheme] = useState<Theme>(
    (document.documentElement.getAttribute('data-theme') as Theme | null) ?? 'system',
  );

  return (
    <>
      <section className="card">
        <h2>{t('settings.language')}</h2>
        <select
          aria-label={t('settings.language')}
          value={i18n.language}
          onChange={(e) => setLang(e.target.value as Lang)}
        >
          {LANGUAGES.map((l) => (
            <option key={l.code} value={l.code}>
              {l.label}
            </option>
          ))}
        </select>
      </section>
      <section className="card">
        <h2>{t('settings.theme')}</h2>
        <select
          aria-label={t('settings.theme')}
          value={theme}
          onChange={(e) => {
            const next = e.target.value as Theme;
            setTheme(next);
            applyTheme(next);
          }}
        >
          <option value="system">{t('settings.themeSystem')}</option>
          <option value="light">{t('settings.themeLight')}</option>
          <option value="dark">{t('settings.themeDark')}</option>
        </select>
      </section>
      <AiCard />
      <DataCard />
      <section className="card">
        <h2>{t('settings.about')}</h2>
        <p className="muted">
          {snapshot ? t('settings.version', { version: snapshot.status.service_version }) : t('table.loading')}
        </p>
      </section>
    </>
  );
}
