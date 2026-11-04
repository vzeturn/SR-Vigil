import { useState } from 'react';
import { useTranslation } from 'react-i18next';
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
      <section className="card">
        <h2>{t('settings.about')}</h2>
        <p className="muted">
          {snapshot ? t('settings.version', { version: snapshot.status.service_version }) : t('table.loading')}
        </p>
      </section>
    </>
  );
}
