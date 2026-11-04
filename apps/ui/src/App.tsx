import { Activity, Network, Settings as Cog, ShieldCheck, ListChecks, type LucideIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { syncTrayLabels } from './bridge';
import { Connections } from './pages/Connections';
import { Overview } from './pages/Overview';
import { Processes } from './pages/Processes';
import { RulesTrust } from './pages/RulesTrust';
import { Settings } from './pages/Settings';
import { useVigil } from './store';

const PAGES = {
  overview: { icon: Activity, view: Overview },
  processes: { icon: ListChecks, view: Processes },
  connections: { icon: Network, view: Connections },
  rules: { icon: ShieldCheck, view: RulesTrust },
  settings: { icon: Cog, view: Settings },
} satisfies Record<string, { icon: LucideIcon; view: () => React.JSX.Element }>;

type PageId = keyof typeof PAGES;

export function App() {
  const { t } = useTranslation();
  const { link } = useVigil();
  const [page, setPage] = useState<PageId>('overview');
  useEffect(() => {
    syncTrayLabels(t('tray.open'), t('tray.quit')).catch(() => undefined);
  }, [t]);
  const View = PAGES[page].view;

  return (
    <div className="shell">
      <nav className="sidebar" aria-label={t('app.name')}>
        <div className="brand">
          <ShieldCheck size={20} aria-hidden="true" />
          {t('app.name')}
        </div>
        {(Object.keys(PAGES) as PageId[]).map((id) => {
          const Icon = PAGES[id].icon;
          return (
            <button
              key={id}
              type="button"
              className="nav-item"
              aria-current={page === id ? 'page' : undefined}
              onClick={() => setPage(id)}
            >
              <Icon size={18} aria-hidden="true" />
              {t(`nav.${id}`)}
            </button>
          );
        })}
      </nav>
      <main className="main">
        <h1>{t(`nav.${page}`)}</h1>
        {!link.up && (
          <div className="card banner" role="status">
            <strong>{t('link.offlineTitle')}</strong>
            {t('link.offlineBody')}
          </div>
        )}
        <View />
      </main>
    </div>
  );
}
