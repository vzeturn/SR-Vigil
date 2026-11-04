import { Activity, Bell, Network, ScrollText, Settings as Cog, ShieldCheck, ListChecks, type LucideIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { syncTrayLabels, syncTrayPending } from './bridge';
import { Audit } from './pages/Audit';
import { Connections } from './pages/Connections';
import { Overview } from './pages/Overview';
import { Pending } from './pages/Pending';
import { Popup } from './pages/Popup';
import { Processes } from './pages/Processes';
import { RulesTrust } from './pages/RulesTrust';
import { Settings } from './pages/Settings';
import { useVigil } from './store';

const PAGES = {
  overview: { icon: Activity, view: Overview },
  pending: { icon: Bell, view: Pending },
  processes: { icon: ListChecks, view: Processes },
  connections: { icon: Network, view: Connections },
  audit: { icon: ScrollText, view: Audit },
  rules: { icon: ShieldCheck, view: RulesTrust },
  settings: { icon: Cog, view: Settings },
} satisfies Record<string, { icon: LucideIcon; view: () => React.JSX.Element }>;

type PageId = keyof typeof PAGES;

/** The `popup` Tauri window loads the same bundle at `#popup`. */
const isPopup = () => globalThis.location?.hash === '#popup';

export function App() {
  return isPopup() ? <Popup /> : <Shell />;
}

function Shell() {
  const { t } = useTranslation();
  const { link, snapshot } = useVigil();
  const pendingCount = snapshot?.status.counts.pending ?? 0;
  const [page, setPage] = useState<PageId>('overview');
  useEffect(() => {
    syncTrayLabels({
      open: t('tray.open'),
      quit: t('tray.quit'),
      panic: t('tray.panic'),
      modes: t('mode.label'),
      mode_observe: t('mode.observe'),
      mode_learning: t('mode.learning'),
      mode_enforce: t('mode.enforce'),
    }).catch(() => undefined);
  }, [t]);
  useEffect(() => {
    syncTrayPending(t('tray.pending', { count: pendingCount })).catch(() => undefined);
  }, [t, pendingCount]);
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
              {id === 'pending' && pendingCount > 0 && <span className="badge">{pendingCount}</span>}
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
