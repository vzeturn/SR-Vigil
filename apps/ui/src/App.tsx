import {
  Activity,
  Bell,
  ListChecks,
  Network,
  Power,
  OctagonX,
  ScrollText,
  Settings as Cog,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { enableProtection, syncTrayLabels, syncTrayPending } from './bridge';
import { LiveScan } from './components/LiveScan';
import { Kills } from './pages/Kills';
import { Audit } from './pages/Audit';
import { Connections } from './pages/Connections';
import { Overview } from './pages/Overview';
import { Pending } from './pages/Pending';
import { Popup } from './pages/Popup';
import { Processes } from './pages/Processes';
import { RulesTrust } from './pages/RulesTrust';
import { Startup } from './pages/Startup';
import { Settings } from './pages/Settings';
import { useVigil } from './store';

const PAGES = {
  overview: { icon: Activity, view: Overview },
  pending: { icon: Bell, view: Pending },
  processes: { icon: ListChecks, view: Processes },
  connections: { icon: Network, view: Connections },
  kills: { icon: OctagonX, view: Kills },
  startup: { icon: Power, view: Startup },
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
  const [enabling, setEnabling] = useState(false);
  const [enableFailed, setEnableFailed] = useState(false);
  const enable = async () => {
    setEnabling(true);
    setEnableFailed(!(await enableProtection()));
    setEnabling(false);
  };
  useEffect(() => {
    syncTrayLabels({
      open: t('tray.open'),
      quit: t('tray.quit'),
      panic: t('tray.panic'),
      audit: t('tray.audit'),
      settings: t('tray.settings'),
      autostart: t('tray.autostart'),
      modes: t('mode.label'),
      mode_observe: t('mode.observe'),
      mode_learning: t('mode.learning'),
      mode_enforce: t('mode.enforce'),
    }).catch(() => undefined);
  }, [t]);
  useEffect(() => {
    syncTrayPending(t('tray.pending', { count: pendingCount })).catch(() => undefined);
  }, [t, pendingCount]);
  useEffect(() => {
    let off: (() => void) | undefined;
    import('@tauri-apps/api/event')
      .then(({ listen }) =>
        listen<string>('vigil://navigate', (e) => {
          if (e.payload in PAGES) setPage(e.payload as PageId);
        }),
      )
      .then((un) => (off = un))
      .catch(() => undefined);
    return () => off?.();
  }, []);
  useEffect(() => {
    const go = (e: Event) => {
      const id = (e as CustomEvent<string>).detail;
      if (id in PAGES) setPage(id as PageId);
    };
    window.addEventListener('vigil:goto', go);
    return () => window.removeEventListener('vigil:goto', go);
  }, []);
  const View = PAGES[page].view;

  return (
    <div className="shell">
      <nav className="sidebar" aria-label={t('app.name')}>
        <div className="brand">
          <ShieldCheck size={20} aria-hidden="true" />
          <span>
            {t('app.name')}
            <small>{t('app.tagline')}</small>
          </span>
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
        <div className="page-head">
          <h1>{t(`nav.${page}`)}</h1>
          <span className={`status-pill${link.up ? ' up' : ''}`} role="status">
            {link.up ? t('link.protected') : t('link.watching')}
          </span>
        </div>
        {!link.up && (
          <section className="hero" aria-labelledby="hero-title">
            <div className="hero-icon">
              <ShieldCheck size={28} aria-hidden="true" />
            </div>
            <div>
              <h2 id="hero-title">{t('link.offlineTitle')}</h2>
              <p>{t('link.offlineBody')}</p>
            </div>
            <div className="hero-actions">
              <button type="button" className="btn primary" disabled={enabling} onClick={() => void enable()}>
                {enabling ? t('link.enabling') : t('link.enable')}
              </button>
              {enableFailed && (
                <span className="hero-error" role="alert">
                  {t('link.enableFailed')}
                </span>
              )}
            </div>
          </section>
        )}
        {!link.up && page !== 'settings' && <LiveScan onCleanup={() => setPage('settings')} />}
        {(link.up || page === 'settings') && <View />}
      </main>
    </div>
  );
}
