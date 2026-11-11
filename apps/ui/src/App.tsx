import {
  Activity,
  Bell,
  ListChecks,
  Network,
  Power,
  OctagonX,
  ShieldAlert,
  ScrollText,
  Settings as Cog,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge, enableProtection, syncTrayLabels, syncTrayPending } from './bridge';
import { LiveScan } from './components/LiveScan';
import { Kills } from './pages/Kills';
import { Lockdown } from './pages/Lockdown';
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
  lockdown: { icon: ShieldAlert, view: Lockdown },
  kills: { icon: OctagonX, view: Kills },
  startup: { icon: Power, view: Startup },
  audit: { icon: ScrollText, view: Audit },
  rules: { icon: ShieldCheck, view: RulesTrust },
  settings: { icon: Cog, view: Settings },
} satisfies Record<string, { icon: LucideIcon; view: () => React.JSX.Element }>;

type PageId = keyof typeof PAGES;

/** Sidebar sections, in task order; Settings sits apart at the foot. */
const NAV_GROUPS: { id: string; pages: PageId[] }[] = [
  { id: 'monitor', pages: ['overview', 'pending', 'processes', 'connections'] },
  { id: 'respond', pages: ['lockdown', 'kills', 'startup'] },
  { id: 'review', pages: ['audit', 'rules'] },
];

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
  const active = snapshot?.status.protection !== false;
  const [toggleFailed, setToggleFailed] = useState(false);
  const setProtection = (enabled: boolean) => {
    setToggleFailed(false);
    getBridge()
      .then((b) => b.rpc('protection.set', { enabled }))
      .catch(() => setToggleFailed(true));
  };
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
  const navItem = (id: PageId) => {
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
        <span className="nav-label">{t(`nav.${id}`)}</span>
        {id === 'pending' && pendingCount > 0 && <span className="badge">{pendingCount}</span>}
      </button>
    );
  };

  return (
    <div className="shell">
      <nav className="sidebar" aria-label={t('app.name')}>
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <ShieldCheck size={18} />
          </span>
          <span>
            {t('app.name')}
            <small>{t('app.tagline')}</small>
          </span>
        </div>
        {NAV_GROUPS.map((g) => (
          <div key={g.id} className="nav-group" role="group" aria-labelledby={`nav-${g.id}`}>
            <p className="nav-section" id={`nav-${g.id}`}>
              {t(`navGroup.${g.id}`)}
            </p>
            {g.pages.map((id) => navItem(id))}
          </div>
        ))}
        <div className="nav-foot">{navItem('settings')}</div>
      </nav>
      <main className="main">
        <div className="page-head">
          <h1>{t(`nav.${page}`)}</h1>
          <span className="page-head-actions">
            {link.up && (
              <button
                type="button"
                className={`btn${active ? '' : ' primary'}`}
                title={t('link.pauseHelp')}
                aria-pressed={!active}
                onClick={() => setProtection(!active)}
              >
                {active ? t('link.pause') : t('link.resume')}
              </button>
            )}
            {toggleFailed && (
              <span className="hero-error" role="alert">
                {t('link.toggleFailed')}
              </span>
            )}
            <span className={`status-pill${link.up && active ? ' up' : ''}`} role="status">
              {!link.up ? t('link.watching') : active ? t('link.protected') : t('link.paused')}
            </span>
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
