import { useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { hidePopup } from '../bridge';
import { answerLauncher, type LauncherAction } from '../store';
import type { LauncherPrompt } from '../types';
import { useFitPopup } from './useFitPopup';

const base = (p: string) => p.split(/[\\/]/).pop() ?? p;

/** One question about whatever keeps starting a stopped program; "Keep waiting" leaves everything as is. */
export function LauncherView({ prompt }: { prompt: LauncherPrompt }) {
  const { t } = useTranslation();
  const box = useRef<HTMLDivElement>(null);
  useFitPopup(box);
  const launcher = base(prompt.launcher);
  const answer = (action: LauncherAction) => {
    void answerLauncher(prompt, action).finally(() => void hidePopup());
  };

  return (
    <div ref={box} className="popup" role="alertdialog" aria-label={t('launcher.title')}>
      <strong>{t('launcher.headline', { launcher, child: base(prompt.child) })}</strong>
      <div className="mono muted">{prompt.launcher}</div>
      <div>{t('launcher.body', { n: prompt.count, min: Math.round(prompt.window_secs / 60) })}</div>
      {prompt.autostart_entries === 0 && <div className="muted">{t('launcher.noAutostart')}</div>}
      <div className="toolbar">
        <button type="button" className="btn" onClick={() => answer('wait')}>
          {t('launcher.wait')}
        </button>
        <span className="spacer" />
        <button type="button" className="btn" onClick={() => answer('allow')}>
          {t('launcher.allowBoth')}
        </button>
        <button type="button" className="btn" disabled={prompt.autostart_entries === 0} onClick={() => answer('disable')}>
          {t('launcher.disable')}
        </button>
        <button type="button" className="btn primary" onClick={() => answer('stop')}>
          {t('launcher.stop', { launcher })}
        </button>
      </div>
    </div>
  );
}
