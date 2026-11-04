import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { act } from 'react';
import { App } from './App';
import i18n from './i18n';
import { start } from './store';

// Contrast needs real layout and computed colours; jsdom cannot judge it, so it is covered by the
// token contrast table in docs/07 and the manual run-through in docs/11.
const RULES = { 'color-contrast': { enabled: false } };

async function violations() {
  const r = await axe.run(document.body, { rules: RULES });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(' | ')}`);
}

describe.each(['en', 'vi'])('accessibility (%s)', (lang) => {
  beforeEach(async () => {
    await act(async () => {
      await i18n.changeLanguage(lang);
      start();
    });
  });

  it('every page has no axe violations and the sidebar is keyboard reachable', async () => {
    render(<App />);
    const nav = Array.from(document.querySelectorAll<HTMLButtonElement>('nav.sidebar button.nav-item'));
    expect(nav.length).toBeGreaterThanOrEqual(8);
    for (const item of nav) {
      await userEvent.click(item);
      await screen.findByRole('heading', { level: 1 });
      expect(await violations(), item.textContent ?? '').toEqual([]);
    }
    document.body.focus();
    await userEvent.tab();
    expect(document.activeElement).not.toBe(document.body);
  });
});
