import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { act } from 'react';
import { App } from './App';
import i18n from './i18n';
import { en, vi } from './i18n/locales';
import { start } from './store';

function keys(o: object, prefix = ''): string[] {
  return Object.entries(o).flatMap(([k, v]) =>
    typeof v === 'object' && v !== null ? keys(v, `${prefix}${k}.`) : [`${prefix}${k}`],
  );
}

describe('i18n', () => {
  it('vi has exactly the keys of en', () => {
    expect(keys(vi).sort()).toEqual(keys(en).sort());
  });
});

describe('App', () => {
  it('renders the mock snapshot and filters processes by verdict', async () => {
    await act(async () => {
      await i18n.changeLanguage('en');
      start();
    });
    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: 'Processes' }));
    expect(await screen.findByText('process-0.exe')).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('All verdicts'), 'malicious');
    expect(screen.getByText('40 rows')).toBeInTheDocument();
  });

  it('switches language', async () => {
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage('vi');
    });
    expect(screen.getByRole('button', { name: 'Tiến trình' })).toBeInTheDocument();
  });
});
