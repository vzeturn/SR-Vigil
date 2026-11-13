import { vi as vitest } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { act } from 'react';
import { App } from './App';
import { getBridge } from './bridge';
import i18n from './i18n';
import { start } from './store';

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

  it('opens the vendor download page of an out-of-date program', async () => {
    await act(async () => {
      await i18n.changeLanguage('en');
      start();
    });
    const open = vitest.spyOn(window, 'open').mockReturnValue(null);
    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: 'Processes' }));
    await userEvent.click(
      await screen.findByRole('button', { name: 'Open the vendor download page for Mock App' }),
    );
    expect(open).toHaveBeenCalledWith('https://example.com/download', '_blank', 'noopener,noreferrer');
    open.mockRestore();
  });
});

describe('M3 screens', () => {
  beforeEach(async () => {
    await act(async () => {
      await i18n.changeLanguage('en');
      start();
    });
  });

  it('lists pending items with no default action and submits with the chosen scope', async () => {
    const bridge = await getBridge();
    const rpc = vitest.spyOn(bridge, 'rpc');
    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: /Pending/ }));
    expect(await screen.findByText('tool-0.exe')).toBeInTheDocument();
    expect(rpc).not.toHaveBeenCalledWith('decision.submit', expect.anything());
    expect(document.querySelectorAll('[aria-pressed="true"], [aria-checked="true"]')).toHaveLength(0);

    await userEvent.selectOptions(screen.getAllByLabelText('Duration')[0] as HTMLElement, '24h');
    await userEvent.click(screen.getAllByRole('button', { name: 'Allow' })[0] as HTMLElement);
    expect(rpc).toHaveBeenCalledWith('decision.submit', {
      pending_id: 'pending-0',
      action: 'allow',
      scope: '24h',
      apply_to: 'file',
    });
    rpc.mockRestore();
  });

  it('offers a package-family decision only for a launcher in a trusted package family', async () => {
    const bridge = await getBridge();
    const rpc = vitest.spyOn(bridge, 'rpc');
    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: /Pending/ }));
    await screen.findByText('tool-1.exe');
    const selects = screen.getAllByLabelText('Apply to') as HTMLSelectElement[];
    const enabled = selects.map((sel) => !sel.querySelector<HTMLOptionElement>('option[value="package_source"]')?.disabled);
    expect(enabled.filter(Boolean)).toHaveLength(1);
    const i = enabled.indexOf(true);
    await userEvent.selectOptions(selects[i] as HTMLElement, 'package_source');
    await userEvent.click(screen.getAllByRole('button', { name: 'Allow' })[i] as HTMLElement);
    expect(rpc).toHaveBeenCalledWith('decision.submit', {
      pending_id: 'pending-1',
      action: 'allow',
      scope: 'once',
      apply_to: 'package_source',
    });
    rpc.mockRestore();
  });

  it('keeps inbound blocking off until the user turns it on', async () => {
    const bridge = await getBridge();
    const rpc = vitest.spyOn(bridge, 'rpc');
    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: 'Settings' }));
    const box = await screen.findByRole('checkbox', { name: 'Block incoming connections to blocked programs' });
    expect(box).not.toBeChecked();
    await userEvent.click(box);
    expect(rpc).toHaveBeenCalledWith('settings.set', { settings: { enforcement: { block_inbound: true } } });
    expect(box).toBeChecked();
    rpc.mockRestore();
  });

  it('shows the broken audit chain with text, not colour alone', async () => {
    const bridge = await getBridge();
    const rpc = vitest.spyOn(bridge, 'rpc').mockResolvedValue({ items: [], next_cursor: null, chain_ok: false });
    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: 'Audit' }));
    expect(await screen.findByText('Chain broken')).toBeInTheDocument();
    rpc.mockRestore();
  });

  it('traps focus in the review wizard and closes on Esc', async () => {
    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: /Pending/ }));
    const opener = (await screen.findAllByRole('button', { name: 'Review' }))[0] as HTMLElement;
    await userEvent.click(opener);
    const dialog = screen.getByRole('dialog', { name: /Review tool-/ });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
    for (let i = 0; i < 12; i++) {
      await userEvent.tab();
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
    }
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });
});
