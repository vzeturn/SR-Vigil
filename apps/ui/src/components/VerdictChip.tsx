import { ShieldCheck, ShieldQuestion, ShieldX } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { Verdict } from '../types';

const icons = { safe: ShieldCheck, unknown: ShieldQuestion, malicious: ShieldX } as const;

interface VerdictChipProps {
  verdict?: Verdict | null;
}

/** Colour plus icon plus text: a verdict is never conveyed by colour alone. */
export function VerdictChip({ verdict }: VerdictChipProps) {
  const { t } = useTranslation();
  if (!verdict) return <span className="muted">{t('verdict.none')}</span>;
  const Icon = icons[verdict];
  return (
    <span className={`chip ${verdict}`}>
      <Icon size={14} aria-hidden="true" />
      {t(`verdict.${verdict}`)}
    </span>
  );
}
