import { OctagonAlert, TriangleAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { Reputation } from '../types';

const look = {
  bad: { Icon: OctagonAlert, tone: 'malicious' },
  risky: { Icon: TriangleAlert, tone: 'unknown' },
} as const;

/** Offline destination reputation (docs/15 §4): icon plus text, never colour alone. */
export function ReputationChip({ reputation }: { reputation?: Reputation | null }) {
  const { t } = useTranslation();
  if (!reputation) return null;
  const { Icon, tone } = look[reputation];
  return (
    <span className={`chip ${tone}`} title={t(`reputation.${reputation}Hint`)}>
      <Icon size={14} aria-hidden="true" />
      {t(`reputation.${reputation}`)}
    </span>
  );
}
