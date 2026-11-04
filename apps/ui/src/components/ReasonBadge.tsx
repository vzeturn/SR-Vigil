import { Ban, CircleCheck, Lock, ShieldAlert, TriangleAlert, type LucideIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { LocalReason } from '../bridge';

export const title = (name: string) => {
  const s = name.replaceAll('_', ' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
};

function iconOf(r: Pick<LocalReason, 'kind' | 'delta'>): { Icon: LucideIcon; tone: string } {
  if (r.kind === 'hard_rule') return { Icon: Ban, tone: 'malicious' };
  if (r.kind === 'guard') return { Icon: Lock, tone: 'safe' };
  if (r.kind === 'hard_allow') return { Icon: CircleCheck, tone: 'safe' };
  return (r.delta ?? 0) < 0 ? { Icon: TriangleAlert, tone: 'unknown' } : { Icon: ShieldAlert, tone: 'safe' };
}

interface ReasonBadgeProps {
  reason: Pick<LocalReason, 'id' | 'name' | 'kind' | 'delta' | 'description'>;
  /** Show the title next to the icon; otherwise icon-only with the title in the tooltip. */
  label?: boolean;
}

/** Icon + short title; the full explanation, rule id and score effect live in the tooltip. */
export function ReasonBadge({ reason, label = false }: ReasonBadgeProps) {
  const { t } = useTranslation();
  const { Icon, tone } = iconOf(reason);
  const effect =
    reason.delta === null
      ? t(`live.kind.${reason.kind}`)
      : t('live.effect', { delta: (reason.delta > 0 ? '+' : '') + reason.delta });
  const tip = `${title(reason.name)}\n${reason.description}\n${reason.id} · ${effect}`;
  return (
    <span className={`rbadge tone-${tone}`} data-tip={tip} tabIndex={0} aria-label={tip.replaceAll('\n', '. ')}>
      <Icon size={14} aria-hidden="true" />
      {label && <span className="rbadge-title">{title(reason.name)}</span>}
    </span>
  );
}
