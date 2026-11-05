import type { TFunction } from 'i18next';
import type { ReactNode } from 'react';

export interface RichTipContent {
  title: string;
  summary: string;
  points?: readonly string[];
  note?: string;
}

/** Reads a tip object (title, summary, points, note) from the translation table. */
export function tipOf(t: TFunction, key: string): RichTipContent {
  const points = t(`${key}.points`, { returnObjects: true, defaultValue: [] }) as unknown;
  const note = t(`${key}.note`, { defaultValue: '' });
  return {
    title: t(`${key}.title`),
    summary: t(`${key}.summary`),
    points: Array.isArray(points) ? (points as string[]) : undefined,
    note: note || undefined,
  };
}

interface RichTipProps {
  tip: RichTipContent;
  /** Where the card opens relative to the trigger. */
  side?: 'top' | 'bottom';
  children: ReactNode;
}

/** Hover/focus card with a title, a summary, bullet points and a footnote; no JS state, keyboard reachable. */
export function RichTip({ tip, side = 'bottom', children }: RichTipProps) {
  return (
    <span className={`rtip rtip-${side}`}>
      {children}
      <span className="rtip-card" role="tooltip">
        <strong className="rtip-title">{tip.title}</strong>
        <span className="rtip-summary">{tip.summary}</span>
        {tip.points && (
          <ul className="rtip-points">
            {tip.points.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        )}
        {tip.note && <span className="rtip-note">{tip.note}</span>}
      </span>
    </span>
  );
}
