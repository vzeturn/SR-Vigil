import type { Verdict } from '../types';

/** Trust score 0-100 as a thin bar plus the number, so colour is never the only signal. */
export function ScoreBar({ score, verdict }: { score?: number | null; verdict?: Verdict | null }) {
  if (score == null) return null;
  return (
    <span className="scorebar">
      <span className={`scorebar-track tone-${verdict ?? 'unknown'}`} aria-hidden="true">
        <span style={{ width: `${Math.max(0, Math.min(100, score))}%` }} />
      </span>
      <span className="mono scorebar-num">{score}</span>
    </span>
  );
}
