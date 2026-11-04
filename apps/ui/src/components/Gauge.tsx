import { Num } from './Num';

interface GaugeProps {
  /** 0-100. */
  value: number;
  label: string;
  tone: 'safe' | 'unknown' | 'malicious';
  large?: boolean;
}

const R = 52;
const C = 2 * Math.PI * R;

/** Radial meter; the number is always printed, so colour is never the only signal. */
export function Gauge({ value, label, tone, large }: GaugeProps) {
  const v = Math.max(0, Math.min(100, value));
  return (
    <div className={`gauge tone-${tone}${large ? ' large' : ''}`} role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={v} aria-label={label}>
      <svg viewBox="0 0 120 120" aria-hidden="true">
        <circle className="gauge-track" cx="60" cy="60" r={R} />
        <circle className="gauge-fill" cx="60" cy="60" r={R} strokeDasharray={`${(C * v) / 100} ${C}`} />
      </svg>
      <span key={`${tone}-${Math.round(v)}`} className="gauge-ripple" aria-hidden="true" />
      <strong className="gauge-value">
        <Num value={v} />
      </strong>
    </div>
  );
}
