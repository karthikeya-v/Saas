import type { SummaryBucket } from '../api/types';
import { colorFor } from './CategoryBadge';

const SIZE = 160;
const RADIUS = 70;

export default function CategoryPie({
  buckets,
}: {
  buckets: SummaryBucket[];
}): JSX.Element | null {
  const total = buckets.reduce((s, b) => s + b.minutes, 0);
  if (total === 0) {
    return (
      <div className="flex h-[160px] items-center text-sm text-slate-500">
        No data yet — log a check-in to get started.
      </div>
    );
  }
  let angle = -Math.PI / 2;
  const paths = buckets.map((b) => {
    const slice = (b.minutes / total) * 2 * Math.PI;
    const start = angle;
    const end = angle + slice;
    angle = end;
    const large = slice > Math.PI ? 1 : 0;
    const x1 = SIZE / 2 + RADIUS * Math.cos(start);
    const y1 = SIZE / 2 + RADIUS * Math.sin(start);
    const x2 = SIZE / 2 + RADIUS * Math.cos(end);
    const y2 = SIZE / 2 + RADIUS * Math.sin(end);
    const d = [
      `M ${SIZE / 2} ${SIZE / 2}`,
      `L ${x1} ${y1}`,
      `A ${RADIUS} ${RADIUS} 0 ${large} 1 ${x2} ${y2}`,
      'Z',
    ].join(' ');
    return <path key={b.category} d={d} fill={colorFor(b.category)} />;
  });

  return (
    <div className="flex items-center gap-6">
      <svg width={SIZE} height={SIZE}>
        {paths}
      </svg>
      <ul className="space-y-1 text-sm">
        {buckets.map((b) => (
          <li key={b.category} className="flex items-center gap-2">
            <span
              className="h-2.5 w-2.5 rounded-full"
              style={{ backgroundColor: colorFor(b.category) }}
            />
            <span className="capitalize">{b.category}</span>
            <span className="text-slate-500">{b.minutes}m</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
