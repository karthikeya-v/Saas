const COLORS: Record<string, string> = {
  work: '#4f8cff',
  social: '#ff5c8a',
  messaging: '#ffb347',
  email: '#c08cff',
  browsing: '#9aa5b1',
  video: '#ff715b',
  music: '#4cc9f0',
  audio: '#4cc9f0',
  learning: '#3ddc97',
  reading: '#38b000',
  exercise: '#ef476f',
  rest: '#8ecae6',
  sleep: '#264653',
  meal: '#e9c46a',
  commute: '#a0a0a0',
  chores: '#ddbea9',
  uncategorized: '#cbd5e1',
  gap: '#e5e7eb',
};

export function colorFor(category?: string | null): string {
  return COLORS[category || 'uncategorized'] ?? COLORS.uncategorized;
}

export default function CategoryBadge({
  category,
}: {
  category?: string | null;
}): JSX.Element {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs"
      style={{ backgroundColor: `${colorFor(category)}22` }}
    >
      <span
        className="h-2 w-2 rounded-full"
        style={{ backgroundColor: colorFor(category) }}
      />
      {category || 'uncategorized'}
    </span>
  );
}
