import { useEffect, useState } from 'react';
import { todaySummary } from '../api/client';
import type { TodaySummary } from '../api/types';
import CategoryPie from '../components/CategoryPie';

export default function Review(): JSX.Element {
  const [data, setData] = useState<TodaySummary | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const load = () =>
      todaySummary().then(setData).catch((e) => setErr(String(e)));
    void load();
    const id = setInterval(load, 60_000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="mx-auto max-w-3xl space-y-8 px-6 py-8">
      <h1 className="text-3xl font-semibold tracking-tight">Review</h1>

      {err && <p className="text-sm text-red-600">{err}</p>}

      {data && (
        <>
          <div className="grid grid-cols-3 gap-4">
            <Stat
              label="Accounted"
              value={`${data.accounted_minutes}m`}
              sub="today"
            />
            <Stat
              label="Unaccounted"
              value={`${data.unaccounted_minutes}m`}
              sub="target 0"
              emphasis={
                data.unaccounted_minutes > 30
                  ? 'bad'
                  : data.unaccounted_minutes > 0
                    ? 'warn'
                    : 'good'
              }
            />
            <Stat
              label="Tracked total"
              value={`${data.total_minutes}m`}
              sub="since midnight"
            />
          </div>

          <section className="rounded-lg border border-slate-200 bg-white p-6">
            <h2 className="mb-4 text-lg font-medium">Today by category</h2>
            <CategoryPie buckets={data.buckets} />
          </section>

          <p className="text-xs text-slate-500">
            Dashboard also available in Grafana at{' '}
            <a
              href="http://localhost:4500"
              target="_blank"
              rel="noreferrer"
              className="underline"
            >
              localhost:4500
            </a>
            .
          </p>
        </>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  sub,
  emphasis = 'neutral',
}: {
  label: string;
  value: string;
  sub?: string;
  emphasis?: 'neutral' | 'good' | 'warn' | 'bad';
}): JSX.Element {
  const tone = {
    neutral: 'text-ink',
    good: 'text-green-700',
    warn: 'text-amber-600',
    bad: 'text-red-600',
  }[emphasis];
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${tone}`}>
        {value}
      </div>
      {sub && <div className="text-xs text-slate-500">{sub}</div>}
    </div>
  );
}
