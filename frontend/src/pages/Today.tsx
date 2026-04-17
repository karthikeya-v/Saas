import type { FormEvent } from 'react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { listBlocks, postBlocks } from '../api/client';
import type { Block } from '../api/types';
import CategoryBadge from '../components/CategoryBadge';

function startOfDay(d: Date): Date {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  return x;
}

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });
}

function minutesBetween(a: string, b: string): number {
  return Math.max(
    0,
    Math.round((new Date(b).getTime() - new Date(a).getTime()) / 60000),
  );
}

function lastBoundary(blocks: Block[]): Date {
  if (blocks.length === 0) {
    const d = new Date();
    d.setMinutes(0, 0, 0);
    d.setHours(d.getHours() - 1);
    return d;
  }
  return new Date(blocks[blocks.length - 1].end_ts);
}

export default function Today(): JSX.Element {
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [draft, setDraft] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const today = useMemo(() => startOfDay(new Date()), []);
  const tomorrow = useMemo(() => {
    const d = new Date(today);
    d.setDate(d.getDate() + 1);
    return d;
  }, [today]);

  const refresh = useCallback(async () => {
    try {
      const rows = await listBlocks(today, tomorrow);
      rows.sort((a, b) => a.start_ts.localeCompare(b.start_ts));
      setBlocks(rows);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [today, tomorrow]);

  useEffect(() => {
    void refresh();
    const id = setInterval(refresh, 60_000);
    return () => clearInterval(id);
  }, [refresh]);

  const logCheckin = async (e: FormEvent) => {
    e.preventDefault();
    const activity = draft.trim();
    if (!activity) return;
    setBusy(true);
    setErr(null);
    try {
      const end = new Date();
      const start = lastBoundary(blocks);
      await postBlocks([
        {
          client_id: crypto.randomUUID(),
          start_ts: start.toISOString(),
          end_ts: end.toISOString(),
          source: 'checkin',
          activity,
        },
      ]);
      setDraft('');
      await refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const recent = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (let i = blocks.length - 1; i >= 0 && out.length < 6; i--) {
      const a = blocks[i].activity;
      if (a && !seen.has(a)) {
        seen.add(a);
        out.push(a);
      }
    }
    return out;
  }, [blocks]);

  const quickLog = async (activity: string) => {
    setBusy(true);
    try {
      const end = new Date();
      const start = lastBoundary(blocks);
      await postBlocks([
        {
          client_id: crypto.randomUUID(),
          start_ts: start.toISOString(),
          end_ts: end.toISOString(),
          source: 'checkin',
          activity,
        },
      ]);
      await refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-8 px-6 py-8">
      <section>
        <h1 className="text-3xl font-semibold tracking-tight">
          What are you doing?
        </h1>
        <p className="text-slate-500">
          {new Date().toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
          })}{' '}
          · logs the block since your last entry
        </p>
      </section>

      {recent.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {recent.map((r) => (
            <button
              key={r}
              onClick={() => quickLog(r)}
              disabled={busy}
              className="rounded-full bg-slate-100 px-3 py-1 text-sm hover:bg-slate-200 disabled:opacity-60"
            >
              {r}
            </button>
          ))}
        </div>
      )}

      <form onSubmit={logCheckin} className="flex gap-2">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="e.g. deep work on spec"
          className="flex-1 rounded border border-slate-300 px-3 py-2"
          autoFocus
        />
        <button
          disabled={busy || !draft.trim()}
          className="rounded bg-ink px-4 py-2 text-white disabled:opacity-60"
        >
          Save
        </button>
      </form>
      {err && <p className="text-sm text-red-600">{err}</p>}

      <section>
        <h2 className="mb-3 text-lg font-medium">Today</h2>
        {blocks.length === 0 ? (
          <p className="text-sm text-slate-500">No blocks yet.</p>
        ) : (
          <ul className="divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white">
            {blocks.map((b) => (
              <li
                key={b.client_id}
                className="flex items-start justify-between gap-3 px-4 py-3"
              >
                <div>
                  <div className="text-sm font-medium">
                    {b.activity || b.app || '—'}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
                    <span>
                      {fmtTime(b.start_ts)} – {fmtTime(b.end_ts)}
                    </span>
                    <span>·</span>
                    <span>{minutesBetween(b.start_ts, b.end_ts)}m</span>
                    <span>·</span>
                    <span className="capitalize">{b.source}</span>
                  </div>
                </div>
                <CategoryBadge category={b.category} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
