import { useEffect, useMemo, useState } from 'react';
import { getPlan, savePlan } from '../api/client';
import type { PlannedBlock } from '../api/types';

function tomorrow(): Date {
  const d = new Date();
  d.setDate(d.getDate() + 1);
  d.setHours(0, 0, 0, 0);
  return d;
}

function isoFor(base: Date, hour: number): string {
  const d = new Date(base);
  d.setHours(hour, 0, 0, 0);
  return d.toISOString();
}

interface Slot {
  hour: number;
  category: string;
  note: string;
}

const HOURS = Array.from({ length: 15 }, (_, i) => i + 8); // 08..22

export default function Plan(): JSX.Element {
  const day = useMemo(() => tomorrow(), []);
  const dayISO = useMemo(() => day.toISOString().slice(0, 10), [day]);

  const [slots, setSlots] = useState<Slot[]>(
    HOURS.map((h) => ({ hour: h, category: '', note: '' })),
  );
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const existing = await getPlan(dayISO);
        if (existing.length === 0) return;
        setSlots((prev) =>
          prev.map((slot) => {
            const match = existing.find(
              (p) => new Date(p.start_ts).getHours() === slot.hour,
            );
            return match
              ? {
                  ...slot,
                  category: match.category || '',
                  note: match.note || '',
                }
              : slot;
          }),
        );
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [dayISO]);

  const update = (hour: number, patch: Partial<Slot>) =>
    setSlots((prev) =>
      prev.map((s) => (s.hour === hour ? { ...s, ...patch } : s)),
    );

  const save = async () => {
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      const payload: PlannedBlock[] = slots
        .filter((s) => s.category.trim() || s.note.trim())
        .map((s) => ({
          day: dayISO,
          start_ts: isoFor(day, s.hour),
          end_ts: isoFor(day, s.hour + 1),
          category: s.category.trim() || null,
          note: s.note.trim() || null,
        }));
      const { saved } = await savePlan(payload);
      setMsg(`Saved ${saved} block${saved === 1 ? '' : 's'} for ${dayISO}.`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6 px-6 py-8">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Plan</h1>
          <p className="text-slate-500">
            {day.toLocaleDateString(undefined, {
              weekday: 'long',
              month: 'short',
              day: 'numeric',
            })}
          </p>
        </div>
        <button
          onClick={save}
          disabled={busy}
          className="rounded bg-ink px-4 py-2 text-white disabled:opacity-60"
        >
          {busy ? 'Saving…' : 'Save plan'}
        </button>
      </header>
      <div className="rounded-lg border border-slate-200 bg-white">
        <table className="w-full text-sm">
          <thead className="border-b border-slate-200 text-left text-slate-500">
            <tr>
              <th className="px-4 py-2 font-medium">Hour</th>
              <th className="px-4 py-2 font-medium">Category</th>
              <th className="px-4 py-2 font-medium">Intent</th>
            </tr>
          </thead>
          <tbody>
            {slots.map((s) => (
              <tr key={s.hour} className="border-b border-slate-100 last:border-0">
                <td className="px-4 py-2 font-mono">
                  {String(s.hour).padStart(2, '0')}:00
                </td>
                <td className="px-4 py-2">
                  <input
                    value={s.category}
                    onChange={(e) => update(s.hour, { category: e.target.value })}
                    placeholder="work / rest / exercise…"
                    className="w-full rounded border border-slate-200 px-2 py-1"
                  />
                </td>
                <td className="px-4 py-2">
                  <input
                    value={s.note}
                    onChange={(e) => update(s.hour, { note: e.target.value })}
                    placeholder="what specifically?"
                    className="w-full rounded border border-slate-200 px-2 py-1"
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {msg && <p className="text-sm text-green-700">{msg}</p>}
      {err && <p className="text-sm text-red-600">{err}</p>}
    </div>
  );
}
