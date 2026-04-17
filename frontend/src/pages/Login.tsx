import type { FormEvent } from 'react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { devLogin } from '../api/client';

export default function Login(): JSX.Element {
  const navigate = useNavigate();
  const [sub, setSub] = useState('me');
  const [tz, setTz] = useState(
    Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
  );
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await devLogin(sub, tz);
      navigate('/today');
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto mt-24 max-w-sm px-6">
      <h1 className="mb-1 text-3xl font-semibold tracking-tight">TimeGrid</h1>
      <p className="mb-8 text-sm text-slate-500">
        Every minute accounted for.
      </p>
      <form onSubmit={submit} className="space-y-3">
        <label className="block text-sm">
          <span className="mb-1 block text-slate-600">Identifier</span>
          <input
            value={sub}
            onChange={(e) => setSub(e.target.value)}
            className="w-full rounded border border-slate-300 px-3 py-2"
            required
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block text-slate-600">Time zone</span>
          <input
            value={tz}
            onChange={(e) => setTz(e.target.value)}
            className="w-full rounded border border-slate-300 px-3 py-2"
            required
          />
        </label>
        <button
          disabled={busy}
          className="mt-2 w-full rounded bg-ink px-3 py-2 text-white disabled:opacity-60"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        {err && <p className="text-sm text-red-600">{err}</p>}
        <p className="text-xs text-slate-500">
          Dev mode only. Sign in with Apple is on the roadmap.
        </p>
      </form>
    </div>
  );
}
