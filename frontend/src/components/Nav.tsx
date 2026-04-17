import { NavLink, useNavigate } from 'react-router-dom';
import { clearToken } from '../api/client';

const tabs: { to: string; label: string }[] = [
  { to: '/today', label: 'Today' },
  { to: '/plan', label: 'Plan' },
  { to: '/review', label: 'Review' },
];

export default function Nav(): JSX.Element {
  const navigate = useNavigate();

  const logout = () => {
    clearToken();
    navigate('/login');
  };

  return (
    <nav className="sticky top-0 z-10 border-b border-slate-200 bg-white/80 backdrop-blur">
      <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-3">
        <div className="flex items-center gap-6">
          <span className="font-semibold tracking-tight">TimeGrid</span>
          <div className="flex gap-4 text-sm">
            {tabs.map((t) => (
              <NavLink
                key={t.to}
                to={t.to}
                className={({ isActive }) =>
                  isActive
                    ? 'text-ink font-medium'
                    : 'text-slate-500 hover:text-ink'
                }
              >
                {t.label}
              </NavLink>
            ))}
          </div>
        </div>
        <button
          onClick={logout}
          className="text-sm text-slate-500 hover:text-ink"
        >
          Sign out
        </button>
      </div>
    </nav>
  );
}
