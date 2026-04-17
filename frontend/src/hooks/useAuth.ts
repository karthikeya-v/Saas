import { useEffect, useState } from 'react';
import { getToken } from '../api/client';

export function useAuth(): { authed: boolean; refresh: () => void } {
  const [authed, setAuthed] = useState<boolean>(() => !!getToken());

  useEffect(() => {
    const onStorage = () => setAuthed(!!getToken());
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  return {
    authed,
    refresh: () => setAuthed(!!getToken()),
  };
}
