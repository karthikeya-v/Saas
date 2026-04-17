import type { Block, PlannedBlock, TodaySummary } from './types';

const TOKEN_KEY = 'tg_token';
const BASE = '/api';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  auth = true,
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  if (auth) {
    const token = getToken();
    if (!token) throw new Error('not authenticated');
    headers.set('Authorization', `Bearer ${token}`);
  }
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export async function devLogin(appleSub: string, tz: string): Promise<string> {
  const qs = new URLSearchParams({ apple_sub: appleSub, tz });
  const data = await request<{ token: string }>(
    `/v1/auth/dev?${qs.toString()}`,
    { method: 'POST' },
    false,
  );
  setToken(data.token);
  return data.token;
}

export function listBlocks(from: Date, to: Date): Promise<Block[]> {
  const qs = new URLSearchParams({
    from: from.toISOString(),
    to: to.toISOString(),
  });
  return request(`/v1/blocks?${qs.toString()}`);
}

export function postBlocks(blocks: Block[]): Promise<{ accepted: number }> {
  return request('/v1/blocks', {
    method: 'POST',
    body: JSON.stringify({ blocks }),
  });
}

export function todaySummary(): Promise<TodaySummary> {
  return request('/v1/summary/today');
}

export function getPlan(day: string): Promise<PlannedBlock[]> {
  return request(`/v1/plan?day=${encodeURIComponent(day)}`);
}

export function savePlan(blocks: PlannedBlock[]): Promise<{ saved: number }> {
  return request('/v1/plan', {
    method: 'POST',
    body: JSON.stringify(blocks),
  });
}

export function health(): Promise<{ status: string }> {
  return request('/health', {}, false);
}
