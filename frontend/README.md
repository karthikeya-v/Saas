# TimeGrid Web Frontend

Vite + React + TypeScript + Tailwind. Day-to-day dashboard: log a check-in,
plan tomorrow hour-by-hour, review today.

## Local dev

With the full stack up:

```bash
docker compose up -d
open http://localhost:5173
```

That serves the built SPA behind nginx and proxies `/api/*` to the backend
container.

For hot-reload development against the backend container, run Vite on the
host instead:

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173, proxies /api -> http://backend:8000
```

If you're not running the backend inside Docker, edit `vite.config.ts` and
point the `/api` proxy at `http://localhost:8000`.

## Structure

```
src/
  api/
    client.ts      # fetch wrapper, JWT handling
    types.ts       # Block, TodaySummary, PlannedBlock
  components/
    Nav.tsx
    CategoryBadge.tsx
    CategoryPie.tsx
  hooks/
    useAuth.ts
  pages/
    Login.tsx      # dev JWT entry (apple_sub + tz)
    Today.tsx      # check-in + block list
    Plan.tsx       # hour-by-hour editor for tomorrow
    Review.tsx     # stats + category pie
  App.tsx          # router + auth guard
  main.tsx
  index.css
```

## Auth

For now the frontend uses `POST /v1/auth/dev` to mint a JWT by apple_sub.
This is the same personal-JWT path the iOS app uses in dev. Once Sign in
with Apple is wired up, swap `devLogin` in `api/client.ts` for the real
flow.
