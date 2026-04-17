# TimeGrid — minute-level time tracker

Account for every minute of your day. The iPhone app pings you every hour
(on-device, no server required), reads Screen Time for automatic phone
usage, and syncs everything to a backend so you can plan, review, and
hold yourself accountable at the minute level.

## Components

- `ios/TimeGrid/` — SwiftUI iPhone app. Local hourly notifications,
  FamilyControls / DeviceActivity Screen Time ingestion, Keychain-backed
  JWT, offline-first sync. See [`ios/README.md`](ios/README.md).
- `backend/` — FastAPI + MySQL. Endpoints for block upload, summary,
  and plan. Minute-level reconciliation job runs every 5 minutes.
- `grafana/provisioning/` — MySQL datasource + `TimeGrid` dashboard
  (category pie, 7-day heatmap, unaccounted stat, planned-vs-actual).
- `infra/` — Azure Bicep for App Service + MySQL Flexible Server +
  Key Vault + App Insights. Uses your Azure credits.
- `.github/workflows/` — Backend tests, iOS Swift syntax check, and
  Azure deploy via OIDC federation.
- `legacy/` — the original DNS/SaaS analytics pipeline from this repo,
  preserved but not wired up.

## Local dev

```bash
docker compose up -d
```

- MySQL: `localhost:3306`
- Backend: `http://localhost:8000` (see `/docs`)
- Grafana: `http://localhost:4500` (admin / admin)

### Quick test

```bash
# 1. Get a dev JWT
TOKEN=$(curl -s -X POST 'http://localhost:8000/v1/auth/dev?apple_sub=me&tz=UTC' | jq -r .token)

# 2. Upload fixture blocks
curl -s -X POST http://localhost:8000/v1/blocks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @backend/tests/fixtures/blocks.json

# 3. Today summary
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/v1/summary/today | jq
```

The 5-minute merge job will populate the `minutes` table; Grafana reads
from it.

## iOS setup

See [`ios/README.md`](ios/README.md). Short version: open Xcode, create a
new iOS app in `ios/TimeGrid/` using the Swift sources that are already
there, enable the **Family Controls** capability and the App Group
`group.com.timegrid`, build on a physical iPhone.

## Azure deploy

Prereqs: an Azure resource group, a service principal configured for
GitHub OIDC, and these repo secrets:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `AZURE_RESOURCE_GROUP`
- `AZURE_APP_NAME`

Then:

```bash
# One-off: deploy infra to dev
az deployment group create \
  --resource-group "$AZ_RG" \
  --template-file infra/main.bicep \
  --parameters @infra/parameters.dev.json
```

Subsequent pushes to `main` trigger `.github/workflows/deploy-backend.yml`.
Point the iOS app at the deployed hostname by setting `TG_API_BASE` in
`ios/TimeGrid/TimeGrid/Info.plist`.

## Data model

Three sources flow into the same `blocks` table: `phone` (from Screen
Time), `checkin` (from hourly notifications), and `manual` (edits). A
merge job materializes a `minutes` table with one row per minute per
user, with `source='gap'` for unaccounted time. Grafana and the iOS
Review tab both read the `minutes` table.

## Design notes

- **Why native iOS, not a PWA?** Local hourly notifications fire with no
  server and no network. FamilyControls gives first-class Screen Time
  access. PWAs on iOS can't do either reliably.
- **Why the server then?** History, cross-device aggregation, Grafana,
  and future plan-vs-actual comparisons. The phone works offline and
  syncs when it can.
- **Why minutes and not seconds?** Minute granularity matches how humans
  plan, keeps the dashboard legible, and gives us ~1440 points per day
  per user — plenty of signal, cheap to store.
