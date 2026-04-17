# TimeGrid iOS

SwiftUI app that pings you every hour, reads Screen Time, and logs every
minute of your day.

## Requirements

- Xcode 15+
- iOS 16.4+ on a physical iPhone (Screen Time APIs are not available in the
  simulator)
- An Apple ID signed into Xcode (free personal team works for on-device dev)

## Creating the Xcode project

This folder contains the Swift sources, entitlements, and `Info.plist`. The
`.xcodeproj` is not checked in — generate it once:

1. Open Xcode → **File → New → Project → iOS → App**
2. Name: `TimeGrid`, Interface: **SwiftUI**, Language: **Swift**, Minimum
   deployment: **iOS 16.4**
3. Save inside `ios/TimeGrid/` (overwrite Xcode's default files with the
   sources already in this folder)
4. Add two additional targets:
   - **Device Activity Report Extension** named `TimeGridReport`
   - **Widget Extension** named `TimeGridWidget`
5. **Signing & Capabilities** for the main app:
   - Enable **Family Controls**
   - Add **App Groups** → `group.com.timegrid`
   - Enable **Background Modes** → Background fetch, Background processing
6. Copy the same App Group capability to the `TimeGridReport` target.
7. Set `TG_API_BASE` in `Info.plist` to your backend (defaults to
   `http://127.0.0.1:8000` for local dev; point at Azure for prod).

## First run

1. Build + run on your iPhone.
2. Accept the notification permission prompt.
3. Accept the Screen Time (FamilyControls) authorization prompt.
4. Tap the bell icon on the Now screen to fire a test notification.
5. Watch for the top-of-hour ping (or wait overnight — Screen Time
   aggregation runs via the Report extension in the background).

## Backend connection

- Local dev: `docker compose up -d` in the repo root, then the app talks to
  `http://127.0.0.1:8000`.
- Dev token (no Sign in with Apple yet): call
  `POST /v1/auth/dev?apple_sub=me&tz=America/Los_Angeles` once, save the
  returned JWT into the Keychain via `TokenStorage.save(...)`.

## Files

- `TimeGrid/App/` — app entry, config
- `TimeGrid/Views/` — Now, Today, Plan, Review screens
- `TimeGrid/Model/` — `Block`, `BlockStore`, `LocalCategorizer`
- `TimeGrid/Notifications/` — hourly scheduler + response delegate
- `TimeGrid/ScreenTime/` — FamilyControls auth + App Group bridge
- `TimeGrid/Sync/` — API client, keychain token, sync engine
- `TimeGridReport/` — DeviceActivityReport extension that writes usage
  JSON into the shared App Group container
- `TimeGridWidget/` — home-screen widget
