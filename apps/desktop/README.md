# Sisumail Desktop (Tauri) - WIP

Goal: a single installable app for normal users on Windows + Linux.

This app is a thin shell that will:
- bundle/run the `sisumail` core in the background
- open the built-in local UI (`/app/onboard`, `/app/inbox`, `/app/chat`)
- manage restart, logs, and safe host-key changes

Status: scaffold only. Network/DNS issues in the dev environment can prevent `npm install` / `cargo build` from working right now.

## Dev (later)

```bash
cd apps/desktop
npm install
npm run tauri dev
```

