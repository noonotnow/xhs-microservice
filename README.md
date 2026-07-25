# XHS Microservice

FastAPI microservice for interacting with Xiaohongshu (小红书) via the [ReaJason/xhs](https://github.com/ReaJason/xhs) library.

Handles QR login, session persistence, image upload, and note publishing/scheduling to real Xiaohongshu.

## Architecture

```
Next.js (xhs-platform)
    ↓ HTTP + API key
This Microservice (FastAPI + Playwright)
    ↓ Signed requests
Real Xiaohongshu API
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/login/qr` | Start QR login flow, returns QR data |
| GET | `/login/status` | Check QR scan status, saves session on success |
| GET | `/session/status` | Check if current session is valid |
| POST | `/upload` | Upload an image file (returns local path) |
| POST | `/publish` | Publish or schedule a note |

All endpoints (except `/health`) require `X-Api-Key` header.

## QR Login Flow

1. `GET /login/qr` → returns `{qr_id, code, url}`
2. Convert `url` to QR code image, scan with XHS app
3. Poll `GET /login/status` until `code_status == 2`
4. Session cookie is saved automatically

## Publishing Flow

1. `POST /upload` with image file → returns `{filepath}`
2. `POST /publish` with title, desc, files (from step 1), optional post_time

## Scheduling

Pass `post_time` in format `"YYYY-MM-DD HH:MM:SS"` to schedule a post.
XHS handles the actual publishing at the scheduled time.

## Deployment (Railway)

1. Push to GitHub
2. Connect repo in Railway
3. Add a volume mount at `/app/data` (stores cookies, state, and uploads)
4. Set env var: `XHS_API_KEY=<your-secret>`
5. Deploy

## Local Development

```bash
pip install -r requirements.txt
playwright install chromium
XHS_API_KEY=test DATA_DIR=./data UPLOAD_DIR=./uploads uvicorn main:app --reload
```

## Important Notes

- **Playwright/Chromium is required** for request signing (XHS anti-bot)
- **Session expires** — if `/session/status` returns `{valid: false}`, re-do QR login
- **Images must be local files** — upload via `/upload` first, then pass paths to `/publish`
- **Topics** — pass keyword strings in `topic_keywords`, the service looks up proper topic objects

## Related

- [xhs-platform](https://github.com/noonotnow/xhs-platform) — Next.js management UI
- [ReaJason/xhs](https://github.com/ReaJason/xhs) — Underlying XHS library
