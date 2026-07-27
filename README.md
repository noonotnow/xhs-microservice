# XHS Microservice

FastAPI microservice for interacting with Xiaohongshu (小红书) via the [ReaJason/xhs](https://github.com/ReaJason/xhs) library.

Handles QR login, session persistence, image upload, and note publishing/scheduling to real Xiaohongshu.

## Architecture

```
Next.js (xhs-platform)
    ↓ HTTP + API key (server) or short-lived upload token (browser)
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

All endpoints except `/health` require the permanent `X-Api-Key` header. For
backward compatibility, `/upload` accepts that header or a short-lived
`Authorization: Upload <token>` header. Upload tokens are not accepted by any
other endpoint.

### Browser Upload Authorization

The server that renders the browser client should generate a fresh upload token
instead of exposing `XHS_API_KEY`. The token format is:

```text
<payload_b64url>.<signature_b64url>
```

Both segments use unpadded base64url. The payload is compact UTF-8 JSON with
these fields:

```json
{"exp":1750000000,"method":"POST","path":"/upload","nonce":"unique-random-value"}
```

Sign the ASCII payload segment with HMAC-SHA256 using
`UPLOAD_TOKEN_SECRET`, then base64url-encode the signature without padding.
`exp` is Unix seconds and must be in the future but no more than five minutes
ahead. Use a separate high-entropy secret from `XHS_API_KEY`.

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
4. Set env vars `XHS_API_KEY=<your-secret>` and
   `UPLOAD_TOKEN_SECRET=<your-independent-high-entropy-secret>`
5. Deploy

## Local Development

```bash
pip install -r requirements.txt
playwright install chromium
XHS_API_KEY=test UPLOAD_TOKEN_SECRET=upload-test-secret DATA_DIR=./data UPLOAD_DIR=./uploads uvicorn main:app --reload
```

## Important Notes

- **Playwright/Chromium is required** for request signing (XHS anti-bot)
- **Session expires** — if `/session/status` returns `{valid: false}`, re-do QR login
- **Images must be local files** — upload via `/upload` first, then pass paths to `/publish`
- **Topics** — pass keyword strings in `topic_keywords`, the service looks up proper topic objects

## Related

- [xhs-platform](https://github.com/noonotnow/xhs-platform) — Next.js management UI
- [ReaJason/xhs](https://github.com/ReaJason/xhs) — Underlying XHS library
