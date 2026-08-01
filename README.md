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
| POST | `/publish-video` | Publish a video already staged on this service |
| POST | `/publish-video-url` | Stage and publish a trusted MEDIA video URL |

All endpoints except `/health` require the permanent `X-Api-Key` header. For
backward compatibility, `/upload` accepts that header or a short-lived
`Authorization: Upload <token>` header. Upload tokens are not accepted by any
other endpoint.

`GET /health` includes Railway's `RAILWAY_GIT_COMMIT_SHA` as `revision` (or
`"unknown"` outside Railway) so operators can verify which build is live.

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

1. `GET /login/qr` → replaces any stale login attempt and returns
   `{qr_id, code, url, expires_at}`
2. Convert `url` to QR code image, scan with XHS app
3. Poll `GET /login/status` until `code_status == 2`
4. Session cookie is saved automatically

QR creation uses the normal international creator login endpoints observed on
the first-party `creator.rednote.com/login` page:
`webapi.rednote.com/api/sns/web/v1/login/qrcode/create` and `/status`. The same
paths on the pinned client's domestic default host are rejected, while the
Creator CAS endpoint targets the merchant/Qianfan identity surface and is not
used. Polling state, including the temporary login cookies required to resume
after a container restart, is stored in `qr_state.json`. Expired or rejected QR
attempts return `expired: true` and are removed so the next `/login/qr` call
starts cleanly.

Every `/login/qr` request replaces prior state and generates a new anonymous
browser identity, avoiding the hard-coded cookies in `xhs==0.2.13`. Reused or
already-expired QR IDs are retried once and never persisted. When Rednote
provides expiration metadata, the service honors second or millisecond
timestamps, second durations, or explicitly millisecond-suffixed durations
with a safety margin; otherwise it uses the two-minute fallback. Rejected IDs
remain blocked across restarts for five minutes. QR and status responses always
include `Cache-Control: no-store`.

If Rednote rejects the creator QR flow, the endpoint returns a sanitized 502
without cookies, tickets, or tracebacks. Use the existing authenticated
`POST /login/cookie` operation as the manual fallback; no Railway environment
or volume change is required. Its JSON `cookie` field accepts only the value of
an authenticated browser request's `Cookie` header:

```json
{"cookie": "a1=<value>; web_session=<value>; id_token=<value>"}
```

Do not paste a DevTools cookie table export; domain, path, expiry, and other
columns are rejected. Cookies copied from a fresh authenticated
`creator.rednote.com` request are supported: the client receives the name/value
pairs directly and preserves values such as `id_token`. Both `a1` and
`web_session` are required. Cookie values are never logged or returned, and
invalid-session responses are sanitized.

## Publishing Flow

1. `POST /upload` with image file → returns `{filepath}`
2. `POST /publish` with title, desc, files (from step 1), optional post_time

### Publishing a canonical MEDIA video

`POST /publish-video-url` is the server-to-server contract for a manually
confirmed publish from xhs-platform admin. It requires `X-Api-Key`; browser
upload tokens are not accepted.

```http
POST /publish-video-url
X-Api-Key: <XHS_API_KEY>
Content-Type: application/json

{
  "video_url": "https://images.xhs.justlikekatie.com/videos/assets/example.mp4",
  "title": "Post title",
  "caption": "Caption prepared by CREATE",
  "tags": ["topic-one", "topic-two"]
}
```

The service accepts only HTTPS MP4 URLs under `/videos/assets/` on hosts in
`TRUSTED_MEDIA_VIDEO_HOSTS` (default: `images.xhs.justlikekatie.com`). It does
not follow redirects, requires `video/mp4`, verifies the MP4 signature, limits
the download to `MAX_REMOTE_VIDEO_BYTES` (default: 500 MiB) and
`REMOTE_VIDEO_DOWNLOAD_TIMEOUT_SECONDS` (default: 300 seconds), validates video
metadata with `ffprobe`, and removes the staged file after the publish attempt.

Success is returned only when XHS supplies a note ID:

```json
{
  "status": "success",
  "note_id": "xhs-note-id",
  "share_url": "https://www.xiaohongshu.com/explore/xhs-note-id"
}
```

Validation failures use 4xx responses. MEDIA retrieval, XHS publishing, or a
missing note ID use explicit 5xx responses. Calling this endpoint publishes
immediately, so the caller must place it behind explicit operator confirmation.

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
