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
| POST | `/login/cookie` | Validate and save a Creator request cookie |
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

QR login is disabled. The available Creator CAS endpoint produces
merchant/Qianfan (`小红书商家版`) identity links, not normal Rednote creator
login. The service never returns those links or asks an operator to authorize
them.

Authenticated `GET /login/qr` and `GET /login/status` both clear stale QR state
and return HTTP 503 with:

```json
{
  "detail": {
    "code": "CREATOR_QR_UNAVAILABLE",
    "message": "QR login is disabled ... Use manual cookie login ... https://creator.rednote.com/login."
  }
}
```

Responses are marked `Cache-Control: no-store`. Use authenticated
`POST /login/cookie` as the only supported recovery; no Railway environment or
volume change is required. Its JSON `cookie` field accepts only the value of an
authenticated browser request's `Cookie` header:

```json
{"cookie": "a1=<value>; web_session=<value>; webId=<value>"}
```

Do not paste a DevTools cookie table export; domain, path, expiry, and other
columns are rejected. Cookies copied from a fresh authenticated
`creator.rednote.com` request are supported: the pinned client receives the
name/value pairs directly, so they do not have to originate from a
`xiaohongshu.com` domain. Both `a1` and `web_session` are required. Cookie
values are never logged or returned, and invalid-session responses are
sanitized. A submitted cookie is first validated with the read-only signed
Creator profile request
`GET https://creator.rednote.com/api/galaxy/creator/home/personal_info`.
Only a successful Creator response is persisted and installed; a failed
replacement leaves the prior cookie file and active publishing client intact.
Login redirects and XHS result `-100` return HTTP 401 with
`creator_session_invalid` and `relogin_required: true`. Temporary upstream
validation failures return HTTP 502 without replacing the session.

`GET /session/status` uses the same Creator profile boundary and returns stable
sanitized metadata without forwarding the profile payload:

```json
{
  "valid": true,
  "session_type": "rednote_creator",
  "validation": {
    "method": "creator_profile",
    "host": "creator.rednote.com",
    "path": "/api/galaxy/creator/home/personal_info"
  },
  "relogin_required": false
}
```

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
