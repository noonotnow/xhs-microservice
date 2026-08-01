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

Pasting the full Request Headers line is also supported: a single
case-insensitive leading `Cookie:` label, outer spaces, and one trailing copied
newline are removed before validation. Pair order is retained. Embedded
newlines, additional headers, tabs, other control characters, malformed pairs,
invalid or duplicate names, and oversized inputs are rejected before client
creation, signing, validation, or persistence.

Do not paste a DevTools cookie table export; domain, path, expiry, and other
columns are rejected. Cookies copied from a fresh authenticated
`creator.rednote.com` request are supported: the pinned client receives the
name/value pairs as an explicit request-local `Cookie` header, bypassing
Requests cookie-jar domain and path filtering. Supplemental defaults never
replace submitted cookie names. Both `a1` and `web_session` are required.
Cookie values and names are never logged or returned.

Cookie ingestion failures return HTTP 400 in FastAPI's existing `detail`
envelope with only a stable code and fixed safe message:

```json
{
  "detail": {
    "code": "cookie_header_control_character",
    "message": "Cookie request header contains an unsupported control character."
  }
}
```

Parse codes are `cookie_header_control_character`,
`cookie_header_invalid_name`, `cookie_header_duplicate_name`,
`cookie_header_missing_equals`, `cookie_header_too_large`, and
`cookie_header_empty`. A syntactically valid header without the required
non-empty Creator session fields returns `cookie_required_session_fields`.
These responses never include submitted names, values, lengths, raw input,
headers, exception text, or upstream details.

The copied Request Header may contain pairs selected by the browser from both
`.rednote.com` and `creator.rednote.com` scopes, including host-specific
anti-bot state. The service retains every validated pair in submitted order
when constructing the validation request. Because a plain Cookie header does
not carry domain/path scope, duplicate names are ambiguous and rejected rather
than silently choosing one value. DevTools table exports remain unsupported.

A submitted cookie is validated through the signed Creator upload-permit GET
confirmed by the authenticated browser flow:

```text
https://creator.rednote.com/api/media/v1/upload/creator/permit?biz_name=spectrum&scene=image&file_count=1&version=1&source=web
```

The request includes request-local signing plus browser-compatible Origin,
Referer, User-Agent, Accept, and Sec-Fetch headers. Validation does not mutate
the candidate or active session headers or cookie jar. Only a response
containing a non-empty file ID and upload token plus unambiguous success
metadata is persisted and installed. Supported success metadata is the Creator
contract's top-level `success: true` with `code: 0`, its nested
`data.result.success: true`, or both when they agree. Conflicting, partial, or
malformed success indicators are rejected; there is no fallback acceptance. A
failed replacement leaves the prior cookie file and active publishing client
intact.

Redirects, HTTP 401/403, and XHS session-expired result `-100` return HTTP 401
with `creator_session_invalid`, `relogin_required: true`, and a sanitized
`reason` of `redirect`, `http_401`, `http_403`, or `api_session_expired`.
Numeric `upstream_status` and `upstream_code` fields may be included; no
Location, headers, response bodies, or arbitrary upstream fields are exposed.
Transport failures, 5xx responses, malformed payloads, and unexpected success
shapes return sanitized HTTP 502 `creator_session_validation_unavailable`
without replacing the session.

`GET /session/status` uses the same Creator upload-permit boundary and returns
stable sanitized metadata without forwarding the permit payload:

```json
{
  "valid": true,
  "session_type": "rednote_creator",
  "validation": {
    "method": "creator_upload_permit",
    "host": "creator.rednote.com",
    "path": "/api/media/v1/upload/creator/permit",
    "source": "active_session"
  },
  "relogin_required": false
}
```

`POST /login/cookie` reports `validation.source` as
`cookie_login_candidate`, while `GET /session/status` reports
`active_session`. This static provenance identifies which session was checked
without exposing cookies, upload credentials, response bodies, or headers.

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
- **Session expires** — if `/session/status` returns `{valid: false}`, submit a
  fresh Creator request cookie through `/login/cookie`
- **Images must be local files** — upload via `/upload` first, then pass paths to `/publish`
- **Topics** — pass keyword strings in `topic_keywords`, the service looks up proper topic objects

## Related

- [xhs-platform](https://github.com/noonotnow/xhs-platform) — Next.js management UI
- [ReaJason/xhs](https://github.com/ReaJason/xhs) — Underlying XHS library
