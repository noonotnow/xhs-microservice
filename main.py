from __future__ import annotations

import asyncio
from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
import base64
import binascii
import hashlib
import hmac
import logging
import os
import json
import re
import time
import uuid
import shutil
import threading
import traceback
from pathlib import Path
from urllib.parse import unquote, urlencode, urlparse

import httpx
from xhs import XhsClient
from xhs.help import get_a1_and_web_id
from xhshow import Xhshow
from sign_service import sign

app = FastAPI(title="XHS Microservice", version="1.0.0")
logger = logging.getLogger("xhs-microservice")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://xhs-platform.vercel.app",
        "https://xhs.justlikekatie.com",
        "http://localhost:3000",  # local dev
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def prevent_qr_response_caching(request: Request, call_next):
    response = await call_next(request)
    if request.url.path in {"/login/qr", "/login/status"}:
        response.headers["Cache-Control"] = (
            "no-store, no-cache, max-age=0, must-revalidate"
        )
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled %s during %s %s",
        type(exc).__name__,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )

# --- Config ---
API_KEY = os.getenv("XHS_API_KEY", "change-me-in-production")
UPLOAD_TOKEN_SECRET = os.getenv("UPLOAD_TOKEN_SECRET")
APP_REVISION = os.getenv("RAILWAY_GIT_COMMIT_SHA", "unknown")
DATA_DIR = os.getenv("DATA_DIR", "/app/data")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/data/uploads")
COOKIE_FILE = os.path.join(DATA_DIR, "cookie.json")
QR_STATE_FILE = os.path.join(DATA_DIR, "qr_state.json")
QR_REJECTED_STATE_FILE = os.path.join(DATA_DIR, "qr_rejected.json")
MAX_COOKIE_HEADER_BYTES = 32 * 1024
MAX_QR_URL_BYTES = 8 * 1024
QR_LOGIN_LIFETIME_SECONDS = 2 * 60
QR_EXPIRY_SAFETY_SECONDS = 5
QR_CREATION_ATTEMPTS = 2
QR_REJECTED_ID_LIFETIME_SECONDS = 5 * 60
QR_STATE_LOCK = threading.Lock()
RECENT_REJECTED_QR_IDS: dict[str, int] = {}
XHS_WEBAPI_LOGIN_HOST = "https://webapi.rednote.com"
UPLOAD_TOKEN_MAX_LIFETIME_SECONDS = 5 * 60
BASE64URL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
TRUSTED_MEDIA_VIDEO_HOSTS = {
    host.strip().lower()
    for host in os.getenv(
        "TRUSTED_MEDIA_VIDEO_HOSTS",
        "images.xhs.justlikekatie.com",
    ).split(",")
    if host.strip()
}
MAX_REMOTE_VIDEO_BYTES = int(
    os.getenv("MAX_REMOTE_VIDEO_BYTES", str(500 * 1024 * 1024))
)
REMOTE_VIDEO_DOWNLOAD_TIMEOUT_SECONDS = int(
    os.getenv("REMOTE_VIDEO_DOWNLOAD_TIMEOUT_SECONDS", "300")
)
REMOTE_VIDEO_TIMEOUT = httpx.Timeout(
    connect=10,
    read=60,
    write=10,
    pool=10,
)

# --- Persistent client (singleton) ---
client: XhsClient | None = None
login_client: XhsClient | None = None


def require_api_key(x_api_key: str | None):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")


def _decode_base64url_segment(segment: str) -> bytes:
    if not BASE64URL_SEGMENT_RE.fullmatch(segment):
        raise ValueError("Invalid base64url segment")
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.b64decode(
            segment + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64url segment") from exc


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def validate_upload_token(token: str) -> bool:
    if not UPLOAD_TOKEN_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Upload token authentication is not configured",
        )

    try:
        payload_segment, signature_segment = token.split(".")
        payload_bytes = _decode_base64url_segment(payload_segment)
        supplied_signature = _decode_base64url_segment(signature_segment)

        expected_signature = hmac.new(
            UPLOAD_TOKEN_SECRET.encode("utf-8"),
            payload_segment.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return False

        payload = json.loads(
            payload_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"Invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return False

    if not isinstance(payload, dict):
        return False
    if type(payload.get("exp")) is not int:
        return False
    if payload.get("method") != "POST" or type(payload.get("method")) is not str:
        return False
    if payload.get("path") != "/upload" or type(payload.get("path")) is not str:
        return False
    if type(payload.get("nonce")) is not str:
        return False

    now = int(time.time())
    return now < payload["exp"] <= now + UPLOAD_TOKEN_MAX_LIFETIME_SECONDS


def require_upload_authorization(
    x_api_key: str | None,
    authorization: str | None,
):
    if x_api_key == API_KEY:
        return
    if authorization and authorization.startswith("Upload "):
        token = authorization.removeprefix("Upload ")
        if token and validate_upload_token(token):
            return
    raise HTTPException(status_code=403, detail="Invalid upload authorization")


def load_cookie() -> str:
    if os.path.exists(COOKIE_FILE):
        os.chmod(COOKIE_FILE, 0o600)
        with open(COOKIE_FILE, "r") as f:
            data = json.load(f)
            return data.get("cookie", "")
    return ""


def _parse_cookie_header(cookie_header: str) -> dict[str, str]:
    if not cookie_header or not cookie_header.strip():
        raise ValueError("Cookie header is empty")
    if len(cookie_header.encode("utf-8")) > MAX_COOKIE_HEADER_BYTES:
        raise ValueError("Cookie header is too large")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in cookie_header):
        raise ValueError("Cookie header contains control characters")

    cookies = {}
    for block in cookie_header.split(";"):
        block = block.strip()
        if not block:
            continue
        if "=" not in block:
            raise ValueError("Cookie pair is missing '='")
        name, value = block.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not COOKIE_NAME_RE.fullmatch(name):
            raise ValueError("Cookie name is invalid")
        if name in cookies:
            raise ValueError("Cookie name is duplicated")
        cookies[name] = value
    if not cookies:
        raise ValueError("Cookie header contains no cookie pairs")
    return cookies


def _cookie_header_string(cookies: dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def _new_xhs_client(cookie: str | None = None) -> XhsClient:
    xhs_client = XhsClient(sign=sign)
    if cookie:
        import requests.cookies

        xhs_client.session.cookies = requests.cookies.cookiejar_from_dict(
            _parse_cookie_header(cookie)
        )
    return xhs_client


def save_cookie(cookie_str: str):
    os.makedirs(DATA_DIR, exist_ok=True)
    temp_path = f"{COOKIE_FILE}.{uuid.uuid4().hex}.tmp"
    try:
        descriptor = os.open(
            temp_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w") as cookie_file:
            json.dump({"cookie": cookie_str}, cookie_file)
        os.replace(temp_path, COOKIE_FILE)
    finally:
        Path(temp_path).unlink(missing_ok=True)


def get_client() -> XhsClient:
    """Get or create the persistent XhsClient singleton."""
    global client
    if client is None:
        cookie = load_cookie()
        client = _new_xhs_client(cookie)
        # For international RedNote accounts:
        # - _host → webapi.rednote.com (found in publish-components JS)
        # - _creator_host → creator.rednote.com
        client._host = "https://webapi.rednote.com"
        client._creator_host = "https://creator.rednote.com"
        client.home = "https://creator.rednote.com"
        client.session.headers.update({
            "Origin": "https://creator.rednote.com",
            "Referer": "https://creator.rednote.com/publish/publish",
        })
        # Add required cookies for international accounts (discovered from browser DevTools)
        _add_international_cookies(client)
        _patch_international_urls(client)
    return client


def _add_international_cookies(xhs_client):
    """Add cookies required by international RedNote that aren't in the login cookie.

    These are set by the browser during normal usage and are required for
    certain API calls (especially note creation).
    """
    import requests.cookies
    domain = ".rednote.com"
    extra_cookies = {
        "x-rednote-datactry": "SG",
        "x-rednote-holderctry": "US",
        "webBuild": "1.13.0",
        "xsecappid": "ugc",
        "webId": "3747724572cf538850bbb03b4a64d371",
    }
    for name, value in extra_cookies.items():
        xhs_client.session.cookies.set(name, value, domain=domain)


def refresh_client():
    """Force-rebuild client (e.g., after QR login succeeds)."""
    global client
    cookie = load_cookie()
    client = _new_xhs_client(cookie)
    client._host = "https://webapi.rednote.com"
    client._creator_host = "https://creator.rednote.com"
    client.home = "https://creator.rednote.com"
    client.session.headers.update({
        "Origin": "https://creator.rednote.com",
        "Referer": "https://creator.rednote.com/publish/publish",
    })
    _add_international_cookies(client)
    _patch_international_urls(client)


def get_login_client(cookie: str | None = None) -> XhsClient:
    """Create a client using xiaohongshu.com for QR login.
    QR login must go through xiaohongshu.com — the resulting cookies
    work cross-domain against rnote.com APIs."""
    login_client = XhsClient(sign=sign)
    login_client.session.cookies.clear()
    if cookie:
        cookie_dict = {}
        for block in cookie.split(";"):
            if not block.strip() or "=" not in block:
                continue
            name, value = block.split("=", 1)
            cookie_dict[name.strip()] = value.strip()
        if not cookie_dict:
            raise ValueError("Persisted QR cookie is invalid")
        login_client.session.cookies.update(cookie_dict)
    else:
        a1, web_id = get_a1_and_web_id()
        login_client.session.cookies.update({
            "a1": a1,
            "webId": web_id,
        })
    # Keep default xiaohongshu.com host for login
    # Do NOT set rnote.com hosts
    return login_client


class XhsLoginProtocolError(Exception):
    def __init__(self, code=None):
        super().__init__("XHS login request failed")
        self.code = code


def _login_request(
    xhs_client: XhsClient,
    method: str,
    host: str,
    uri: str,
    *,
    data: dict | None = None,
    params: dict | None = None,
    referer: str | None = None,
) -> dict:
    final_uri = uri
    if params:
        final_uri = f"{uri}?{urlencode(params)}"
    signed_headers = sign(
        final_uri,
        data,
        a1=xhs_client.cookie_dict.get("a1", ""),
        web_session=xhs_client.cookie_dict.get("web_session", ""),
    )
    headers = {
        **signed_headers,
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    if referer:
        headers["Referer"] = referer
    body = None
    if data is not None:
        body = json.dumps(
            data,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()

    try:
        response = xhs_client.session.request(
            method,
            f"{host}{final_uri}",
            data=body,
            headers=headers,
            timeout=xhs_client.timeout,
            proxies=xhs_client.proxies,
        )
        payload = response.json()
    except Exception as exc:
        raise XhsLoginProtocolError() from exc

    if response.status_code != 200 or not payload.get("success"):
        raise XhsLoginProtocolError(payload.get("code"))
    result = payload.get("data", payload.get("success"))
    if not isinstance(result, dict):
        raise XhsLoginProtocolError(payload.get("code"))
    return result


def _create_creator_qr(xhs_client: XhsClient) -> dict:
    return _login_request(
        xhs_client,
        "POST",
        XHS_WEBAPI_LOGIN_HOST,
        "/api/sns/web/v1/login/qrcode/create",
        data={},
    )


def _creator_qr_expires_at(qr: dict, now: int) -> int:
    timestamp_fields = (
        "expires_at",
        "expire_at",
        "expire_time",
        "expiration_time",
    )
    duration_fields = ("expires_in", "ttl", "expire")
    duration_ms_fields = ("expires_in_ms", "ttl_ms", "expire_ms")

    for field in timestamp_fields + duration_fields + duration_ms_fields:
        raw_value = qr.get(field)
        if isinstance(raw_value, str) and raw_value.isdigit():
            raw_value = int(raw_value)
        if type(raw_value) not in (int, float) or raw_value <= 0:
            continue

        if field in duration_fields:
            upstream_expiry = now + int(raw_value)
        elif field in duration_ms_fields:
            upstream_expiry = now + int(raw_value / 1000)
        elif raw_value > 10_000_000_000:
            upstream_expiry = int(raw_value / 1000)
        elif raw_value > 1_000_000_000:
            upstream_expiry = int(raw_value)
        else:
            duration = raw_value / 1000 if raw_value > 10_000 else raw_value
            upstream_expiry = now + int(duration)

        return upstream_expiry - QR_EXPIRY_SAFETY_SECONDS

    return now + QR_LOGIN_LIFETIME_SECONDS


def _recent_rejected_qr_ids(now: int) -> set[str]:
    try:
        with open(QR_REJECTED_STATE_FILE, "r") as rejected_file:
            persisted_ids = json.load(rejected_file)
        if not isinstance(persisted_ids, dict) or any(
            not isinstance(qr_id, str) or type(rejected_until) is not int
            for qr_id, rejected_until in persisted_ids.items()
        ):
            raise ValueError("Invalid rejected QR state")
        RECENT_REJECTED_QR_IDS.update(persisted_ids)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, json.JSONDecodeError):
        Path(QR_REJECTED_STATE_FILE).unlink(missing_ok=True)

    expired_ids = [
        qr_id
        for qr_id, rejected_until in RECENT_REJECTED_QR_IDS.items()
        if rejected_until <= now
    ]
    for qr_id in expired_ids:
        del RECENT_REJECTED_QR_IDS[qr_id]
    _save_rejected_qr_ids()
    return set(RECENT_REJECTED_QR_IDS)


def _save_rejected_qr_ids() -> None:
    if not RECENT_REJECTED_QR_IDS:
        Path(QR_REJECTED_STATE_FILE).unlink(missing_ok=True)
        return
    os.makedirs(DATA_DIR, exist_ok=True)
    temp_path = f"{QR_REJECTED_STATE_FILE}.{uuid.uuid4().hex}.tmp"
    try:
        descriptor = os.open(
            temp_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w") as rejected_file:
            json.dump(RECENT_REJECTED_QR_IDS, rejected_file)
        os.replace(temp_path, QR_REJECTED_STATE_FILE)
    finally:
        Path(temp_path).unlink(missing_ok=True)


def _remember_rejected_qr_id(qr_id: str, now: int) -> None:
    RECENT_REJECTED_QR_IDS[qr_id] = (
        now + QR_REJECTED_ID_LIFETIME_SECONDS
    )
    _save_rejected_qr_ids()


def _is_supported_creator_qr_url(url: str) -> bool:
    if len(url.encode("utf-8")) > MAX_QR_URL_BYTES:
        return False
    decoded_url = url
    for _ in range(10):
        next_url = unquote(decoded_url)
        if next_url == decoded_url:
            break
        decoded_url = next_url
    else:
        return False
    if unquote(decoded_url) != decoded_url:
        return False
    lowered_url = decoded_url.lower()
    return (
        urlparse(decoded_url).scheme.lower() == "xhsdiscover"
        and "xymerchant" not in lowered_url
        and "qianfan" not in lowered_url
    )


def _check_creator_qr(
    xhs_client: XhsClient,
    qr_id: str,
    code: str,
) -> dict:
    return _login_request(
        xhs_client,
        "GET",
        XHS_WEBAPI_LOGIN_HOST,
        "/api/sns/web/v1/login/qrcode/status",
        params={
            "qr_id": qr_id,
            "code": code,
        },
    )


def _clear_qr_state() -> None:
    global login_client
    login_client = None
    Path(QR_STATE_FILE).unlink(missing_ok=True)


def _save_qr_state(state: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    temp_path = f"{QR_STATE_FILE}.{uuid.uuid4().hex}.tmp"
    try:
        with open(temp_path, "w") as state_file:
            json.dump(state, state_file)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, QR_STATE_FILE)
    finally:
        Path(temp_path).unlink(missing_ok=True)


def _load_qr_state() -> dict:
    try:
        with open(QR_STATE_FILE, "r") as state_file:
            state = json.load(state_file)
        if (
            not isinstance(state, dict)
            or state.get("flow") != "creator"
            or not isinstance(state.get("qr_id"), str)
            or not isinstance(state.get("code"), str)
            or not isinstance(state.get("login_cookie"), str)
            or type(state.get("expires_at")) is not int
        ):
            raise ValueError("Invalid QR state")
        return state
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _clear_qr_state()
        raise HTTPException(
            status_code=400,
            detail="QR login state is invalid. Call /login/qr to start again.",
        ) from exc


def _get_image_dimensions(filepath: str) -> tuple[int, int]:
    """Get image width and height. Returns (width, height) or (1080, 1440) as fallback."""
    try:
        from struct import unpack

        with open(filepath, "rb") as f:
            header = f.read(32)

        # JPEG
        if header[:2] == b'\xff\xd8':
            with open(filepath, "rb") as f:
                f.read(2)
                while True:
                    marker = f.read(2)
                    if len(marker) < 2:
                        break
                    if marker[0] != 0xFF:
                        break
                    if marker[1] in (0xC0, 0xC1, 0xC2):
                        f.read(3)  # length + precision
                        h = unpack(">H", f.read(2))[0]
                        w = unpack(">H", f.read(2))[0]
                        return (w, h)
                    else:
                        length = unpack(">H", f.read(2))[0]
                        f.read(length - 2)

        # PNG
        if header[:8] == b'\x89PNG\r\n\x1a\n':
            w = unpack(">I", header[16:20])[0]
            h = unpack(">I", header[20:24])[0]
            return (w, h)

    except Exception:
        pass
    return (1080, 1440)


def _get_video_metadata(filepath: str, strict: bool = False) -> dict:
    """Extract video metadata using ffprobe, with sensible fallback defaults."""
    import subprocess as _sp
    try:
        cmd = [
            'ffprobe', '-v', 'quiet', '-print_format', 'json',
            '-show_format', '-show_streams', filepath
        ]
        proc = _sp.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            probe = json.loads(proc.stdout)
            video_stream = next((s for s in probe.get('streams', []) if s.get('codec_type') == 'video'), {})
            audio_stream = next((s for s in probe.get('streams', []) if s.get('codec_type') == 'audio'), {})
            fmt = probe.get('format', {})
            format_names = fmt.get("format_name", "").split(",")
            if strict and (
                not video_stream
                or video_stream.get("codec_name") != "h264"
                or not audio_stream
                or audio_stream.get("codec_name") != "aac"
                or not {"mov", "mp4"}.intersection(format_names)
            ):
                raise ValueError("File must be an H.264/AAC MP4 video")

            width = int(video_stream.get('width', 0))
            height = int(video_stream.get('height', 0))
            duration_s = float(fmt.get('duration', 0))
            video_bitrate = int(video_stream.get('bit_rate', 0))
            fps_parts = video_stream.get('r_frame_rate', '30/1').split('/')
            fps = round(int(fps_parts[0]) / int(fps_parts[1]), 2) if len(fps_parts) == 2 and int(fps_parts[1]) > 0 else 30.0
            audio_bitrate = int(audio_stream.get('bit_rate', 64000))
            audio_channels = int(audio_stream.get('channels', 1))
            audio_sample_rate = int(audio_stream.get('sample_rate', 44100))

            return {
                "width": width or 1080,
                "height": height or 1920,
                "duration_s": duration_s or 30.0,
                "duration_ms": int(duration_s * 1000) if duration_s else 30000,
                "video_bitrate": video_bitrate or 5000000,
                "fps": fps,
                "audio_bitrate": audio_bitrate,
                "audio_channels": audio_channels,
                "audio_sample_rate": audio_sample_rate,
            }
    except Exception as exc:
        if strict:
            raise ValueError("Could not read MP4 video metadata") from exc
    if strict:
        raise ValueError("Could not read MP4 video metadata")
    # Fallback defaults
    return {
        "width": 1080,
        "height": 1920,
        "duration_s": 30.0,
        "duration_ms": 30000,
        "video_bitrate": 5000000,
        "fps": 30.0,
        "audio_bitrate": 64000,
        "audio_channels": 1,
        "audio_sample_rate": 44100,
    }


def _patch_international_urls(xhs_client):
    """Monkey-patch the xhs library to route ALL calls through creator path.

    For international RedNote accounts, only is_creator=True works
    (uses Python signing + x-s-common + creator.rednote.com host).
    """
    import types

    # Patch get_self_info to use creator endpoint
    def patched_get_self_info(self):
        uri = "/api/galaxy/creator/home/personal_info"
        return self.get(uri, is_creator=True)

    xhs_client.get_self_info = types.MethodType(patched_get_self_info, xhs_client)

    # Patch get_upload_files_permit to use creator path
    def patched_get_upload_files_permit(self, file_type, count=1):
        uri = "/api/media/v1/upload/web/permit"
        params = {
            "biz_name": "spectrum", "scene": file_type,
            "file_count": count, "version": "1", "source": "web",
        }
        res = self.get(uri, params, is_creator=True)
        temp_permit = res["uploadTempPermits"][0]
        return temp_permit["fileIds"][0], temp_permit["token"]

    xhs_client.get_upload_files_permit = types.MethodType(patched_get_upload_files_permit, xhs_client)

    # Patch upload_file to use international CDN (upload.rnote.com instead of ros-upload.xiaohongshu.com)
    def patched_upload_file(self, file_id, token, file_path, content_type="image/jpeg"):
        """Upload file to international CDN at upload.rnote.com"""
        url = "https://upload.rnote.com/" + file_id
        headers = {"X-Cos-Security-Token": token, "Content-Type": content_type}
        with open(file_path, "rb") as f:
            return self.request("PUT", url, data=f, headers=headers)

    xhs_client.upload_file = types.MethodType(patched_upload_file, xhs_client)

    # Patch get_suggest_topic to use creator path
    def patched_get_suggest_topic(self, keyword=""):
        uri = "/web_api/sns/v1/search/topic"
        data = {
            "keyword": keyword,
            "suggest_topic_request": {"title": "", "desc": ""},
            "page": {"page_size": 20, "page": 1},
        }
        res = self.post(uri, data, is_creator=True)
        if isinstance(res, dict):
            return res.get("topic_info_dtos", [])
        return []

    xhs_client.get_suggest_topic = types.MethodType(patched_get_suggest_topic, xhs_client)

    # Patch get_video_first_frame_image_id to use creator path
    def patched_get_video_first_frame_image_id(self, video_id):
        """Get the auto-generated first-frame cover image ID for an uploaded video."""
        uri = "/api/media/v1/upload/web/first_frame"
        params = {"video_id": video_id}
        res = self.get(uri, params, is_creator=True)
        # Response contains the file_id of the auto-generated first frame
        return res.get("file_id", "")

    xhs_client.get_video_first_frame_image_id = types.MethodType(
        patched_get_video_first_frame_image_id, xhs_client
    )

    # Patch create_note: use xhshow library for XYS_ signing (required by /web_api/sns/v2/note)
    def patched_create_note(self, title, desc, note_type="normal", ats=None, topics=None,
                            image_info=None, video_info=None, post_time=None, is_private=False):
        """Create a note using xhshow XYS_ signing for the webapi.rednote.com endpoint."""
        import json as _json

        if ats is None:
            ats = []
        if topics is None:
            topics = []

        # Build confirmed-working request body format
        business_binds = _json.dumps({
            "version": 1, "noteId": 0, "bizType": 0,
            "noteOrderBind": {},
            "notePostTiming": {},
            "noteCollectionBind": {"id": ""},
            "noteSketchCollectionBind": {"id": ""},
            "coProduceBind": {"enable": True},
            "noteCopyBind": {"copyable": True},
            "interactionPermissionBind": {"commentPermission": 0},
            "optionRelationList": []
        }, separators=(",", ":"))

        note_type_str = note_type if isinstance(note_type, str) else "normal"
        payload = {
            "common": {
                "type": note_type_str,
                "note_id": "",
                "source": _json.dumps({"type": "web", "ids": "", "extraInfo": _json.dumps({"systemId": "web"})}, separators=(",", ":")),
                "title": title,
                "desc": desc,
                "ats": ats,
                "hash_tag": topics,
                "business_binds": business_binds,
                "privacy_info": {"op_type": 1, "type": int(is_private)},
                "goods_info": {},
                "biz_relations": [],
                "capa_trace_info": {
                    "contextJson": _json.dumps({
                        "recommend_title": {"recommend_title_id": "", "is_use": 3, "used_index": -1},
                        "recommendTitle": [],
                        "recommend_topics": {"used": []}
                    }, separators=(",", ":"))
                }
            },
            "image_info": image_info,
            "video_info": video_info,
        }

        # Extract cookies from client's session
        cookie_str = self.cookie or ""
        cookies_dict = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies_dict[k.strip()] = v.strip()

        # Also grab cookies from session cookie jar
        for cookie in self.session.cookies:
            cookies_dict[cookie.name] = cookie.value

        # Generate XYS_ signed headers using xhshow
        xhshow_client = Xhshow()
        url = "https://webapi.rednote.com/web_api/sns/v2/note"

        sign_cookies = {
            "a1": cookies_dict.get("a1", ""),
            "web_session": cookies_dict.get("web_session", ""),
            "webId": cookies_dict.get("webId", ""),
        }

        try:
            signed_headers = xhshow_client.sign_headers_post(
                uri=url,
                cookies=sign_cookies,
                payload=payload,
                x_rap=True,
            )
        except Exception:
            # Fallback: try with just the path
            signed_headers = xhshow_client.sign_headers_post(
                uri="/web_api/sns/v2/note",
                cookies=sign_cookies,
                payload=payload,
                x_rap=True,
            )

        # Build full headers
        request_headers = {
            "Content-Type": "application/json",
            "Authorization": "",
            "Referer": "https://creator.rednote.com/",
            "Origin": "https://creator.rednote.com",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        }
        # Merge xhshow signed headers (x-s, x-s-common, x-t, x-rap-param, etc.)
        for k, v in signed_headers.items():
            request_headers[k] = str(v)

        # Build cookie header string
        cookie_parts = []
        for k, v in cookies_dict.items():
            cookie_parts.append(f"{k}={v}")
        request_headers["Cookie"] = "; ".join(cookie_parts)

        # Make direct POST request, using a session to acquire acw_tc cookie
        with httpx.Client(timeout=30) as http_client:
            # Preflight: hit webapi.rednote.com to acquire domain-specific acw_tc cookie
            try:
                preflight_headers = {
                    "User-Agent": request_headers["User-Agent"],
                    "Cookie": request_headers["Cookie"],
                    "Referer": "https://creator.rednote.com/",
                }
                preflight_resp = http_client.get(
                    "https://webapi.rednote.com/api/sns/web/v1/user/selfinfo",
                    headers=preflight_headers,
                )
                # Extract acw_tc from response cookies and add to our cookie header
                for cookie_name, cookie_value in http_client.cookies.items():
                    if cookie_name == "acw_tc":
                        cookies_dict["acw_tc"] = cookie_value
                        # Rebuild cookie header with acw_tc
                        cookie_parts = [f"{k}={v}" for k, v in cookies_dict.items()]
                        request_headers["Cookie"] = "; ".join(cookie_parts)
                        break
            except Exception:
                pass  # Continue without acw_tc if preflight fails

            resp = http_client.post(url, json=payload, headers=request_headers)

        if resp.status_code == 200:
            data = resp.json()
            if data.get("code") == 0 or data.get("success"):
                return data.get("data", data)
            return data
        else:
            return {
                "error": True,
                "status_code": resp.status_code,
                "response": resp.text[:500],
            }

    xhs_client.create_note = types.MethodType(patched_create_note, xhs_client)


# --- QR Login ---
@app.get("/login/qr")
def get_qr(x_api_key: str | None = Header(None)):
    global login_client
    require_api_key(x_api_key)
    with QR_STATE_LOCK:
        previous_qr_id = None
        if os.path.exists(QR_STATE_FILE):
            try:
                with open(QR_STATE_FILE, "r") as state_file:
                    previous_state = json.load(state_file)
                if isinstance(previous_state, dict):
                    previous_qr_id = previous_state.get("qr_id")
            except (OSError, json.JSONDecodeError):
                pass
        _clear_qr_state()
        try:
            now = int(time.time())
            rejected_qr_ids = _recent_rejected_qr_ids(now)
            if isinstance(previous_qr_id, str):
                rejected_qr_ids.add(previous_qr_id)
                _remember_rejected_qr_id(previous_qr_id, now)
            qr = None
            new_login_client = None
            expires_at = 0
            for _ in range(QR_CREATION_ATTEMPTS):
                candidate_client = get_login_client()
                candidate_qr = _create_creator_qr(candidate_client)
                if not all(
                    isinstance(candidate_qr.get(key), str) and candidate_qr[key]
                    for key in ("qr_id", "code", "url")
                ):
                    raise ValueError("XHS returned incomplete QR data")
                if not _is_supported_creator_qr_url(candidate_qr["url"]):
                    raise ValueError("XHS returned a non-creator QR target")
                now = int(time.time())
                candidate_expiry = _creator_qr_expires_at(candidate_qr, now)
                if (
                    candidate_qr["qr_id"] not in rejected_qr_ids
                    and candidate_expiry > now
                ):
                    qr = candidate_qr
                    new_login_client = candidate_client
                    expires_at = candidate_expiry
                    break
                rejected_qr_ids.add(candidate_qr["qr_id"])
                _remember_rejected_qr_id(candidate_qr["qr_id"], now)
            if qr is None or new_login_client is None:
                raise ValueError("XHS returned a stale or expired QR code")
            login_client = new_login_client
            _save_qr_state({
                "flow": "creator",
                "qr_id": qr["qr_id"],
                "code": qr["code"],
                "login_cookie": login_client.cookie,
                "expires_at": expires_at,
            })
        except XhsLoginProtocolError as exc:
            logger.warning(
                "XHS Creator QR generation rejected with code %s",
                exc.code,
            )
            _clear_qr_state()
            raise HTTPException(
                status_code=502,
                detail="XHS QR login is currently unavailable",
            ) from exc
        except Exception as exc:
            _clear_qr_state()
            raise HTTPException(
                status_code=502,
                detail="Could not generate XHS QR code",
            ) from exc
    return {
        "qr_id": qr["qr_id"],
        "code": qr["code"],
        "url": qr["url"],
        "expires_at": expires_at,
    }


@app.get("/login/status")
def check_login_status(x_api_key: str | None = Header(None)):
    global login_client
    require_api_key(x_api_key)
    with QR_STATE_LOCK:
        if not os.path.exists(QR_STATE_FILE):
            raise HTTPException(status_code=400, detail="No QR login in progress. Call /login/qr first.")
        qr_state = _load_qr_state()
        if qr_state["expires_at"] <= int(time.time()):
            _remember_rejected_qr_id(
                qr_state["qr_id"],
                int(time.time()),
            )
            _clear_qr_state()
            return {
                "code_status": -1,
                "login_info": None,
                "expired": True,
            }
        if login_client is None:
            login_client = get_login_client(qr_state["login_cookie"])
        try:
            status = _check_creator_qr(
                login_client,
                qr_state["qr_id"],
                qr_state["code"],
            )
        except XhsLoginProtocolError as exc:
            logger.warning(
                "XHS Creator QR status rejected with code %s",
                exc.code,
            )
            _remember_rejected_qr_id(
                qr_state["qr_id"],
                int(time.time()),
            )
            _clear_qr_state()
            raise HTTPException(
                status_code=502,
                detail="XHS QR login status is currently unavailable",
            ) from exc
        code_status = status.get("code_status")
        if code_status not in (0, 1, 2):
            _remember_rejected_qr_id(
                qr_state["qr_id"],
                int(time.time()),
            )
            _clear_qr_state()
            raise HTTPException(
                status_code=502,
                detail="XHS QR login returned an invalid status",
            )
        if code_status == 2:
            save_cookie(login_client.cookie)
            refresh_client()
            _remember_rejected_qr_id(
                qr_state["qr_id"],
                int(time.time()),
            )
            _clear_qr_state()
        else:
            qr_state["login_cookie"] = login_client.cookie
            _save_qr_state(qr_state)
        return {
            "code_status": code_status,
            "login_info": None,
            "expired": False,
        }


# --- Manual Cookie Login ---
class CookieLoginRequest(BaseModel):
    cookie: str


@app.post("/login/cookie")
def login_with_cookie(req: CookieLoginRequest, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    try:
        cookies = _parse_cookie_header(req.cookie)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "Expected a Cookie request-header value in "
                "'name=value; name=value' format. DevTools cookie table "
                "exports are not accepted."
            ),
        ) from exc
    if not cookies.get("a1") or not cookies.get("web_session"):
        raise HTTPException(
            status_code=400,
            detail=(
                "Cookie header must include non-empty a1 and web_session "
                "cookies from a fresh authenticated Creator request."
            ),
        )
    save_cookie(_cookie_header_string(cookies))
    refresh_client()
    return {"status": "ok", "message": "Cookie saved. Use /session/status to verify."}


# --- Session Health ---
@app.get("/session/status")
def session_status(x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    xhs = get_client()
    try:
        info = xhs.get_self_info()
        return {"valid": True, "user_info": info}
    except Exception:
        return {"valid": False, "error": "Session validation failed"}


# --- File Upload ---
@app.post("/upload")
async def upload_image(
    file: UploadFile = File(...),
    x_api_key: str | None = Header(None),
    authorization: str | None = Header(None),
):
    require_upload_authorization(x_api_key, authorization)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ext = Path(file.filename).suffix or ".jpg"
    filename = f"{uuid.uuid4().hex}{ext}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, "wb") as f:
        shutil.copyfileobj(file.file, f)
    return {"filepath": filepath, "filename": filename}


# --- Publish / Schedule ---
class PublishRequest(BaseModel):
    title: str
    desc: str
    files: list[str]  # Local file paths (from /upload endpoint)
    post_time: str | None = None  # "YYYY-MM-DD HH:MM:SS" for scheduling
    topic_keywords: list[str] = []
    is_private: bool = False


@app.post("/publish")
def publish_note(req: PublishRequest, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    try:
        xhs = get_client()

        for f in req.files:
            if not os.path.exists(f):
                return {"status": "error", "detail": f"File not found: {f}"}

        # Look up topics if keywords provided
        topics = []
        for keyword in req.topic_keywords:
            try:
                suggestions = xhs.get_suggest_topic(keyword)
                if suggestions:
                    topics.append(suggestions[0])
            except Exception:
                pass

        # Step-by-step publishing with detailed error reporting
        steps = {}

        # Upload each image file: get permit, upload to CDN, collect image entries
        images = []
        for i, filepath in enumerate(req.files):
            n = i + 1

            # Get upload permit for this file
            image_id, token = xhs.get_upload_files_permit("image")
            steps[f"{n}_permit"] = {"ok": True, "file_id": image_id[:30]}

            # Upload file to CDN
            upload_resp = xhs.upload_file(image_id, token, filepath)
            steps[f"{n}_upload"] = {"ok": True, "status": getattr(upload_resp, 'status_code', 'unknown')}

            # Get image dimensions and size for the payload
            file_size_kb = os.path.getsize(filepath) / 1024
            img_width, img_height = _get_image_dimensions(filepath)

            images.append({
                "file_id": image_id,
                "width": img_width,
                "height": img_height,
                "metadata": {"source": -1},
                "stickers": {"version": 2, "floating": []},
                "extra_info_json": json.dumps({
                    "mimeType": "image/jpeg",
                    "image_metadata": {"bg_color": "", "origin_size": round(file_size_kb)}
                }, separators=(",", ":")),
            })

        # Create note with all images
        result = xhs.create_note(
            title=req.title,
            desc=req.desc,
            note_type="normal",
            topics=topics,
            image_info={"images": images},
            is_private=req.is_private,
        )
        steps["create_note"] = {"ok": True}
        # Ensure result is JSON-serializable
        if hasattr(result, 'status_code'):
            try:
                result = result.json()
            except Exception:
                result = {"response_status": result.status_code, "response_text": result.text[:200] if result.text else "empty"}
        elif not isinstance(result, (dict, list, str, int, float, bool, type(None))):
            result = str(result)

        note_id = None
        share_link = None
        if isinstance(result, dict):
            note_id = result.get("id") or (result.get("data", {}).get("id") if isinstance(result.get("data"), dict) else None)
            share_link = result.get("share_link")

        response = {"status": "success", "data": result, "steps": steps}
        if note_id:
            response["note_id"] = note_id
        if share_link:
            response["share_link"] = share_link
        return response
    except Exception as e:
        import traceback
        return {"status": "error", "detail": str(e), "traceback": traceback.format_exc()}


# --- Video Publish ---
class VideoPublishRequest(BaseModel):
    title: str
    desc: str
    video_file: str  # Local file path from /upload
    cover_file: str | None = None  # Optional cover image path
    topic_keywords: list[str] = []
    is_private: bool = False


class RemoteVideoPublishRequest(BaseModel):
    video_url: str
    title: str
    caption: str
    tags: list[str] = Field(default_factory=list)


def _validate_media_video_url(video_url: str) -> None:
    parsed = urlparse(video_url)
    hostname = (parsed.hostname or "").lower()
    decoded_path = unquote(parsed.path)
    path_segments = decoded_path.split("/")
    try:
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="video_url must be a trusted HTTPS MEDIA MP4 URL",
        ) from exc

    if (
        parsed.scheme != "https"
        or not hostname
        or hostname not in TRUSTED_MEDIA_VIDEO_HOSTS
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or parsed.fragment
        or any(segment in (".", "..") for segment in path_segments)
        or not decoded_path.startswith("/videos/assets/")
        or not decoded_path.lower().endswith(".mp4")
        or decoded_path != parsed.path
    ):
        raise HTTPException(
            status_code=400,
            detail="video_url must be a trusted HTTPS MEDIA MP4 URL",
        )


async def _stage_remote_media_video(
    video_url: str,
    http_client: httpx.AsyncClient | None = None,
) -> str:
    _validate_media_video_url(video_url)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    filepath = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}.mp4")
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(
        timeout=REMOTE_VIDEO_TIMEOUT,
        follow_redirects=False,
    )

    try:
        async def download() -> None:
            async with client.stream(
                "GET",
                video_url,
                headers={"Accept": "video/mp4"},
            ) as response:
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail=f"MEDIA video download returned HTTP {response.status_code}",
                    )

                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if content_type != "video/mp4":
                    raise HTTPException(
                        status_code=415,
                        detail="MEDIA video must have Content-Type video/mp4",
                    )

                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        declared_size = int(content_length)
                    except ValueError as exc:
                        raise HTTPException(
                            status_code=502,
                            detail="MEDIA video returned an invalid Content-Length",
                        ) from exc
                    if declared_size < 0:
                        raise HTTPException(
                            status_code=502,
                            detail="MEDIA video returned an invalid Content-Length",
                        )
                    if declared_size > MAX_REMOTE_VIDEO_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail="MEDIA video exceeds the maximum allowed size",
                        )

                total_size = 0
                header = bytearray()
                with open(filepath, "wb") as output:
                    async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                        total_size += len(chunk)
                        if total_size > MAX_REMOTE_VIDEO_BYTES:
                            raise HTTPException(
                                status_code=413,
                                detail="MEDIA video exceeds the maximum allowed size",
                            )
                        if len(header) < 12:
                            header.extend(chunk[:12 - len(header)])
                        output.write(chunk)

                if total_size < 12 or bytes(header[4:8]) != b"ftyp":
                    raise HTTPException(
                        status_code=415,
                        detail="MEDIA video is not a valid MP4 file",
                    )
        try:
            await asyncio.wait_for(
                download(),
                timeout=REMOTE_VIDEO_DOWNLOAD_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise HTTPException(
                status_code=504,
                detail="MEDIA video download timed out",
            ) from exc
        except httpx.TimeoutException as exc:
            raise HTTPException(
                status_code=504,
                detail="MEDIA video download timed out",
            ) from exc
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail="MEDIA video download failed",
            ) from exc
    except asyncio.CancelledError:
        Path(filepath).unlink(missing_ok=True)
        raise
    except Exception:
        Path(filepath).unlink(missing_ok=True)
        raise
    finally:
        if owns_client:
            await client.aclose()

    return filepath


@app.post("/publish-video")
def publish_video(req: VideoPublishRequest, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    try:
        xhs = get_client()
        steps = {}

        if not os.path.exists(req.video_file):
            return {"status": "error", "detail": f"Video file not found: {req.video_file}"}
        if req.cover_file and not os.path.exists(req.cover_file):
            return {"status": "error", "detail": f"Cover file not found: {req.cover_file}"}

        # Look up topics if keywords provided
        topics = []
        for keyword in req.topic_keywords:
            try:
                suggestions = xhs.get_suggest_topic(keyword)
                if suggestions:
                    topics.append(suggestions[0])
            except Exception:
                pass

        # Step 1: Get video upload permit
        video_file_id, video_token = xhs.get_upload_files_permit("video")
        steps["1_video_permit"] = {"ok": True, "file_id": video_file_id[:30]}

        # Step 2: Upload video to CDN
        upload_resp = xhs.upload_file(video_file_id, video_token, req.video_file, content_type="video/mp4")
        video_id = upload_resp.headers.get("X-Ros-Video-Id", "")
        steps["2_video_upload"] = {"ok": True, "video_id": video_id}

        # Step 3: Handle cover image
        cover_file_id = None
        is_upload_cover = False

        if req.cover_file:
            # Upload custom cover image
            cover_file_id, cover_token = xhs.get_upload_files_permit("image")
            xhs.upload_file(cover_file_id, cover_token, req.cover_file)
            is_upload_cover = True
            cover_width, cover_height = _get_image_dimensions(req.cover_file)
            steps["3_cover"] = {"ok": True, "type": "custom", "file_id": cover_file_id[:30],
                                "width": cover_width, "height": cover_height}
        else:
            # No cover provided — try auto-generated first frame (less reliable)
            import time
            auto_frame_errors = []
            for attempt in range(10):
                time.sleep(3)
                try:
                    cover_file_id = xhs.get_video_first_frame_image_id(video_id)
                    if cover_file_id:
                        steps["3_cover"] = {"ok": True, "type": "auto_frame", "attempts": attempt + 1}
                        break
                except Exception as frame_err:
                    auto_frame_errors.append(f"attempt {attempt + 1}: {frame_err}")
            if not cover_file_id:
                steps["3_cover_errors"] = auto_frame_errors
                return {
                    "status": "error",
                    "detail": "Could not get video cover frame after 30s. "
                              "Strongly recommend providing a cover_file for reliable results.",
                    "steps": steps,
                }
            cover_width, cover_height = 0, 0  # Unknown for auto-frame

        # Step 4: Build video_info and create note
        vmeta = _get_video_metadata(req.video_file)

        cover_info = {
            "file_id": cover_file_id,
            "fileid": cover_file_id,
            "width": cover_width,
            "height": cover_height,
            "extra_info_json": "{}",
            "fonts": [],
            "stickers": {"neptune": [], "version": 2},
            "frame": {"ts": 0, "is_user_select": is_upload_cover, "is_upload": is_upload_cover},
        }
        video_info = {
            "file_id": video_file_id,
            "fileid": video_file_id,
            "timelines": [],
            "cover": cover_info,
            "chapters": [],
            "chapter_sync_text": False,
            "entrance": "web",
            "format_width": vmeta["width"],
            "format_height": vmeta["height"],
            "video_preview_type": "full_vertical_screen",
            "pk_cover_biz_relations": [],
            "segments": {
                "count": 1,
                "need_slice": False,
                "items": [{
                    "mute": 0,
                    "speed": 1,
                    "start": 0,
                    "duration": vmeta["duration_s"],
                    "transcoded": 0,
                    "media_source": 1,
                    "original_metadata": {}
                }]
            },
            "composite_metadata": {
                "audio": {
                    "bitrate": vmeta["audio_bitrate"],
                    "channels": vmeta["audio_channels"],
                    "duration": vmeta["duration_ms"],
                    "format": "AAC",
                    "sampling_rate": vmeta["audio_sample_rate"],
                },
                "video": {
                    "bitrate": vmeta["video_bitrate"],
                    "colour_primaries": "BT.709",
                    "duration": vmeta["duration_ms"],
                    "format": "AVC",
                    "frame_rate": vmeta["fps"],
                    "height": vmeta["height"],
                    "matrix_coefficients": "BT.601",
                    "rotation": 0,
                    "transfer_characteristics": "BT.709",
                    "width": vmeta["width"],
                },
            },
        }

        result = xhs.create_note(
            title=req.title,
            desc=req.desc,
            note_type="video",
            topics=topics,
            video_info=video_info,
            is_private=req.is_private,
        )
        steps["4_create_note"] = {"ok": True}

        # Ensure result is JSON-serializable
        if hasattr(result, 'status_code'):
            try:
                result = result.json()
            except Exception:
                result = {"response_status": result.status_code, "response_text": result.text[:200] if result.text else "empty"}
        elif not isinstance(result, (dict, list, str, int, float, bool, type(None))):
            result = str(result)

        note_id = None
        share_link = None
        if isinstance(result, dict):
            note_id = result.get("id") or (result.get("data", {}).get("id") if isinstance(result.get("data"), dict) else None)
            share_link = result.get("share_link")

        response = {"status": "success", "data": result, "steps": steps}
        if note_id:
            response["note_id"] = note_id
        if share_link:
            response["share_link"] = share_link
        if not req.cover_file:
            response["warning"] = (
                "No cover_file was provided. Auto first-frame was used, which may "
                "produce null cover URLs. Providing a cover_file is strongly recommended."
            )
        return response
    except Exception as e:
        import traceback
        return {"status": "error", "detail": str(e), "traceback": traceback.format_exc()}


@app.post("/publish-video-url")
async def publish_video_url(
    req: RemoteVideoPublishRequest,
    x_api_key: str | None = Header(None),
):
    require_api_key(x_api_key)
    if not req.title.strip() or len(req.title) > 20:
        raise HTTPException(status_code=422, detail="title must be 1-20 characters")
    if not req.caption.strip() or len(req.caption) > 1000:
        raise HTTPException(status_code=422, detail="caption must be 1-1000 characters")
    if len(req.tags) > 10 or any(not tag.strip() or len(tag) > 30 for tag in req.tags):
        raise HTTPException(
            status_code=422,
            detail="tags must contain at most 10 non-empty values of 30 characters or fewer",
        )

    staged_video = await _stage_remote_media_video(req.video_url)
    try:
        try:
            await run_in_threadpool(
                _get_video_metadata,
                staged_video,
                True,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=415,
                detail="MEDIA video is not a readable MP4 video",
            ) from exc

        result = await run_in_threadpool(
            publish_video,
            VideoPublishRequest(
                title=req.title.strip(),
                desc=req.caption.strip(),
                video_file=staged_video,
                topic_keywords=[tag.strip() for tag in req.tags],
            ),
            x_api_key,
        )
    finally:
        Path(staged_video).unlink(missing_ok=True)

    if result.get("status") != "success":
        raise HTTPException(
            status_code=502,
            detail=result.get("detail", "XHS video publish failed"),
        )

    note_id = result.get("note_id")
    if not note_id:
        raise HTTPException(
            status_code=502,
            detail="XHS publish response did not include a note ID",
        )

    share_url = result.get("share_link") or (
        f"https://www.xiaohongshu.com/explore/{note_id}"
    )
    return {
        "status": "success",
        "note_id": note_id,
        "share_url": share_url,
    }


# --- Health Check ---
@app.get("/health")
def health():
    return {
        "status": "ok",
        "has_cookie": os.path.exists(COOKIE_FILE),
        "revision": APP_REVISION,
    }


# --- Debug: test signing function ---
@app.get("/debug/sign-test")
def debug_sign_test(x_api_key: str | None = Header(None)):
    """Test if _webmsxyw loads and signs correctly on creator.rednote.com."""
    require_api_key(x_api_key)
    import time
    xhs = get_client()
    cookie_str = xhs.cookie or ""
    a1 = ""
    web_session_val = ""
    for part in cookie_str.split(";"):
        part = part.strip()
        if part.startswith("a1="):
            a1 = part[3:]
        elif part.startswith("web_session="):
            web_session_val = part[12:]

    test_uri = "/api/sns/web/v1/user/selfinfo"
    start = time.time()
    try:
        result = sign(test_uri, None, a1, web_session_val)
        elapsed = round(time.time() - start, 2)
        return {
            "success": True,
            "elapsed_seconds": elapsed,
            "x_s_preview": result.get("x-s", "")[:50] + "...",
            "x_t": result.get("x-t", ""),
            "a1_used": a1[:10] + "..." if a1 else "MISSING",
            "web_session_used": web_session_val[:10] + "..." if web_session_val else "MISSING",
        }
    except Exception as e:
        elapsed = round(time.time() - start, 2)
        return {
            "success": False,
            "elapsed_seconds": elapsed,
            "error": str(e),
            "a1_used": a1[:10] + "..." if a1 else "MISSING",
        }


# --- Debug: test direct creator API ---
@app.get("/debug/creator-direct")
def debug_creator_direct(x_api_key: str | None = Header(None)):
    """Test direct request to creator.rednote.com API with our signing."""
    require_api_key(x_api_key)
    import requests
    import time

    cookie_str = load_cookie()
    if not cookie_str:
        return {"error": "No cookies saved"}

    # Parse a1 and web_session
    a1 = ""
    web_session_val = ""
    for part in cookie_str.split(";"):
        part = part.strip()
        if part.startswith("a1="):
            a1 = part[3:]
        elif part.startswith("web_session="):
            web_session_val = part[12:]

    # Sign the creator API path
    uri = "/api/media/v1/upload/creator/permit?biz_name=spectrum&scene=video&file_count=1&version=1&source=web"
    try:
        sign_result = sign(uri, None, a1, web_session_val)
    except Exception as e:
        return {"error": f"Signing failed: {e}"}

    # Make direct request to creator.rednote.com
    url = f"https://creator.rednote.com{uri}"
    headers = {
        "Cookie": cookie_str,
        "Origin": "https://creator.rednote.com",
        "Referer": "https://creator.rednote.com/publish/publish",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "X-S": sign_result["x-s"],
        "X-T": sign_result["x-t"],
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Sec-Ch-Ua-Platform": '"macOS"',
    }

    start = time.time()
    resp = requests.get(url, headers=headers, timeout=30)
    elapsed = round(time.time() - start, 2)

    return {
        "status_code": resp.status_code,
        "elapsed_seconds": elapsed,
        "response": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:200],
        "x_s_used": sign_result["x-s"][:30] + "...",
    }


# --- Debug: test each publish step ---
@app.get("/debug/publish-steps")
def debug_publish_steps(x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    xhs = get_client()
    results = {}

    # Step 0: verify signing works (pure Python now, no Playwright)
    try:
        from sign_service import sign as test_sign
        sig = test_sign("/api/sns/web/v1/feed", None, a1=xhs.cookie_dict.get("a1", ""))
        results["0_signing"] = {
            "ok": True,
            "x-s_prefix": sig["x-s"][:20],
            "has_x-s-common": "x-s-common" in sig and len(sig["x-s-common"]) > 0,
            "x-s-common_len": len(sig.get("x-s-common", "")),
        }
    except Exception as e:
        results["0_signing"] = {"ok": False, "error": str(e)}

    # Step 1: get_self_info (regular endpoint, edith.xiaohongshu.com)
    try:
        info = xhs.get_self_info()
        results["1_self_info"] = {"ok": True, "data": str(info)[:200]}
    except Exception as e:
        results["1_self_info"] = {"ok": False, "error": str(e)}

    # Step 1b: creator self info (manual call with is_creator=True)
    try:
        uri = "/api/galaxy/creator/home/personal_info"
        info = xhs.get(uri, is_creator=True)
        results["1b_creator_self_info"] = {"ok": True, "data": str(info)[:200]}
    except Exception as e:
        results["1b_creator_self_info"] = {"ok": False, "error": str(e)}

    # Step 2: get_upload_files_permit (manual with is_creator=True)
    try:
        uri = "/api/media/v1/upload/web/permit"
        params = {"biz_name": "spectrum", "scene": "image", "file_count": 1, "version": "1", "source": "web"}
        res = xhs.get(uri, params, is_creator=True)
        temp_permit = res["uploadTempPermits"][0]
        results["2_upload_permit"] = {"ok": True, "file_id": temp_permit["fileIds"][0]}
    except Exception as e:
        results["2_upload_permit"] = {"ok": False, "error": str(e)}

    # Step 2b: creator upload permit (the exact URL from Katie's browser)
    try:
        uri = "/api/media/v1/upload/creator/permit"
        params = {"biz_name": "spectrum", "scene": "image", "file_count": 1, "version": "1", "source": "web"}
        res = xhs.get(uri, params, is_creator=True)
        results["2b_creator_upload_permit"] = {"ok": True, "data": str(res)[:200]}
    except Exception as e:
        results["2b_creator_upload_permit"] = {"ok": False, "error": str(e)}

    # Step 3: get_suggest_topic
    try:
        topics = xhs.get_suggest_topic("test")
        results["3_suggest_topic"] = {"ok": True, "count": len(topics) if topics else 0}
    except Exception as e:
        results["3_suggest_topic"] = {"ok": False, "error": str(e)}

    return results


# --- Debug: cookie state ---
@app.get("/debug/cookie-state")
def debug_cookie_state(x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    xhs = get_client()
    result = {
        "cookie_file_exists": os.path.exists(COOKIE_FILE),
        "client_cookie_string": None,
        "cookie_jar_entries": [],
        "saved_cookie_keys": [],
    }

    # Show current client cookie string (keys + value lengths only)
    cookie_str = xhs.cookie
    if cookie_str:
        parts = cookie_str.split(";")
        result["client_cookie_string"] = []
        for part in parts:
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                result["client_cookie_string"].append({
                    "key": key.strip(),
                    "value_length": len(val.strip()),
                    "value_preview": val.strip()[:10] + "..."
                })

    # Show cookie jar entries with domain info
    try:
        for cookie in xhs.session.cookies:
            result["cookie_jar_entries"].append({
                "name": cookie.name,
                "domain": cookie.domain,
                "value_length": len(cookie.value),
                "value_preview": cookie.value[:10] + "..."
            })
    except Exception as e:
        result["cookie_jar_error"] = str(e)

    # Show saved cookie file keys
    if os.path.exists(COOKIE_FILE):
        try:
            with open(COOKIE_FILE, "r") as f:
                data = json.load(f)
                saved = data.get("cookie", "")
                if saved:
                    for part in saved.split(";"):
                        part = part.strip()
                        if "=" in part:
                            key, val = part.split("=", 1)
                            result["saved_cookie_keys"].append({
                                "key": key.strip(),
                                "value_length": len(val.strip())
                            })
        except Exception as e:
            result["saved_cookie_error"] = str(e)

    return result


# --- Debug: test note creation endpoint ---
@app.get("/debug/test-create-note")
def debug_test_create_note(x_api_key: str | None = Header(None)):
    """Test create_note approaches to find what works for international accounts."""
    require_api_key(x_api_key)
    import json as _json
    import requests as _requests

    xhs = get_client()
    results = {}

    # First verify auth still works
    try:
        info = xhs.get(
            "/api/galaxy/creator/home/personal_info", is_creator=True
        )
        results["0_auth"] = {"ok": True, "name": str(info.get("nickname", ""))[:30]}
    except Exception as e:
        results["0_auth"] = {"ok": False, "error": str(e)}
        return results

    # Call sbtsource first (the browser does this to "register" the session)
    try:
        sbt_resp = _requests.post(
            "https://as.rednote.com/api/sec/v1/sbtsource",
            json={"callFrom": "creator-platform", "appId": "ugc"},
            headers={
                "Origin": "https://creator.rednote.com",
                "Referer": "https://creator.rednote.com/",
                "Content-Type": "application/json",
                "Cookie": xhs.cookie,
            },
            timeout=10,
        )
        results["0b_sbtsource"] = {"status": sbt_resp.status_code, "response": sbt_resp.json() if sbt_resp.status_code == 200 else sbt_resp.text[:200]}
    except Exception as e:
        results["0b_sbtsource"] = {"error": str(e)}

    uri = "/web_api/sns/v2/note"
    # Include capa_trace_info like the browser does
    common_data = {
        "type": 1, "title": "API test (will delete)", "note_id": "",
        "desc": "Testing API connectivity - private post",
        "source": '{"type":"web","ids":"","extraInfo":"{\\"subType\\":\\"official\\"}"}',
        "business_binds": _json.dumps({
            "version": 1, "noteId": 0, "noteOrderBind": {},
            "notePostTiming": {"postTime": ""},
            "noteCollectionBind": {"id": ""}
        }, separators=(",", ":")),
        "ats": [], "hash_tag": [], "post_loc": {},
        "privacy_info": {"op_type": 1, "type": 1},  # PRIVATE
        "capa_trace_info": {"contextJson": "{}"},
    }
    data = {
        "common": common_data,
        "image_info": {"images": []},
        "video_info": None,
    }
    headers = {"Referer": "https://creator.rednote.com/publish/publish"}

    # Approach 1: webapi.rednote.com with capa_trace_info
    try:
        res = xhs.post(uri, data, headers=headers)
        if hasattr(res, 'status_code'):
            try:
                results["1_webapi_with_trace"] = {"response": res.json()}
            except Exception:
                results["1_webapi_with_trace"] = {"status": res.status_code, "text": res.text[:300]}
        else:
            results["1_webapi_with_trace"] = {"response": res}
    except Exception as e:
        results["1_webapi_with_trace"] = {"error": str(e)}

    # Approach 2: www.rednote.com + /fe_api/burdock/v2/note/post
    try:
        burdock_uri = "/fe_api/burdock/v2/note/post"
        # Temporarily swap host to www.rednote.com
        old_host = xhs._host
        xhs._host = "https://www.rednote.com"
        res2 = xhs.post(burdock_uri, data, headers=headers)
        xhs._host = old_host
        if hasattr(res2, 'status_code'):
            try:
                results["2_www_burdock"] = {"response": res2.json()}
            except Exception:
                results["2_www_burdock"] = {"status": res2.status_code, "text": res2.text[:300]}
        else:
            results["2_www_burdock"] = {"response": res2}
    except Exception as e:
        xhs._host = old_host if 'old_host' in dir() else "https://webapi.rednote.com"
        results["2_www_burdock"] = {"error": str(e)}

    # Approach 3: Try edith.xiaohongshu.com (Chinese host) — might not enforce XYS
    try:
        old_host = xhs._host
        xhs._host = "https://edith.xiaohongshu.com"
        res3 = xhs.post(uri, data, headers=headers)
        xhs._host = old_host
        if hasattr(res3, 'status_code'):
            try:
                results["3_edith_xiaohongshu"] = {"response": res3.json()}
            except Exception:
                results["3_edith_xiaohongshu"] = {"status": res3.status_code, "text": res3.text[:300]}
        else:
            results["3_edith_xiaohongshu"] = {"response": res3}
    except Exception as e:
        xhs._host = old_host if 'old_host' in dir() else "https://webapi.rednote.com"
        results["3_edith_xiaohongshu"] = {"error": str(e)}

    return results
