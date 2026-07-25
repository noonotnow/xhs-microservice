from fastapi import FastAPI, HTTPException, Header, UploadFile, File
from pydantic import BaseModel
import os
import json
import uuid
import shutil
from pathlib import Path

from xhs import XhsClient
from sign_service import sign

app = FastAPI(title="XHS Microservice", version="1.0.0")

# --- Config ---
API_KEY = os.getenv("XHS_API_KEY", "change-me-in-production")
DATA_DIR = os.getenv("DATA_DIR", "/app/data")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/data/uploads")
COOKIE_FILE = os.path.join(DATA_DIR, "cookie.json")
QR_STATE_FILE = os.path.join(DATA_DIR, "qr_state.json")

# --- Persistent client (singleton) ---
client: XhsClient | None = None
login_client: XhsClient | None = None


def require_api_key(x_api_key: str | None):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")


def load_cookie() -> str:
    if os.path.exists(COOKIE_FILE):
        with open(COOKIE_FILE, "r") as f:
            data = json.load(f)
            return data.get("cookie", "")
    return ""


def save_cookie(cookie_str: str):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(COOKIE_FILE, "w") as f:
        json.dump({"cookie": cookie_str}, f)


def get_client() -> XhsClient:
    """Get or create the persistent XhsClient singleton."""
    global client
    if client is None:
        cookie = load_cookie()
        client = XhsClient(cookie=cookie, sign=sign)
        # For international RedNote accounts:
        # - _host stays as edith.xiaohongshu.com (correct for API)
        # - _creator_host changes to creator.rednote.com (international creator)
        # - Creator endpoints use the library's built-in Python signing
        #   which generates x-s-common (no Playwright needed for publishing!)
        client._creator_host = "https://creator.rednote.com"
        client.home = "https://creator.rednote.com"
        client.session.headers.update({
            "Origin": "https://creator.rednote.com",
            "Referer": "https://creator.rednote.com/",
        })
        _patch_international_urls(client)
    return client


def refresh_client():
    """Force-rebuild client (e.g., after QR login succeeds)."""
    global client
    cookie = load_cookie()
    client = XhsClient(cookie=cookie, sign=sign)
    client._creator_host = "https://creator.rednote.com"
    client.home = "https://creator.rednote.com"
    client.session.headers.update({
        "Origin": "https://creator.rednote.com",
        "Referer": "https://creator.rednote.com/",
    })
    _patch_international_urls(client)


def get_login_client() -> XhsClient:
    """Create a client using xiaohongshu.com for QR login.
    QR login must go through xiaohongshu.com — the resulting cookies
    work cross-domain against rnote.com APIs."""
    cookie = load_cookie()
    login_client = XhsClient(cookie=cookie, sign=sign)
    # Keep default xiaohongshu.com host for login
    # Do NOT set rnote.com hosts
    return login_client


def _patch_international_urls(xhs_client):
    """Monkey-patch the xhs library to use international endpoints for publishing."""
    import types

    # Patch upload_file to use rnote upload server (fallback to xiaohongshu if needed)
    original_upload = xhs_client.upload_file

    def patched_upload_file(self, file_id, token, file_path, content_type="image/jpeg"):
        import os as _os
        # Try rnote upload first, the CDN might be shared
        url = "https://ros-upload.xiaohongshu.com/" + file_id
        headers = {"X-Cos-Security-Token": token, "Content-Type": content_type}
        with open(file_path, "rb") as f:
            return self.request("PUT", url, data=f, headers=headers)

    xhs_client.upload_file = types.MethodType(patched_upload_file, xhs_client)

    # Patch create_note to use correct Referer
    original_create_note = xhs_client.create_note

    def patched_create_note(self, title, desc, note_type, ats=None, topics=None,
                            image_info=None, video_info=None, post_time=None, is_private=False):
        from datetime import datetime as _dt
        import json as _json

        if ats is None:
            ats = []
        if topics is None:
            topics = []
        if post_time:
            post_date_time = _dt.strptime(post_time, "%Y-%m-%d %H:%M:%S")
            post_time = round(int(post_date_time.timestamp()) * 1000)

        uri = "/web_api/sns/v2/note"
        business_binds = {
            "version": 1, "noteId": 0, "noteOrderBind": {},
            "notePostTiming": {"postTime": post_time},
            "noteCollectionBind": {"id": ""}
        }
        data = {
            "common": {
                "type": note_type, "title": title, "note_id": "", "desc": desc,
                "source": '{"type":"web","ids":"","extraInfo":"{\\"subType\\":\\"official\\"}"}',
                "business_binds": _json.dumps(business_binds, separators=(",", ":")),
                "ats": ats, "hash_tag": topics, "post_loc": {},
                "privacy_info": {"op_type": 1, "type": int(is_private)},
            },
            "image_info": image_info,
            "video_info": video_info,
        }
        headers = {"Referer": "https://creator.xiaohongshu.com/"}
        return self.post(uri, data, headers=headers)

    xhs_client.create_note = types.MethodType(patched_create_note, xhs_client)


# --- QR Login ---
@app.get("/login/qr")
def get_qr(x_api_key: str | None = Header(None)):
    global login_client
    require_api_key(x_api_key)
    login_client = get_login_client()
    qr = login_client.get_qrcode()
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(QR_STATE_FILE, "w") as f:
        json.dump({"qr_id": qr["qr_id"], "code": qr["code"]}, f)
    return {
        "qr_id": qr["qr_id"],
        "code": qr["code"],
        "url": qr["url"],
    }


@app.get("/login/status")
def check_login_status(x_api_key: str | None = Header(None)):
    global login_client
    require_api_key(x_api_key)
    if not os.path.exists(QR_STATE_FILE):
        raise HTTPException(status_code=400, detail="No QR login in progress. Call /login/qr first.")
    with open(QR_STATE_FILE, "r") as f:
        qr_state = json.load(f)
    if login_client is None:
        login_client = get_login_client()
    status = login_client.check_qrcode(qr_state["qr_id"], qr_state["code"])
    if status.get("code_status") == 2:
        # Save cookies from xiaohongshu.com login
        save_cookie(login_client.cookie)
        # Rebuild the main client with rnote.com hosts + fresh cookies
        refresh_client()
        login_client = None  # Clean up
        os.remove(QR_STATE_FILE)
    return {
        "code_status": status.get("code_status"),
        "login_info": status.get("login_info"),
    }


# --- Manual Cookie Login ---
class CookieLoginRequest(BaseModel):
    cookie: str


@app.post("/login/cookie")
def login_with_cookie(req: CookieLoginRequest, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    if not req.cookie.strip():
        raise HTTPException(status_code=400, detail="Cookie string is empty")
    save_cookie(req.cookie.strip())
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
    except Exception as e:
        return {"valid": False, "error": str(e)}


# --- File Upload ---
@app.post("/upload")
async def upload_image(
    file: UploadFile = File(...),
    x_api_key: str | None = Header(None),
):
    require_api_key(x_api_key)
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
    xhs = get_client()

    for f in req.files:
        if not os.path.exists(f):
            raise HTTPException(status_code=400, detail=f"File not found: {f}")

    # Look up topics if keywords provided
    topics = []
    for keyword in req.topic_keywords:
        try:
            suggestions = xhs.get_suggest_topic(keyword)
            if suggestions:
                topics.append(suggestions[0])
        except Exception:
            pass

    try:
        result = xhs.create_image_note(
            title=req.title,
            desc=req.desc,
            files=req.files,
            post_time=req.post_time,
            topics=topics,
            is_private=req.is_private,
        )
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Health Check ---
@app.get("/health")
def health():
    return {"status": "ok", "has_cookie": os.path.exists(COOKIE_FILE)}


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

    # Step 1b: get_self_info_from_creator (creator endpoint, uses Python signing + x-s-common)
    try:
        info = xhs.get_self_info_from_creator()
        results["1b_creator_self_info"] = {"ok": True, "data": str(info)[:200]}
    except Exception as e:
        results["1b_creator_self_info"] = {"ok": False, "error": str(e)}

    # Step 2: get_upload_files_permit
    try:
        file_id, token = xhs.get_upload_files_permit("image")
        results["2_upload_permit"] = {"ok": True, "file_id": file_id, "token": token[:20] + "..."}
    except Exception as e:
        results["2_upload_permit"] = {"ok": False, "error": str(e)}

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
