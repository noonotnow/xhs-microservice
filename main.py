from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os
import json
import uuid
import shutil
import traceback
from pathlib import Path

from xhs import XhsClient
from sign_service import sign

app = FastAPI(title="XHS Microservice", version="1.0.0")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "traceback": traceback.format_exc()},
    )

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
    client = XhsClient(cookie=cookie, sign=sign)
    client._host = "https://webapi.rednote.com"
    client._creator_host = "https://creator.rednote.com"
    client.home = "https://creator.rednote.com"
    client.session.headers.update({
        "Origin": "https://creator.rednote.com",
        "Referer": "https://creator.rednote.com/publish/publish",
    })
    _add_international_cookies(client)
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

    # Patch create_note: send to webapi.rednote.com (where /web_api/sns/v2/note exists)
    # with correct Referer and all international cookies set.
    # Note: sbtsource says this endpoint needs XYS_ signing, but we try with
    # Python signing + correct cookies first. If that fails, we'll need XYS.
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
        headers = {
            "Referer": "https://creator.rednote.com/publish/publish",
        }
        # Goes to webapi.rednote.com (default _host) with Python signing
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

        # Step 1: Get upload permit
        image_id, token = xhs.get_upload_files_permit("image")
        steps["1_permit"] = {"ok": True, "file_id": image_id[:30]}

        # Step 2: Upload file to CDN
        upload_resp = xhs.upload_file(image_id, token, req.files[0])
        steps["2_upload"] = {"ok": True, "status": getattr(upload_resp, 'status_code', 'unknown')}

        # Step 3: Create note
        images = [{
            "file_id": image_id,
            "metadata": {"source": -1},
            "stickers": {"version": 2, "floating": []},
            "extra_info_json": '{"mimeType":"image/jpeg"}',
        }]
        result = xhs.create_note(
            title=req.title,
            desc=req.desc,
            note_type=1,
            topics=topics,
            image_info={"images": images},
            is_private=req.is_private,
            post_time=req.post_time,
        )
        steps["3_create_note"] = {"ok": True}
        # Ensure result is JSON-serializable
        if hasattr(result, 'status_code'):
            # It's a requests.Response object
            try:
                result = result.json()
            except Exception:
                result = {"response_status": result.status_code, "response_text": result.text[:200] if result.text else "empty"}
        elif not isinstance(result, (dict, list, str, int, float, bool, type(None))):
            result = str(result)
        return {"status": "success", "data": result, "steps": steps}
    except Exception as e:
        import traceback
        return {"status": "error", "detail": str(e), "traceback": traceback.format_exc()}


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
