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
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
COOKIE_FILE = os.path.join(DATA_DIR, "cookie.json")
QR_STATE_FILE = os.path.join(DATA_DIR, "qr_state.json")

# --- Persistent client (singleton) ---
client: XhsClient | None = None


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
    return client


def refresh_client():
    """Force-rebuild client (e.g., after QR login succeeds)."""
    global client
    cookie = load_cookie()
    client = XhsClient(cookie=cookie, sign=sign)


# --- QR Login ---
@app.get("/login/qr")
def get_qr(x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    xhs = get_client()
    qr = xhs.get_qrcode()
    # Save qr_id + code for check_qrcode later
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
    require_api_key(x_api_key)
    if not os.path.exists(QR_STATE_FILE):
        raise HTTPException(status_code=400, detail="No QR login in progress. Call /login/qr first.")
    with open(QR_STATE_FILE, "r") as f:
        qr_state = json.load(f)
    xhs = get_client()
    status = xhs.check_qrcode(qr_state["qr_id"], qr_state["code"])
    # code_status: 0=waiting, 1=scanned, 2=confirmed
    if status.get("code_status") == 2:
        save_cookie(xhs.cookie)
        refresh_client()
        os.remove(QR_STATE_FILE)
    return {
        "code_status": status.get("code_status"),
        "login_info": status.get("login_info"),
    }


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
