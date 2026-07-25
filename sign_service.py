"""Playwright-based request signing for XHS API.

The XHS web client uses a JS function `window._webmsxyw` to sign requests.
We replicate this by running a headless Chromium instance.

For international (RedNote) accounts, we navigate to creator.rednote.com.
We keep a persistent browser context to avoid triggering bot detection
on every request (new browser = instant bot flag → XYW_ fallback signer).
"""
import os
import threading
from time import sleep
from playwright.sync_api import sync_playwright

STEALTH_JS_PATH = os.getenv("STEALTH_JS_PATH", "/app/stealth.min.js")
SIGN_DOMAIN = os.getenv("XHS_SIGN_DOMAIN", "creator.rednote.com")
COOKIE_DOMAIN = os.getenv("XHS_COOKIE_DOMAIN", ".rednote.com")

# Persistent browser state
_browser = None
_context = None
_page = None
_lock = threading.Lock()
_playwright = None


def _get_page():
    """Get or create a persistent browser page."""
    global _browser, _context, _page, _playwright

    if _page and not _page.is_closed():
        return _page

    # Launch persistent browser
    _playwright = sync_playwright().start()
    _browser = _playwright.chromium.launch(
        headless=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-dev-shm-usage",
        ]
    )
    _context = _browser.new_context(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        viewport={"width": 1920, "height": 1080},
        locale="en-US",
    )

    if os.path.exists(STEALTH_JS_PATH):
        _context.add_init_script(path=STEALTH_JS_PATH)

    _page = _context.new_page()
    _page.goto(f"https://{SIGN_DOMAIN}", wait_until="networkidle", timeout=30000)

    # Wait for security system to fully initialize
    _page.wait_for_function(
        "() => typeof window._webmsxyw === 'function'",
        timeout=15000
    )
    # Extra time for zeus-engine to complete webprofile verification
    sleep(8)

    return _page


def sign(uri, data=None, a1="", web_session=""):
    """Sign a request URI using XHS's web signing function.

    Uses a persistent browser context to maintain security verification
    state across requests (avoids re-triggering bot detection each time).

    Args:
        uri: The API path (e.g., "/api/sns/web/v1/feed")
        data: Optional request body data (serialized to JSON string or None)
        a1: The a1 cookie value from the current session
        web_session: The web_session cookie value

    Returns:
        dict with "x-s" and "x-t" keys
    """
    with _lock:
        for attempt in range(3):
            try:
                page = _get_page()

                # Update cookies if needed
                _context.add_cookies([
                    {"name": "a1", "value": a1, "domain": COOKIE_DOMAIN, "path": "/"}
                ])
                if web_session:
                    _context.add_cookies([
                        {"name": "web_session", "value": web_session, "domain": COOKIE_DOMAIN, "path": "/"}
                    ])

                encrypt_params = page.evaluate(
                    "([url, data]) => window._webmsxyw(url, data)",
                    [uri, data]
                )

                return {
                    "x-s": encrypt_params["X-s"],
                    "x-t": str(encrypt_params["X-t"])
                }
            except Exception as e:
                # Reset browser on failure
                _reset_browser()
                if attempt == 2:
                    raise Exception(f"Failed to sign after 3 attempts. Last error: {e}")


def _reset_browser():
    """Force-close and reset the persistent browser."""
    global _browser, _context, _page, _playwright
    try:
        if _browser:
            _browser.close()
    except Exception:
        pass
    try:
        if _playwright:
            _playwright.stop()
    except Exception:
        pass
    _browser = None
    _context = None
    _page = None
    _playwright = None
