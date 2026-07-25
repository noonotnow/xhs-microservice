"""Playwright-based request signing for XHS API.

The XHS web client uses a JS function `window._webmsxyw` to sign requests.
We replicate this by running a headless Chromium instance.

For international (RedNote) accounts, we navigate to www.rednote.com
since the signing script is loaded from as.rednote.com and may generate
different signatures than the Chinese xiaohongshu.com version.
"""
import os
from time import sleep
from playwright.sync_api import sync_playwright

STEALTH_JS_PATH = os.getenv("STEALTH_JS_PATH", "/app/stealth.min.js")
# Use creator.rednote.com for international accounts — the creator page
# loads its signing JS with appId=ugc (vs xhs-pc-web on the main site)
SIGN_DOMAIN = os.getenv("XHS_SIGN_DOMAIN", "creator.rednote.com")
COOKIE_DOMAIN = os.getenv("XHS_COOKIE_DOMAIN", ".rednote.com")


def sign(uri, data=None, a1="", web_session=""):
    """Sign a request URI using XHS's web signing function.

    This is called internally by XhsClient for every API request.
    It launches a headless browser, sets the a1 cookie, and calls
    window._webmsxyw to generate the x-s and x-t headers.

    Args:
        uri: The API path (e.g., "/api/sns/web/v1/feed")
        data: Optional request body data (serialized to JSON string or None)
        a1: The a1 cookie value from the current session
        web_session: The web_session cookie value

    Returns:
        dict with "x-s" and "x-t" keys
    """
    for attempt in range(10):
        try:
            with sync_playwright() as playwright:
                chromium = playwright.chromium
                browser = chromium.launch(headless=True)
                browser_context = browser.new_context()

                if os.path.exists(STEALTH_JS_PATH):
                    browser_context.add_init_script(path=STEALTH_JS_PATH)

                context_page = browser_context.new_page()
                context_page.goto(f"https://{SIGN_DOMAIN}", wait_until="domcontentloaded")

                browser_context.add_cookies([
                    {"name": "a1", "value": a1, "domain": COOKIE_DOMAIN, "path": "/"}
                ])
                if web_session:
                    browser_context.add_cookies([
                        {"name": "web_session", "value": web_session, "domain": COOKIE_DOMAIN, "path": "/"}
                    ])

                context_page.reload()

                # Wait for _webmsxyw to be loaded by the security script
                context_page.wait_for_function(
                    "() => typeof window._webmsxyw === 'function'",
                    timeout=10000
                )

                # The security system loads in stages:
                # 1. Basic _webmsxyw appears (produces XYW_ signatures — rejected by API)
                # 2. webprofile + scripting calls verify the browser
                # 3. _webmsxyw gets upgraded (produces XYS_ signatures — accepted)
                # Wait for the upgrade by polling the output prefix
                for wait_attempt in range(20):
                    test_result = context_page.evaluate(
                        "([url, data]) => window._webmsxyw(url, data)",
                        [uri, data]
                    )
                    xs_value = test_result.get("X-s", "")
                    if xs_value.startswith("XYS_"):
                        break
                    sleep(0.5)

                encrypt_params = test_result

                browser.close()

                return {
                    "x-s": encrypt_params["X-s"],
                    "x-t": str(encrypt_params["X-t"])
                }
        except Exception as e:
            if attempt == 9:
                raise Exception(f"Failed to sign request after 10 attempts. Last error: {e}")

    raise Exception("Failed to sign request after 10 attempts")
