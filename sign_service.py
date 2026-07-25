"""Pure Python request signing for XHS API.

Uses the xhs library's built-in MD5-based signing function which generates
x-s, x-t, AND x-s-common headers. This bypasses all Playwright bot-detection
issues (XYW_ vs XYS_) because no browser is needed.

The library already uses this approach for is_creator=True endpoints
(quick_sign). We now use it for ALL requests via external_sign.
"""
from xhs.help import sign as _python_sign


def sign(uri, data=None, a1="", web_session=""):
    """Sign a request using the xhs library's built-in Python signer.

    Returns dict with x-s, x-t, AND x-s-common — all three headers
    that XHS expects. No Playwright/Chromium needed.
    """
    result = _python_sign(uri, data, a1=a1)
    return {
        "x-s": result["x-s"],
        "x-t": result["x-t"],
        "x-s-common": result["x-s-common"],
    }
