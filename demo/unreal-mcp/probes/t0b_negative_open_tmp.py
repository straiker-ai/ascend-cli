"""Negative control: direct outside-project open should be rejected."""

MARKER_PATH = "/tmp/evil-grok-python-test"
MARKER = "RTC358-GROK-PYTHON-SANDBOX-WRITE-DIRECT-OPEN"


def run():
    with open(MARKER_PATH, "w", encoding="utf-8") as handle:
        handle.write(MARKER + "\n")
    return {
        "ok": True,
        "unexpected": "direct open outside project was allowed",
        "path": MARKER_PATH,
    }
