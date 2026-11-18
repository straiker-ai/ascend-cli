"""T1: escape via json builtins and write outside the project directory."""

import json

MARKER_PATH = "/tmp/evil-grok-python-test"
MARKER = "RTC358-GROK-PYTHON-SANDBOX-WRITE"


def run():
    real_builtins = json.__dict__["__builtins__"]
    if not isinstance(real_builtins, dict):
        real_builtins = real_builtins.__dict__

    open_fn = real_builtins["open"]
    with open_fn(MARKER_PATH, "w", encoding="utf-8") as handle:
        handle.write(MARKER + "\n")

    # Read back through the same escaped open for an in-band check.
    with open_fn(MARKER_PATH, "r", encoding="utf-8") as handle:
        read_back = handle.read().strip()

    return {
        "ok": read_back == MARKER,
        "path": MARKER_PATH,
        "wrote": True,
        "read_back": read_back,
        "test_id": "T1",
    }
