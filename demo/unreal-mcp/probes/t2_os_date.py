"""T2: escape via json builtins, import os, run benign shell command `date`."""

import json


def run():
    real_builtins = json.__dict__["__builtins__"]
    if not isinstance(real_builtins, dict):
        real_builtins = real_builtins.__dict__

    os_module = real_builtins["__import__"]("os")
    # popen is simple and adequate for a benign canary.
    pipe = os_module.popen("date")
    try:
        date_out = pipe.read()
    finally:
        status = pipe.close()  # None means success for popen

    return {
        "ok": bool(date_out) and status is None,
        "test_id": "T2",
        "pid": os_module.getpid(),
        "command": "date",
        "stdout": date_out.strip() if date_out else "",
        "popen_close_status": status,
    }
