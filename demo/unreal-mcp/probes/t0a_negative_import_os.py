"""Negative control: direct import os should be rejected by the advertised sandbox."""

def run():
    import os
    return {
        "ok": True,
        "unexpected": "import os was allowed",
        "pid": os.getpid(),
    }
