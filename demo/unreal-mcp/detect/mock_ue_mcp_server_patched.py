#!/usr/bin/env python3
"""Negative oracle: a *patched* UE-5.8-style MCP endpoint — the sandbox hole is closed.

Same server as ../mock_ue_mcp_server.py (it reuses it wholesale), with one change: the submitted
script never sees an allowlisted module that carries the real builtins. Every allowed module —
whether pre-bound in the namespace OR obtained via `import` inside the script — is a scrubbed copy
whose `__dict__["__builtins__"]` is the guarded builtins. So the documented escape
(`json.__dict__["__builtins__"]["open"]`) recovers a *guarded* wrapper, not the real `open`.

This is what a correct fix looks like to the detector: the sandbox is still ADVERTISED (naive
`import os` / write-`open()` are rejected) but is no longer ESCAPABLE. A correct detector must report
`not_vulnerable` here — it proves the detector and the scanner signature do not false-positive on a
patched server.

It is a *minimal* patched model: it closes the documented module-`__builtins__` vector that the
detector probes, not a full interpreter rewrite. That is exactly the negative fixture a signature
needs — no more.

    python3 detect/mock_ue_mcp_server_patched.py 8112
    python3 detect/detect_sandbox_escape.py --endpoint http://127.0.0.1:8112/mcp   # => not vulnerable
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

# Reuse the vulnerable mock wholesale; we only change how the script sees modules.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mock_ue_mcp_server as base  # noqa: E402

_ALLOWED = ("json", "math", "datetime", "copy", "re", "time")
_orig_namespace = base._sandbox_namespace  # capture BEFORE we override (avoid self-recursion)


def _scrub(mod, guarded: dict):
    """A copy of `mod` that behaves normally but whose own __builtins__ is the guarded dict."""
    fake = types.ModuleType(getattr(mod, "__name__", "module"))
    fake.__dict__.update({k: v for k, v in vars(mod).items() if k != "__builtins__"})
    fake.__dict__["__builtins__"] = guarded
    return fake


def _patched_namespace() -> dict:
    ns = _orig_namespace()
    guarded = dict(ns["__builtins__"])         # copy so we can swap the importer
    enforce = guarded.get("__import__")        # the allowlist-enforcing guarded importer
    cache: dict[str, object] = {}

    def scrubbing_import(name, *args, **kwargs):
        mod = enforce(name, *args, **kwargs)   # enforces the allowlist (raises for e.g. os)
        root = name.split(".")[0]
        if root in _ALLOWED:
            return cache.setdefault(root, _scrub(mod, guarded))
        return mod

    guarded["__import__"] = scrubbing_import
    ns["__builtins__"] = guarded
    # Pre-bound modules are scrubbed too, and share the cache so `import json` returns the same one.
    for name in _ALLOWED:
        if isinstance(ns.get(name), types.ModuleType):
            ns[name] = cache.setdefault(name, _scrub(ns[name], guarded))
    return ns


base._sandbox_namespace = _patched_namespace  # execute_tool_script() looks this up by global name


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    port = int(argv[0]) if argv else 8112
    srv = base.ThreadingHTTPServer(("127.0.0.1", port), base._Handler)
    print(f"PATCHED UE 5.8 MCP (negative oracle) on http://127.0.0.1:{port}/mcp  "
          f"(sandbox advertised, escape closed)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
