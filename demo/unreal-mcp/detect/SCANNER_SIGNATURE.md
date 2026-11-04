# Scanner signature spec — UE 5.8 ProgrammaticToolset Python sandbox escape

**Status:** detection spec + fixtures for the `ascend_scan` MCP catalog. Path A of ENG-2269.
**Reference:** HackerOne #3907191. **Severity:** Critical (RCE-equivalent under the editor user).

This is a hand-off, not an implementation: the `ascend_scan` engine is a compiled binary whose
source is private (see `ascend-agent/client/scan.py`), so the signature lands in the scanner
catalog, not here. This document gives the catalog team the vulnerability condition, both a static
and a live-URL detection approach, and ready-to-use fixtures and an oracle.

## What to detect

A UE-5.8-style native MCP server exposing a `ProgrammaticToolset` whose `execute_tool_script`
runs operator-submitted Python in an **advertised sandbox that is not real**:

- it blocks naive escapes — `import os` and write-mode `open()` are rejected, and
  `get_execution_environment` advertises an import allowlist
  (`frozenset({'re','copy','datetime','math','json','time'})`);
- **but** an allowlisted stdlib module retains the *real* builtins on its own
  `__dict__["__builtins__"]`, so `json.__dict__["__builtins__"]["open"]` / `["__import__"]`
  hand back an unrestricted `open` / `__import__` → filesystem R/W, process exec, network egress.

The root cause is the sandbox exposing genuine module objects while relying on a swapped
`__builtins__` in the script namespace only. Any allowlisted module that was imported normally
defeats it.

## Detection approach

### Static (scan an MCP server as a repo / package / directory)
Flag a server that **both** (a) implements a script-execution tool (names seen in the wild:
`execute_tool_script`, a `ProgrammaticToolset`/`programmatic` toolset, an `execute_tool` dispatcher)
**and** (b) builds its sandbox by overriding `__builtins__`/`open`/`__import__` in an `exec`/`compile`
namespace while binding real stdlib module objects (`json`, `re`, `math`, `datetime`, `copy`,
`time`) into that same namespace. The tell is a restricted-builtins dict applied to the script but
real module objects reachable from it. Presence of the advertised allowlist string above is a strong
secondary indicator.

### Live URL (scan a reachable MCP endpoint)
The scanner already accepts a live MCP URL. The runtime check is three MCP `call_tool`s against
`…ProgrammaticToolset.execute_tool_script` and is **benign — it causes no side effects**:

1. submit `import os` → expect rejection `Import of 'os' is not permitted`  *(sandbox advertised)*
2. submit write-mode `open()` → expect rejection `Mode 'w' is not permitted`  *(sandbox advertised)*
3. submit the primitive below → the recovered `open`/`__import__` are the **real** builtins ⇒ **escapable**

Verdict = **vulnerable** iff a sandbox is advertised (1 and 2 rejected) AND step 3 recovers the
*real* builtins. Decide "real" by **type** (`builtin_function_or_method` vs. a guard `function`),
never by invoking them — this is what avoids a false positive on a patched sandbox that still exposes
guarded `open`/`__import__` wrappers. This exact logic is implemented and tested in
`detect_sandbox_escape.py` (Path B) and can be lifted as the catalog's live-URL probe. Transport is
MCP **streamable-HTTP** (not stdio).

Benign primitive (recovers the builtins by type, invokes none of them):
```python
import json
def run():
    try:
        b = json.__dict__["__builtins__"]
    except Exception:
        return {"open_is_real": False, "import_is_real": False}
    if not isinstance(b, dict):
        b = getattr(b, "__dict__", {})
    real = lambda fn: type(fn).__name__ == "builtin_function_or_method"
    o, i = b.get("open"), b.get("__import__")
    return {"open_is_real": callable(o) and real(o), "import_is_real": callable(i) and real(i)}
```

## Fixtures / oracle (in this directory tree)

| Fixture | Use |
|---|---|
| `../mock_ue_mcp_server.py` | **Positive oracle** — faithfully reproduces the broken sandbox; a correct signature must flag it. Loopback only. |
| `../probes/t0a_negative_import_os.py`, `t0b_negative_open_tmp.py` | The "sandbox advertised" controls (expected rejections). |
| `../probes/t1_write_outside.py`, `t2_os_date.py`, `t3*.py` | Impact payloads (file write / exec / egress) — for an impact-confirming mode; **not** needed for benign detection. |
| the primitive above | The benign escape signal (type-based, no side effects). |
| `mock_ue_mcp_server_patched.py` | **Negative oracle** — same server, hole closed (modules scrubbed so `json.__builtins__` yields guarded wrappers). A correct signature must NOT flag it. |
| `detect_sandbox_escape.py --json` | Reference live-URL implementation + output shape. |
| `test_detect.py` | Asserts true positive, **no false positive** (patched oracle), and no side effects. |

**Still worth adding:** a negative case for an MCP server with **no** script-execution tool at all
(the signature must stay silent). The patched oracle above already covers the advertised-but-fixed
false-positive case.

## Suggested finding shape
`{ reference: "HackerOne #3907191", tool: "...ProgrammaticToolset.execute_tool_script",
severity: "critical", verdict: "vulnerable|not_vulnerable|inconclusive", signals: {...}, benign: true }`
— matches `detect_sandbox_escape.py --json`.

## Open questions for the catalog team
- Does the current MCP catalog already flag script-exec toolsets at all? (Run the spike:
  `ascend_scan` the mock, see what comes back — needs a Straiker PAT, which this workspace lacks.)
- Static-only, live-URL-only, or both? Live-URL is higher-confidence here (the escape is a runtime
  property); static is the "safe to install?" pre-check.
