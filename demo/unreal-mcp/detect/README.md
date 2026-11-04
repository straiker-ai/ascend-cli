# Detection — UE 5.8 MCP sandbox escape (ENG-2269, POC-A)

The reproduce/demo in `../` proves impact. This directory is the **detection** side: answer
"is this MCP endpoint vulnerable?" *without* causing impact. Covers two of the three paths scoped
for ENG-2269 (POC-A).

## Path A — static scanner signature (hand-off)
`SCANNER_SIGNATURE.md` — the vulnerability condition, a static + live-URL detection approach, the
finding shape, and fixtures/oracle, written for the `ascend_scan` catalog team. The scanner is a
**private compiled binary** (`ascend-agent/client/scan.py` drives it), so the signature lands there,
not in this repo. Our contribution is the spec + `../mock_ue_mcp_server.py` as the positive oracle
and `detect_sandbox_escape.py` as the reference live-URL probe.

*Not done here:* the "spike" — running `ascend_scan` against the mock to see what the catalog
already flags — needs a Straiker PAT + the scanner installed, neither of which is in this workspace.
Run it where those exist.

## Path B — active runtime detector (built, tested)
`detect_sandbox_escape.py` — reuses `../unreal_mcp_adapter.py` to probe a live endpoint and returns a
scan-style finding. **Benign by construction:** it recovers `json.__builtins__` and checks whether
`open`/`__import__` are the **real** (unrestricted) builtins — decided by *type*
(`builtin_function_or_method` vs. a sandbox-guard `function`), never by invoking them. No file write,
no process, no network. The type check is what stops a false positive on a patched-but-advertised
sandbox that still exposes guarded wrappers.

```bash
# against the local mock
python3 demo/unreal-mcp/mock_ue_mcp_server.py 8111 &
python3 demo/unreal-mcp/detect/detect_sandbox_escape.py --endpoint http://127.0.0.1:8111/mcp
# => VULNERABLE [severity: critical];  --json for the finding;  exit 1 on a positive detection

# against a real editor (authorization required for a non-loopback host)
python3 demo/unreal-mcp/detect/detect_sandbox_escape.py --endpoint https://host:8000/mcp --authorized --json
```

Verdict = **vulnerable** iff a sandbox is advertised (`import os` and write-`open()` both rejected)
**and** the benign primitive recovers the *real* builtins. Advertised-but-not-escapable ⇒ not
vulnerable; no sandbox advertised ⇒ inconclusive (not this target).

### Fixtures and tests
- `mock_ue_mcp_server_patched.py` — **negative oracle**: the same server with the hole closed
  (modules scrubbed so `json.__builtins__` yields guarded wrappers). A correct detector/signature
  reports `not_vulnerable` here.
- `test_detect.py` — asserts true positive (vulnerable mock → `vulnerable`), **no false positive**
  (patched mock → `not_vulnerable`), and no side effects. Run: `python3 demo/unreal-mcp/detect/test_detect.py`
  (or `pytest`).

### How this slots into `ascend-agent` (not done — needs a product/policy decision)
`ascend-agent` already has a bounded MCP client (`local_mcp_list` / `local_mcp_call`,
`client/ascend/integrations/mcp_client.py`) behind its Session/policy gates. This detector could
become a sibling bounded tool (a `ToolDefinition` in `DEFINITIONS`) — but two things must be decided
first, which is why it ships standalone here:

1. **Transport.** That client is deliberately **stdio-only** ("credential-bearing servers are outside
   this increment"); the UE endpoint is **streamable-HTTP**. Either add an HTTP transport to the
   hardened client or keep this as a separate bounded check.
2. **Surface + policy.** A detector that calls `execute_tool_script` is an active probe on a target.
   It needs ascend-agent's authorization/benign-fixture framing (this script's `--authorized`
   loopback guard and side-effect-free primitive are the starting point).

## Relationship to the exploits
- **POC-A** (direct sandbox escape) — detected by **both** paths here.
- **POC-B** (indirect agent coercion) — a different detection story (Ascend runtime assessment,
  "Path C"); tracked by the checkbox on ENG-2269, not built.
