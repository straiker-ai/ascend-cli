# UE 5.8 native MCP — ProgrammaticToolset sandbox escape (Ascend demo)

Integrates the Unreal Engine 5.8 **ProgrammaticToolset Python sandbox escape**
(HackerOne #3907191) into Ascend as a bespoke **custom adapter**, so the finding can be driven
through the same `Ascend → bridge → adapter → target` path as any other engagement — and
demonstrated offline, with no Unreal install.

## The finding, in one line

UE 5.8's native MCP exposes `ProgrammaticToolset.execute_tool_script`, an "orchestration
sandbox" that blocks `import os` and `open(..., "w")` — but an allowlisted stdlib module
(`json`) still carries the **real** builtins on `json.__dict__["__builtins__"]`, handing back an
unrestricted `open` / `__import__`. That yields filesystem write, process execution, and network
egress under the Unreal Editor user. No coding agent required.

## What's here

| File | Role |
|---|---|
| `mock_ue_mcp_server.py` | Deterministic local UE-MCP endpoint that **faithfully reproduces the broken sandbox** — the same escape payloads beat it that beat live UE 5.8. Loopback only. |
| `unreal_mcp_adapter.py` | The Ascend **custom adapter** (`send_prompt`). Submits a script body to `execute_tool_script` and returns the evidence. Uses the `mcp` SDK if present, else a stdlib streamable-HTTP client. |
| `probes/` | The escape payloads **verbatim** from the POC (T0a–T3b), plus `manifest.json` with per-probe expected evidence. |
| `run_demo.py` | Self-scored runner: feeds the pack through the adapter, judges PASS/FAIL, prints a results table. |
| `unreal_escape.config.json` | Ascend `custom`-adapter config, to drive it through the real bridge. |

The probe set (self-scored locally — no cloud dependency):

| ID | Intent | Expected |
|---|---|---|
| T0a | naive `import os` | **blocked** (negative control) |
| T0b | naive `open(...,"w")` | **blocked** (negative control) |
| T1 | escape → write+read a file outside the project | canary read-back matches |
| T2 | escape → `os.popen("date")` | process stdout returned |
| T3 | escape → `urllib` HTTP GET | HTTP status returned *(network)* |
| T3b | escape → `curl` subprocess | returncode 0 *(network)* |

## Run it (offline, against the mock)

```bash
# from the repo root
python3 demo/unreal-mcp/mock_ue_mcp_server.py 8111 &      # local UE-MCP mock
python3 demo/unreal-mcp/run_demo.py --endpoint http://127.0.0.1:8111/mcp
```

Expected: T0a/T0b blocked (controls), T1/T2 escape, T3/T3b skipped. The default run performs a
real filesystem write and a real `date` process spawn — benign canaries — but **no network**.
Add `--allow-network` to include T3/T3b (a real outbound HTTP GET). `--json` for machine output.

The runner **preflights** the endpoint first (`initialize` + `list_toolsets`) and prints whether
it reached the **MOCK** or a **LIVE** editor, by the server's own name — so you always know which
you hit. An unreachable endpoint fails fast with one message (exit 2) instead of six probe errors.

## Record a clip

A VHS tape drives the whole thing against the local mock (no Unreal, no network), matching the
other recorded demos in `demo/`:

```bash
brew install vhs
vhs demo/unreal-mcp/unreal-mcp.tape       # -> demo/unreal-mcp/unreal-mcp.gif + .mp4
```

The `.gif`/`.mp4` outputs are gitignored.

## Point it at a live UE 5.8 editor

The adapter reads its endpoint from `UE_MCP_ENDPOINT` (default `http://127.0.0.1:8000/mcp`):

```bash
# with a real UE 5.8 editor + native MCP listening on :8000
UE_MCP_ENDPOINT=http://127.0.0.1:8000/mcp python3 demo/unreal-mcp/run_demo.py --allow-network
```

For the real streamable-HTTP endpoint, install the MCP SDK (`pip install mcp`); the adapter
prefers it automatically and falls back to the built-in stdlib client when it is absent.

## Drive it through the Ascend bridge

The config registers the module as a `custom` adapter:

```bash
./ascend target add --module demo/unreal-mcp/unreal_mcp_adapter.py --name 'UE5.8 MCP (escape demo)'
```

Each probe Ascend sends is submitted as the `execute_tool_script` body; the adapter returns the
script's `returnValue` (the attacker-observable evidence) for scoring.

## Safety

Benign canaries only — one temp-file write, `date`, a single HTTP GET. No reverse shells,
persistence, credential access, or project/engine mutation. The mock really executes submitted
scripts (that is the demonstrated behaviour), so keep it bound to loopback and feed it only the
payloads in `probes/`. Canary cleanup: `rm -f /tmp/evil-grok-python-test`.
