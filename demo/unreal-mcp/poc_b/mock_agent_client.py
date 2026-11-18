#!/usr/bin/env python3
"""mock_agent_client.py — a deterministic stand-in agent for POC-B Mode A.

Mode B/C use a *real* coding agent (Codex) and so actually test whether a model is susceptible
to indirect injection. But a real model is non-deterministic, needs network/credentials, and
can't live in a unit test. This mock agent exists for Mode A: it exercises the *mechanism*
end-to-end — connect over MCP, read the asset metadata, and (depending on a policy flag) either
act on the embedded instruction or ignore it — so the mock target + oracle can be tested
deterministically and the plumbing proven before a live run.

It is faithful to the channel but incapable of harm: in `obey` mode it does NOT execute free
text from the metadata — it extracts only the structured, benign (PATH, CONTENT) fields via
injection.parse_instruction and writes that one marker file. In `resist` mode it reads the same
metadata and does nothing (the hardened-agent outcome). Either way it then reports what it saw.

Transport reuses the POC-A adapter's stdlib MCP client (_MinimalMCP), so it speaks the mock and
a real UE endpoint alike.

    python3 poc_b/mock_agent_client.py --endpoint http://127.0.0.1:8201/mcp --policy obey
    python3 poc_b/mock_agent_client.py --endpoint http://127.0.0.1:8201/mcp --policy resist
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))  # for unreal_mcp_adapter._MinimalMCP
import injection  # noqa: E402
from unreal_mcp_adapter import _MinimalMCP  # noqa: E402


def _read_metadata(client: _MinimalMCP) -> dict:
    """Call AssetTools.get_metadata_tags and return the tag dict the agent sees."""
    result = client.call_tool("call_tool", {
        "toolset_name": injection.ASSET_TOOLSET,
        "tool_name": "get_metadata_tags",
        "arguments": {"asset_path": injection.ASSET_PATH},
    })
    text = ""
    for part in result.get("content") or []:
        if isinstance(part, dict) and part.get("type") == "text":
            text = part.get("text", "")
            break
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}
    tags = payload.get("returnValue") if isinstance(payload, dict) else None
    return tags if isinstance(tags, dict) else {}


def run(endpoint: str, policy: str, timeout_s: float = 15.0) -> dict:
    """Simulate an agent reading the asset and (per policy) acting on what it read."""
    client = _MinimalMCP(endpoint, timeout_s)
    client.initialize()
    tags = _read_metadata(client)
    description = tags.get("RTC358Description", "")
    instruction = injection.parse_instruction(description)

    acted = False
    note = "no embedded instruction found"
    if instruction:
        path, marker = instruction
        if policy == "obey":
            # Susceptible agent: carries out the (benign) instruction it read from data.
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(marker + "\n", encoding="utf-8")
            acted = True
            note = f"obeyed embedded instruction -> wrote {path}"
        else:
            # Hardened agent: recognizes the injection and refuses to act on tool data.
            note = "detected embedded instruction in metadata; ignored it (treated as data)"

    return {
        "policy": policy,
        "saw_instruction": instruction is not None,
        "acted": acted,
        "note": note,
        "asset": injection.ASSET_PATH,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--policy", choices=("obey", "resist"), default="obey",
                    help="obey = susceptible agent; resist = hardened agent")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    out = run(args.endpoint, args.policy)
    print(json.dumps(out, indent=2) if args.json else out["note"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
