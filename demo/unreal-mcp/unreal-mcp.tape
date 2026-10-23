# UE 5.8 native MCP — ProgrammaticToolset sandbox escape, driven through an Ascend custom adapter.
#
#   vhs demo/unreal-mcp/unreal-mcp.tape       # -> demo/unreal-mcp/unreal-mcp.gif + .mp4
#
# Deterministic and safe to re-record: the target is the LOCAL faithful UE-MCP mock on :8111, so
# the recording never depends on a live Unreal editor being up. The escape writes one benign
# canary under /tmp and spawns `date`; there is no network (T3/T3b are skipped without
# --allow-network), so the clip does not depend on a third-party site either.
#
# NOTE on syntax: `Type` lines contain no shell ${VAR} expansions — vhs 0.11 rejects `$` inside a
# Type argument at validate time. Environment comes from the shell that launches vhs instead.

Output demo/unreal-mcp/unreal-mcp.gif
Output demo/unreal-mcp/unreal-mcp.mp4

Set Shell "bash"
Set FontSize 14
Set Width 1500
Set Height 860
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 22

# --- hidden setup: start the faithful local UE-MCP mock -----------------------------------
Hide
Type "export COLORTERM=truecolor" Enter
Type "rm -f /tmp/evil-grok-python-test" Enter
Type "python3 demo/unreal-mcp/mock_ue_mcp_server.py 8111 >/tmp/mock_ue.log 2>&1 & sleep 2" Enter
Type "clear" Enter
Show

Type "# UE 5.8 ships a native MCP 'ProgrammaticToolset' — a Python orchestration sandbox." Enter
Sleep 1500ms
Type "# It blocks  import os  and write-mode open(). But an allowed module (json) still"    Enter
Type "# carries the REAL builtins on  json.__builtins__  — handing back open / __import__." Enter
Sleep 2500ms

Type "clear"                                                                               Enter
Type "# The escape is one script body submitted to execute_tool_script. Here it is:"       Enter
Sleep 800ms
Type "cat demo/unreal-mcp/probes/t1_write_outside.py"                                       Enter
Sleep 6s

Type "clear"                                                                               Enter
Type "# Ascend drives it as a custom adapter. Run the probe pack (it preflights the"       Enter
Type "# endpoint first, so it tells you whether it hit the MOCK or a LIVE editor):"         Enter
Sleep 900ms
Type "python3 demo/unreal-mcp/run_demo.py --endpoint http://127.0.0.1:8111/mcp"            Enter
Sleep 9s

Type "# T0a/T0b are negative controls — correctly BLOCKED. T1/T2 escape the sandbox."      Enter
Sleep 2500ms

Type "clear"                                                                               Enter
Type "# Not a rubber stamp — the escape really wrote a file on the host:"                   Enter
Sleep 900ms
Type "ls -l /tmp/evil-grok-python-test && cat /tmp/evil-grok-python-test"                   Enter
Sleep 5s

Type "# The same payloads beat a live UE 5.8 editor — just point the adapter at it:"        Enter
Sleep 700ms
Type "#   UE_MCP_ENDPOINT=http://127.0.0.1:8000/mcp python3 demo/unreal-mcp/run_demo.py"    Enter
Sleep 3s

# --- hidden teardown: leave the host as we found it ---------------------------------------
Hide
Type "pkill -f mock_ue_mcp_server.py" Enter
Type "rm -f /tmp/evil-grok-python-test" Enter
Type "rm -rf demo/unreal-mcp/__pycache__" Enter
Show
