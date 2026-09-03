# cli-tour.tape — the video on docs.straiker.ai/ascend-ai/cli/overview
#
#   export STRAIKER_PAT=s6r_pat_...          # vhs inherits the environment
#   python3 demo/localhost_agent.py --port 8600 &
#   vhs demo/cli-tour.tape                   # -> demo/cli-tour.mp4 (+ .gif)
#
# This replaces a tour recorded against the pre-1.1 shape, which opened on
# `ascend onboard --api ...` and taught `adapter build` -> `app create`. Those still work, but
# they are the machinery underneath `target` now, so a new reader was being sent the long way
# round on the first page they land on.
#
# GEOMETRY IS DELIBERATE. The page embeds this with `className="w-full rounded-xl"`, and the
# video it replaces is 982x828. A much wider canvas scales down to unreadable text on a narrow
# screen, so this stays close to the original aspect and sets COLUMNS=100 — the CLI's own block
# diagram is 76 visible cells, so 100 columns fits it with room and keeps the type large.
#
# Nothing secret reaches the screen: `target add` masks the bridge key it stores, and no command
# here prints a PAT. Do not add `keys list`.
#
# BEFORE RECORDING, validate every command against its own --help. Two takes were burned on
# tape errors that only showed up on screen: `assess run` requires --name (omitted) and has no
# --size flag (invented). A recording is ~2 minutes plus real probes; a flag check is seconds.
#
# NOTE on syntax: `Type` lines are ASCII-ONLY. An em dash inside a Type argument came out
# mangled on screen -- ".har - it works out which" rendered as ". it works out whichhar" --
# so keep punctuation plain. `Type` lines also contain no shell ${VAR} expansions — vhs 0.11 rejects `$` inside a
# Type argument at validate time. Environment comes from the shell that launches vhs.

Output demo/cli-tour.mp4
Output demo/cli-tour.gif

Set Shell "bash"
Set FontSize 15
Set Width 1000
Set Height 840
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set Padding 20

# --- hidden setup ---------------------------------------------------------------------------
Hide
Type "export COLUMNS=100 COLORTERM=truecolor ASCEND_LOGO=off" Enter
Type "clear" Enter
Show

# 1. The home screen: one noun, and how the pieces fit.
Type "ascend"                                                                Enter
Sleep 9s

Type "clear"                                                                 Enter
Sleep 500ms

# 2. Onboard a target from whatever evidence you have.
Type "# a url, a request copied from devtools, or a .har - it detects which"  Enter
Sleep 1s
Type "ascend target add http://127.0.0.1:8600/chat --save-as demo-bot --name 'Demo Bot'" Enter
Sleep 30s

Type "clear"                                                                 Enter
Type "# what do I have? adapter, registered, serving - one line each"        Enter
Sleep 800ms
Type "ascend target list"                                                    Enter
Sleep 8s

Type "clear"                                                                 Enter
Type "# the kinds of target it can speak to"                                 Enter
Sleep 800ms
Type "ascend target types"                                                   Enter
Sleep 5s

Type "clear"                                                                 Enter
Type "# re-prove before spending an assessment: a drifted target still produces" Enter
Type "# a clean-LOOKING run that measured nothing"            Enter
Sleep 1s
Type "ascend target check 'Demo Bot'"                                        Enter
Sleep 12s

Type "clear"                                                                 Enter
Type "# run it. the bridge starts and stops itself."                         Enter
Sleep 800ms
Type "ascend assess run --app 'Demo Bot' --name 'tour' --controls sys_prompt_leak --no-wait" Enter
Sleep 16s

Type "clear"                                                                 Enter
Type "# every command also takes --json, for an agent or a pipeline"         Enter
Sleep 800ms
Type "ascend target list --json"                                             Enter
Sleep 8s

# --- hidden teardown: leave the tenant as we found it ---------------------------------------
# Deleting the application also stops its bridge and drops its stored key.
Hide
Type "ascend bridge stop --all >/dev/null 2>&1" Enter
Sleep 3s
Type "ascend target rm 'Demo Bot' --json >/dev/null 2>&1" Enter
Sleep 6s
Show
