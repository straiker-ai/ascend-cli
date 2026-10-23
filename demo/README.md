# Demo tapes

Scripted terminal demos, recorded with [VHS](https://github.com/charmbracelet/vhs) so they
are deterministic and re-recordable — the script is the source of truth, not a screen
capture someone has to redo by hand.

```bash
brew install vhs
vhs demo/target-flow.tape   # the 1.1 flow, through `target`
vhs demo/full-loop.tape     # the older arc (map/adapter build/app create)
vhs demo/discover.tape      # discovery, six ways in
vhs demo/chat.tape          # talking to an agent
```

| Tape | Shows |
|---|---|
| `target-flow.tape` | **Start here for 1.1.** doctor → `target add` (one command: adapt, prove, register, store the key) → `target list` / `show` → `target check` → `assess run` → `assess watch` with a live progress bar → `--json`. |
| `full-loop.tape` | doctor → discover a live target → chat with it → onboard (register + relay + assess) → watch. The Console is never opened. |
| `discover.tape` | `--api` with only a base URL, `--curl` import, and a dead host producing a diagnosis rather than a crash. |
| `chat.tape` | A live recorded session, `/results`, and replaying the transcript. |

### Scenario demos

| Directory | Shows |
|---|---|
| [`unreal-mcp/`](unreal-mcp/) | UE 5.8 native-MCP **ProgrammaticToolset sandbox escape** driven through a bespoke Ascend custom adapter, against a faithful local mock (offline) or a live editor. |

## Before recording

The tapes drive **local** targets so a recording never depends on a third party being up:

```bash
python3 tests/live/echo_target.py 8790 &     # simple agent (leaks a fake system prompt)
python3 tests/live/api_zoo.py 8820 &         # OpenAI-style API under a /openai prefix
export STRAIKER_PAT='s6r_pat_…'
```

To film a **third-party** agent instead, swap the `--api`/`--url` in `full-loop.tape`.
Outputs (`*.gif`, `*.mp4`) are gitignored — they can show live targets.
