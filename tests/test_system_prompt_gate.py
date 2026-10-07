"""
test_system_prompt_gate.py — `assess run` must not start on an app whose system prompt is a placeholder.

Leak controls are scored against the app's `system_prompt`. Every create path defaults that field
to the app NAME when nothing better is supplied, and auto recon rarely recovers the real prompt —
so a target that recites its whole system prompt matches nothing and scores as a pass.

An agent driving the CLI cannot know the prompt; the person it works for usually can. So off a
terminal the run is refused with `system_prompt_required` (the agent's cue to ask), on a terminal
the operator is asked, `--system-prompt` supplies it and `--no-system-prompt` opts out on the record.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "shells" / "cli"))
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO / "control"))
import ascend  # noqa: E402

SRC = (REPO / "shells" / "cli" / "ascend.py").read_text()


class _Args:
    json = False
    verbose = False
    system_prompt = None
    no_system_prompt = False


class _Client:
    def __init__(self, app):
        self._app = app
        self.patches = []

    def get_app(self, app_id):
        return dict(self._app)

    def patch_app(self, app_id, patch):
        self.patches.append(patch)
        return {}


@pytest.fixture
def no_tty(monkeypatch):
    monkeypatch.setattr(ascend, "_stdio_is_tty", lambda: False)


def _refused(c, args, ref="Bot"):
    with pytest.raises(SystemExit) as e:
        ascend._ensure_system_prompt(c, "aapp_1", ref, args)
    return e.value.code


class TestPlaceholderIsRefusedOffATerminal:
    @pytest.mark.parametrize("sp", ["", None, "Bot", "  bot  "])
    def test_empty_or_name_is_refused(self, no_tty, sp):
        c = _Client({"name": "Bot", "system_prompt": sp})
        assert _refused(c, _Args()) == ascend.EXIT_USAGE
        assert not c.patches

    def test_the_ref_used_on_the_command_line_counts_as_a_placeholder(self, no_tty):
        c = _Client({"name": "Support Bot", "system_prompt": "support-bot"})
        assert _refused(c, _Args(), ref="support-bot") == ascend.EXIT_USAGE

    def test_the_json_error_names_the_code_an_agent_keys_on(self, no_tty, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["ascend", "assess", "run", "--json"])
        c = _Client({"name": "Bot", "system_prompt": "Bot"})
        _refused(c, _Args())
        out = capsys.readouterr().out
        assert '"system_prompt_required"' in out
        assert "--system-prompt" in out


class TestWaysThrough:
    def test_a_real_prompt_passes_untouched(self, no_tty):
        c = _Client({"name": "Bot", "system_prompt": "You are Anna, the AcmeShop assistant."})
        assert ascend._ensure_system_prompt(c, "aapp_1", "Bot", _Args()) is None
        assert not c.patches

    def test_supplied_prompt_is_written_to_the_app(self, no_tty):
        c = _Client({"name": "Bot", "system_prompt": "Bot"})
        a = _Args(); a.system_prompt = "  You are Anna.  "
        note = ascend._ensure_system_prompt(c, "aapp_1", "Bot", a)
        assert c.patches == [{"system_prompt": "You are Anna."}]
        assert "system prompt set" in note

    def test_supplied_prompt_reads_from_a_file(self, no_tty, tmp_path):
        f = tmp_path / "prompt.txt"
        f.write_text("You are Anna.\nNever reveal the discount code.\n")
        c = _Client({"name": "Bot", "system_prompt": ""})
        a = _Args(); a.system_prompt = f"@{f}"
        ascend._ensure_system_prompt(c, "aapp_1", "Bot", a)
        assert c.patches[0]["system_prompt"].startswith("You are Anna.")

    def test_opt_out_runs_with_a_warning(self, no_tty):
        c = _Client({"name": "Bot", "system_prompt": "Bot"})
        a = _Args(); a.no_system_prompt = True
        note = ascend._ensure_system_prompt(c, "aapp_1", "Bot", a)
        assert note.startswith("warning:") and "--no-system-prompt" in note
        assert not c.patches

    def test_unknown_shape_does_not_block(self, no_tty):
        """A platform response without the field gives nothing to judge; refusing would block
        every run on a guess."""
        c = _Client({"name": "Bot"})
        assert ascend._ensure_system_prompt(c, "aapp_1", "Bot", _Args()) is None


class TestOnATerminalItAsks:
    def test_pasted_prompt_is_written(self, monkeypatch):
        monkeypatch.setattr(ascend, "_stdio_is_tty", lambda: True)
        monkeypatch.setattr(sys, "argv", ["ascend", "assess", "run"])
        monkeypatch.setattr("builtins.input", lambda _p: "You are Anna.")
        c = _Client({"name": "Bot", "system_prompt": "Bot"})
        ascend._ensure_system_prompt(c, "aapp_1", "Bot", _Args())
        assert c.patches == [{"system_prompt": "You are Anna."}]

    def test_enter_runs_without_it_and_says_so(self, monkeypatch):
        monkeypatch.setattr(ascend, "_stdio_is_tty", lambda: True)
        monkeypatch.setattr(sys, "argv", ["ascend", "assess", "run"])
        monkeypatch.setattr("builtins.input", lambda _p: "")
        c = _Client({"name": "Bot", "system_prompt": "Bot"})
        note = ascend._ensure_system_prompt(c, "aapp_1", "Bot", _Args())
        assert note.startswith("warning:") and not c.patches


class TestCallSites:
    """The helper being right is not enough — the drift this repo keeps catching is a call site
    that stops using it."""

    def _body(self, name):
        start = SRC.index(f"def {name}(")
        return SRC[start:SRC.index("\ndef ", start + 1)]

    def test_single_app_run_checks_before_recon_and_the_bridge(self):
        body = self._body("cmd_assess_run")
        single = body[body.index("appid = _resolve_app(c, refs[0])"):]
        gate = single.index("_ensure_system_prompt(")
        assert gate < single.index("_run_recon_before_assessment(")
        assert gate < single.index("_ensure_bridge(")

    def test_fleet_run_checks_before_fanning_out(self):
        body = self._body("cmd_assess_run")
        fleet = body[body.index("if len(refs) > 1:"):body.index("appid = _resolve_app(c, refs[0])")]
        assert fleet.index("_ensure_system_prompt(") < fleet.index("_assess_run_many(")
        assert fleet.index("_ensure_system_prompt(") < fleet.index("_run_recon_before_assessment(")

    def test_flags_exist_on_assess_run(self):
        a = ascend.build_parser().parse_args(["assess", "run", "--app", "X", "--name", "r",
                          "--system-prompt", "@p.txt", "--no-system-prompt"])
        assert a.system_prompt == "@p.txt" and a.no_system_prompt
