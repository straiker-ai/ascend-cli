"""
test_ui_contract — the terminal-presentation guarantees.

These are decorations on someone else's output, so the contract is defensive rather than
aesthetic. Four things must hold no matter what:

  1. A machine reading stdout sees byte-identical output to before. That means zero escapes when
     piped, under `NO_COLOR`, under `ASCEND_PLAIN`, and under `--json`.
  2. A rendered cell occupies the same number of terminal columns at every colour depth. Padding
     with `f"{s:10}"` counts escape BYTES, so a coloured cell silently under-pads and every
     column to its right shifts.
  3. No renderer raises. A cosmetic feature that throws on an odd locale is an outage.
  4. `gradient_bar` never overstates progress: floor not round, 99% is not a full bar, and no
     duration is invented from a single sample.

Two bugs found while writing this file, both pinned below:
  * depth is not an ordered scale — 24 (bit depth) < 256 (colour count) — so comparing depths by
    ORDER routed truecolour into the 8-colour branch and a 256-colour terminal into truecolour.
    Every tier fell through to plain, and the width test still passed, because identical-and-
    broken is still identical. Hence `test_each_tier_emits_escapes_when_it_should`.
  * `paint()` re-checks `color_ok()` and therefore discards a caller-supplied `depth=`, which is
    how the whole bar rendered plain even when asked for truecolour.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
import ui      # noqa: E402

ESC = "\033"
DEPTHS = (0, 8, 256, 24)
FRACTIONS = [i / 20 for i in range(21)]


class _Tty:
    """A stream that claims to be a TTY, so colour decisions can be exercised off a real one."""

    encoding = "utf-8"

    def __init__(self, tty=True):
        self._tty = tty

    def isatty(self):
        return self._tty


class _Raising:
    encoding = "utf-8"

    def isatty(self):
        raise OSError("no tty for you")


@pytest.fixture()
def colour_env(monkeypatch):
    """A terminal that permits colour, so the gates can be tested from a piped test run."""
    for k in ("NO_COLOR", "ASCEND_PLAIN", "ASCEND_COLOR_DEPTH", "TERM_PROGRAM", "COLORTERM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(sys, "argv", ["ascend", "status"])
    return _Tty()


# ---- 1. the colour gates ----------------------------------------------------------------------
class TestColourGates:
    def test_piped_stream_gets_no_colour(self, colour_env):
        assert ui.color_depth(_Tty(tty=False)) == 0

    def test_no_color_env_forces_zero(self, colour_env, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert ui.color_depth(colour_env) == 0

    def test_ascend_plain_beats_force_color(self, colour_env, monkeypatch):
        monkeypatch.setenv("ASCEND_FORCE_COLOR", "1")
        monkeypatch.setenv("ASCEND_PLAIN", "1")
        assert ui.color_depth(colour_env) == 0

    def test_json_on_the_command_line_silences_stdout(self, colour_env, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["ascend", "--json", "status"])
        monkeypatch.setattr(sys, "stdout", colour_env)
        assert ui.json_mode() is True
        assert ui.color_depth(sys.stdout) == 0

    def test_json_does_not_silence_stderr(self, colour_env, monkeypatch):
        """Progress and notes live on stderr; --json is a contract about stdout only."""
        monkeypatch.setattr(sys, "argv", ["ascend", "--json", "status"])
        assert ui.color_depth(colour_env) != 0

    def test_term_dumb_forces_zero(self, colour_env, monkeypatch):
        monkeypatch.setenv("TERM", "dumb")
        assert ui.color_depth(colour_env) == 0

    def test_explicit_depth_override_is_honoured(self, colour_env, monkeypatch):
        for val, want in (("8", 8), ("256", 256), ("24", 24), ("1", 0)):
            monkeypatch.setenv("ASCEND_COLOR_DEPTH", val)
            assert ui.color_depth(colour_env) == want, val

    def test_colorterm_truecolor_gives_24(self, colour_env, monkeypatch):
        monkeypatch.setenv("COLORTERM", "truecolor")
        assert ui.color_depth(colour_env) == 24

    def test_a_raising_isatty_is_treated_as_no_colour(self, colour_env):
        assert ui.color_depth(_Raising()) == 0

    def test_depth_is_never_compared_by_order(self):
        """24 is a bit depth, 256 is a colour count. `24 < 256` is true and meaningless."""
        assert ui.rich(24) and ui.rich(256)
        assert not ui.rich(8) and not ui.rich(0)


# ---- 2. visible width -------------------------------------------------------------------------
class TestVisibleWidth:
    def test_strip_ansi_removes_sgr(self):
        assert ui.strip_ansi(f"{ESC}[31mred{ESC}[0m") == "red"

    def test_strip_ansi_removes_osc(self):
        assert ui.strip_ansi(f"{ESC}]0;title\x07body") == "body"

    def test_vwidth_ignores_escapes(self):
        assert ui.vwidth(f"{ESC}[31mabc{ESC}[0m") == 3

    def test_vwidth_counts_wide_glyphs_as_two(self):
        assert ui.vwidth("中文") == 4

    def test_vwidth_counts_combining_as_zero(self):
        assert ui.vwidth("é") == 1

    def test_vpad_pads_to_visible_width(self):
        padded = ui.vpad(f"{ESC}[31mab{ESC}[0m", 6)
        assert ui.vwidth(padded) == 6
        assert len(padded) > 6, "the escape bytes must not be counted against the pad"

    def test_vpad_never_shrinks(self):
        assert ui.vwidth(ui.vpad("abcdef", 3)) == 6

    def test_vpad_right_and_center(self):
        assert ui.vpad("ab", 6, align="right").endswith("ab")
        assert ui.vwidth(ui.vpad("ab", 6, align="center")) == 6

    def test_vtrunc_never_exceeds_the_budget(self):
        for w in range(1, 12):
            assert ui.vwidth(ui.vtrunc("abcdefghijklmnop", w)) <= w, w

    def test_vtrunc_does_not_split_an_escape(self):
        out = ui.vtrunc(f"{ESC}[31mabcdefghij{ESC}[0m", 5)
        # every escape in the result is a complete, parseable sequence
        assert ui.strip_ansi(out).count(ESC) == 0

    def test_vtrunc_leaves_short_strings_alone(self):
        assert ui.vtrunc("abc", 10) == "abc"


class TestTerminalWidth:
    def test_non_tty_gets_the_fixed_default(self):
        assert ui.term_width(_Tty(tty=False), default=97) == 97

    def test_width_is_clamped(self, monkeypatch):
        monkeypatch.setattr(ui._shutil, "get_terminal_size",
                            lambda fallback=(80, 24): os.terminal_size((500, 24)))
        assert ui.term_width(_Tty(), maximum=120) == 120
        monkeypatch.setattr(ui._shutil, "get_terminal_size",
                            lambda fallback=(80, 24): os.terminal_size((5, 24)))
        assert ui.term_width(_Tty(), minimum=40) == 40

    def test_a_raising_get_terminal_size_returns_the_default(self, monkeypatch):
        def boom(fallback=(80, 24)):
            raise OSError
        monkeypatch.setattr(ui._shutil, "get_terminal_size", boom)
        assert ui.term_width(_Tty(), default=88) == 88


# ---- 3. the progress bar ----------------------------------------------------------------------
class TestGradientBar:
    @pytest.mark.parametrize("width", [10, 20, 24, 40])
    @pytest.mark.parametrize("frac", FRACTIONS)
    def test_visible_width_is_identical_across_every_tier(self, width, frac):
        """The keystone. Geometry is decided before colour, so no tier can change the columns."""
        widths = {d: ui.vwidth(ui.gradient_bar(frac, width=width, depth=d)) for d in DEPTHS}
        assert len(set(widths.values())) == 1, widths

    def test_each_tier_emits_colour_when_it_should(self):
        """Pins the depth-ordering bug: every tier once fell through to plain, and the width
        test still passed because identical-and-broken is still identical.

        Counting escapes is NOT enough -- the bar emits a literal reset regardless, so a version
        that sets no colour at all still contains \033. This asserts a colour-SETTING sequence,
        which is what actually broke.
        """
        colour = re.compile(r"\x1b\[(?:3[0-7]|9[0-7]|38;[25]);?")
        assert not colour.search(ui.gradient_bar(0.5, width=24, depth=0))
        assert colour.search(ui.gradient_bar(0.5, width=24, depth=8)), "8-colour set no colour"
        assert re.search(r"\x1b\[38;5;\d+m", ui.gradient_bar(0.5, width=24, depth=256)), \
            "256-colour tier emitted no 38;5; sequence"
        assert re.search(r"\x1b\[38;2;\d+;\d+;\d+m", ui.gradient_bar(0.5, width=24, depth=24)), \
            "truecolour tier emitted no 38;2; sequence"

    def test_256_colour_tier_run_length_compresses(self):
        """Quantising to the xterm cube makes adjacent cells share a code, so the ramp emits an
        escape only on a change: ~10 instead of one per cell. Truecolour is NOT compressible
        here — a smooth 24-step ramp across 24 cells really is 24 distinct colours."""
        assert ui.gradient_bar(1.0, width=24, depth=256).count(ESC) < 24

    def test_truecolour_escape_count_stays_bounded(self):
        """Redrawn at 8fps, so it must not balloon: at most a colour plus a reset per cell."""
        assert ui.gradient_bar(1.0, width=24, depth=24).count(ESC) <= 2 * 24 + 4

    def test_eight_colour_tier_is_flat_not_a_ramp(self):
        """8-colour has no orange. A red+yellow 'gradient' reads as a barber pole, i.e. a fault."""
        assert ui.gradient_bar(1.0, width=24, depth=8).count(ESC) <= 6

    @pytest.mark.parametrize("depth", DEPTHS)
    def test_zero_shows_no_filled_cell(self, depth):
        body = ui.strip_ansi(ui.gradient_bar(0.0, width=20, depth=depth))
        assert body.count("█") == 0 and body.count("#") == 0

    @pytest.mark.parametrize("depth", DEPTHS)
    def test_one_percent_shows_at_least_one_cell(self, depth):
        body = ui.strip_ansi(ui.gradient_bar(0.01, width=20, depth=depth))
        assert (body.count("█") + body.count("#")) >= 1

    @pytest.mark.parametrize("depth", DEPTHS)
    def test_ninety_nine_percent_is_not_full(self, depth):
        body = ui.strip_ansi(ui.gradient_bar(0.99, width=20, depth=depth))
        assert (body.count("█") + body.count("#")) < 20

    @pytest.mark.parametrize("depth", DEPTHS)
    def test_one_hundred_percent_is_full(self, depth):
        body = ui.strip_ansi(ui.gradient_bar(1.0, width=20, depth=depth))
        assert (body.count("█") + body.count("#")) == 20

    def test_filled_cells_never_decrease_as_progress_advances(self):
        seen = [ui.strip_ansi(ui.gradient_bar(f, width=24, depth=0)).count("█")
                for f in FRACTIONS]
        assert seen == sorted(seen)

    def test_over_one_is_clamped_and_the_label_never_exceeds_100(self):
        out = ui.strip_ansi(ui.gradient_bar(1.7, width=10, depth=0))
        assert "100%" in out and "170" not in out

    @pytest.mark.parametrize("bad", [None, float("nan"), "banana", object()])
    def test_unknown_progress_renders_empty_never_a_fake_pulse(self, bad):
        out = ui.strip_ansi(ui.gradient_bar(bad, width=10, depth=0))
        assert out.count("█") == 0 and "%" not in out

    def test_no_duration_is_invented(self):
        """`eta` is the caller's string; the bar does no timing."""
        assert "s" not in ui.strip_ansi(ui.gradient_bar(0.5, width=10, depth=0)).replace("%", "")
        assert "7s" in ui.strip_ansi(ui.gradient_bar(0.5, width=10, depth=0, eta="7s"))

    def test_hue_at_a_cell_does_not_shift_as_progress_advances(self):
        """The ramp spans the full width; rescaling it to `filled` would recolour the whole bar
        every tick and read as a rendering glitch."""
        first = re.findall(r"38;2;(\d+);(\d+);(\d+)", ui.gradient_bar(0.5, width=24, depth=24))
        later = re.findall(r"38;2;(\d+);(\d+);(\d+)", ui.gradient_bar(0.9, width=24, depth=24))
        assert first and later
        assert first[0] == later[0], "cell 0 changed colour as progress advanced"


# ---- 4. padding survives colour ---------------------------------------------------------------
class TestPaddingSurvivesColour:
    @pytest.mark.parametrize("word", ["serving", "dead", "GONE", "paused", "wat"])
    def test_state_cell_width_is_the_requested_width(self, word, monkeypatch):
        monkeypatch.setenv("ASCEND_COLOR_DEPTH", "24")
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert ui.vwidth(ui.state(word, width=12, stream=_Tty())) == 12

    def test_state_only_changes_colour_never_the_word(self, monkeypatch):
        monkeypatch.setenv("ASCEND_COLOR_DEPTH", "24")
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert ui.strip_ansi(ui.state("serving", stream=_Tty())) == "serving"

    def test_an_unknown_state_passes_through_untouched(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        out = ui.state("some_new_platform_status", stream=_Tty())
        assert out == "some_new_platform_status", "guessing a colour is worse than none"

    def test_kv_labels_align_in_one_column(self, monkeypatch):
        monkeypatch.setenv("ASCEND_COLOR_DEPTH", "24")
        monkeypatch.delenv("NO_COLOR", raising=False)
        lines = [ui.strip_ansi(l) for l in
                 ui.kv([("a", 1), ("longer", 2), ("mid", 3)], stream=_Tty())]
        starts = {l.rindex(str(v)) for l, v in zip(lines, (1, 2, 3))}
        assert len(starts) == 1, f"value column not aligned: {starts} in {lines}"

    def test_kv_is_plain_when_colour_is_off(self):
        lines = ui.kv([("a", 1)], stream=_Tty(tty=False))
        assert ESC not in "".join(lines)

    def test_kv_skips_none_values(self):
        assert ui.kv([("a", None), ("b", 2)], stream=_Tty(tty=False)) == ["  b  2"]

    def test_panel_lines_all_share_one_width(self):
        out = ui.panel(["short", "a considerably longer line of text"],
                       title="NO BRIDGE", tone="alarm", stream=_Tty(tty=False), width=60)
        widths = {ui.vwidth(l) for l in out.splitlines()}
        assert len(widths) == 1, widths

    def test_panel_clamps_to_a_narrow_terminal(self):
        out = ui.panel(["x" * 400], stream=_Tty(tty=False), width=50)
        assert all(ui.vwidth(l) <= 50 for l in out.splitlines())

    def test_header_is_plain_when_piped(self):
        assert ESC not in ui.header("ascend", subtitle="assess run", stream=_Tty(tty=False))

    def test_header_letter_spaces_only_the_wordmark(self):
        out = ui.strip_ansi(ui.header("ascend", subtitle="assess run", stream=_Tty(tty=False)))
        assert "A S C E N D" in out
        assert "assess run" in out, "the command path must stay verbatim and greppable"


# ---- 5. nothing raises ------------------------------------------------------------------------
class TestRenderersNeverRaise:
    RENDERERS = [
        lambda s: ui.gradient_bar(0.5, width=20, stream=s),
        lambda s: ui.panel(["a"], title="t", stream=s),
        lambda s: ui.header("ascend", subtitle="x", stream=s),
        lambda s: ui.kv([("k", "v")], stream=s),
        lambda s: ui.state("serving", width=8, stream=s),
        lambda s: ui.rule(stream=s),
        lambda s: ui.section("label", stream=s),
    ]

    @pytest.mark.parametrize("render", RENDERERS)
    def test_survives_a_stream_that_raises_on_isatty(self, render):
        assert isinstance(render(_Raising()), (str, list))

    @pytest.mark.parametrize("render", RENDERERS)
    def test_survives_a_one_column_terminal(self, render, monkeypatch):
        monkeypatch.setattr(ui, "term_width", lambda *a, **k: 1)
        assert isinstance(render(_Tty()), (str, list))

    @pytest.mark.parametrize("render", RENDERERS)
    def test_survives_a_non_utf8_stream(self, render):
        class Ascii:
            encoding = "ascii"

            def isatty(self):
                return True
        assert isinstance(render(Ascii()), (str, list))

    def test_ascii_fallback_uses_ascii_glyphs(self):
        class Ascii:
            encoding = "ascii"

            def isatty(self):
                return False
        out = ui.gradient_bar(0.5, width=10, depth=0, stream=Ascii())
        assert "█" not in out and "#" in out


# ---- 6. source discipline ---------------------------------------------------------------------
class TestSourceDiscipline:
    def test_control_api_never_imports_ui(self):
        """summarize_result is pinned by exact-substring tests; it must stay presentation-free."""
        src = (REPO / "control" / "api.py").read_text()
        assert "import ui" not in src

    def test_argparse_help_carries_no_escapes(self):
        """gen_command_map.py reads help text verbatim into docs/COMMAND_MAP.md."""
        src = (REPO / "shells" / "cli" / "ascend.py").read_text()
        m = re.search(r"LIFECYCLE_HELP\s*=\s*(?:r?)(\"\"\"|''')(.*?)\1", src, re.S)
        assert m, "LIFECYCLE_HELP not found"
        assert "\\033" not in m.group(2) and ESC not in m.group(2)


# ---- 7. the stdout contract, end to end -------------------------------------------------------
class TestStdoutContract:
    def _run(self, *args, env=None):
        e = dict(os.environ)
        e["STRAIKER_PAT"] = "s6r_pat_dummy"   # FORCED: setdefault kept a real PAT from the shell
        if env:
            e.update(env)
        return subprocess.run([sys.executable, str(REPO / "shells/cli/ascend.py"), *args],
                              capture_output=True, text=True, cwd=str(REPO), env=e, timeout=120)

    def test_help_is_plain_when_piped(self):
        r = self._run("--help")
        assert r.returncode == 0
        assert ESC not in r.stdout

    def test_help_is_plain_even_with_force_color(self):
        """The one env var that defeats the pipe check must not put escapes in help text."""
        r = self._run("--help", env={"ASCEND_FORCE_COLOR": "1", "NO_COLOR": ""})
        assert ESC not in r.stdout

    def test_version_stdout_is_unchanged(self):
        """`--json version` prints a bare version string, not a JSON object. That predates this
        work; pinning it here so a styling change cannot quietly alter it."""
        r = self._run("--json", "version")
        assert r.returncode == 0
        assert r.stdout.strip() and ESC not in r.stdout

    def test_json_stdout_has_no_escapes_even_with_force_color(self):
        """ASCEND_FORCE_COLOR defeats the pipe check; --json must still win on stdout."""
        r = self._run("--json", "version", env={"ASCEND_FORCE_COLOR": "1", "NO_COLOR": ""})
        assert ESC not in r.stdout
        r2 = self._run("--json", "doctor", env={"ASCEND_FORCE_COLOR": "1", "NO_COLOR": ""})
        assert ESC not in r2.stdout


# ---- 8. the two pre-existing bugs this work had to fix first ----------------------------------
class TestPaddingBugsFixedBeforeColour:
    """Both of these were live before any colour was added, and both are the kind of bug colour
    would have been blamed for."""

    @pytest.mark.parametrize("depth_env", [{"NO_COLOR": "1"}, {"ASCEND_COLOR_DEPTH": "24"}])
    def test_bar_pads_to_a_visible_cell_width(self, depth_env, monkeypatch):
        """`f"{bar(...):11}"` measures escape BYTES, so the PASS/FAIL column was under-padded
        by one whenever colour was on. bar() pads internally now."""
        for k, v in depth_env.items():
            monkeypatch.setenv(k, v)
        if "ASCEND_COLOR_DEPTH" in depth_env:
            monkeypatch.delenv("NO_COLOR", raising=False)
            monkeypatch.setenv("ASCEND_FORCE_COLOR", "1")
        assert ui.vwidth(ui.bar(7, 3, cell=11)) == 11
        assert ui.vwidth(ui.bar(0, 0, cell=11)) == 11, "the empty case must pad too"

    def test_the_reports_caller_no_longer_re_pads_the_bar(self):
        src = (REPO / "shells" / "cli" / "ascend.py").read_text()
        assert "{pf:11}" not in src, "re-padding a coloured bar silently does nothing"
        assert "cell=11" in src

    def test_watch_many_counts_physical_lines_not_buffer_entries(self):
        """One buf entry starts with "\\n", so `printed = len(buf)` under-counted by one and the
        cursor-up moved too few lines: the table walked down the screen every tick."""
        src = (REPO / "shells" / "cli" / "ascend.py").read_text()
        # Comment lines are stripped: the fix is explained in a comment that necessarily quotes
        # the old expression, and a naive substring check trips on its own documentation.
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        assert "printed = len(lines)" in code
        assert "printed = len(buf)" not in code

    def test_watch_many_erases_with_a_terminal_escape_not_byte_padding(self):
        """\\033[K clears to end of line regardless of what the line contains; padding to 118
        with f"{l:<118}" measures bytes and breaks the moment a line carries colour."""
        src = (REPO / "shells" / "cli" / "ascend.py").read_text()
        block = src[src.index("repaint in place"):]
        block = block[:block.index("printed = len(lines)")]
        assert "\\033[K" in block


# ---- 9. ASCEND_PLAIN is a whole-tool hatch, not a hatch for the new code only -----------------
class TestPlainHatchCoversEverything:
    """The older helpers gate on color_ok(), the new ones on color_depth(). If only the latter
    honoured ASCEND_PLAIN, "make my terminal stop" would silence the bar and leave the severity
    chips and the spinner still painting — which is not a hatch, it is a puzzle."""

    @pytest.fixture(autouse=True)
    def _plain(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("ASCEND_FORCE_COLOR", "1")
        monkeypatch.setenv("ASCEND_PLAIN", "1")

    def test_color_ok_is_false(self):
        assert ui.color_ok(_Tty()) is False

    def test_color_depth_is_zero(self):
        assert ui.color_depth(_Tty()) == 0

    @pytest.mark.parametrize("render", [
        lambda: ui.severity_chip("high"),
        lambda: ui.risk_dot("high"),
        lambda: ui.bar(7, 3),
        lambda: ui.score_cell(80),
        lambda: ui.gradient_bar(0.5, width=10),
        lambda: ui.state("serving", stream=_Tty()),
        lambda: ui.header("ascend", stream=_Tty()),
        lambda: "".join(ui.kv([("k", "v")], stream=_Tty())),
        lambda: ui.panel(["x"], stream=_Tty()),
    ])
    def test_no_renderer_emits_escapes(self, render):
        assert ESC not in render()

    def test_the_spinner_refuses_to_animate(self):
        assert ui.Progress("x", stream=_Tty()).enabled is False


# ---- 10. the design system's law ---------------------------------------------------------------
class TestDesignCanon:
    """Rules from straiker-design-skill (.claude/skills/straiker-ui). These are the mechanical
    ones -- the skill says to apply them without prompting -- so a test is the right place for
    them: they are the kind of thing that drifts back one commit at a time."""

    def test_corners_are_square(self):
        """"No rounded corners -- the system is square by default." """
        class Utf8:
            encoding = "utf-8"
            def isatty(self): return False
        box = ui.panel(["x"], title="T", stream=Utf8()) + ui.header("ascend", stream=Utf8())
        for rounded in "╭╮╰╯":
            assert rounded not in box, f"rounded corner {rounded!r} in a square system"

    def test_critical_and_high_share_the_red_family(self):
        """Canon: critical IS the fail treatment; both sit in the red family."""
        assert ui.SEV_TOKEN["critical"] == ui.SEV_TOKEN["high"] == "ascend"

    def test_low_severity_is_neutral_not_green(self):
        """Green reads "good". Low severity is still an issue, and inverting red=bad/green=good
        is an explicit reject."""
        assert ui.SEV_TOKEN["low"] == "gris"
        assert ui.brand("gris") == (217, 217, 217)
        assert "\033[32m" not in ui.severity_chip("low"), "low must not be green"

    def test_informational_is_the_defend_cyan(self):
        """informational is not an issue -- it renders as benign info."""
        assert ui.SEV_TOKEN["informational"] == ui.SEV_TOKEN["info"] == "defend"

    def test_severity_anchors_match_the_design_tokens(self):
        """Converted from the dark-mode `-600` HSL anchors. Eyeballing a colour is a bug."""
        assert ui.brand("ascend") == (255, 97, 107)     # hsla(356,100%,69%) ~ #FF616B
        assert ui.brand("pulse") == (255, 223, 82)      # hsla(49,100%,66%)
        assert ui.brand("defend") == (77, 222, 255)     # hsla(191,100%,65%)
        assert ui.brand("secure") == (133, 255, 137)    # hsla(122,100%,76%)

    def test_progress_is_status_coloured_not_brand_or_severity(self):
        """"Brand colors (rose/gold) are for the logo only." And a bar that fills with the
        severity-high red would read as "this is getting worse"."""
        assert ui.PROGRESS_RAMP == ("defend", "defend")
        assert ui.GRADIENT_BAR == ui.PROGRESS_RAMP
        rendered = ui.gradient_bar(0.6, width=24, depth=24)
        for token in ("rose", "gold"):
            r, g, b = ui.brand(token)
            assert f"38;2;{r};{g};{b}m" not in rendered, f"brand {token} used as decoration"

    def test_the_default_ramp_is_flat_not_decorative(self):
        """"No decorative color, no 'visual interest' palettes." A flat fill collapses to one
        escape; a ramp would emit many."""
        assert ui.gradient_bar(1.0, width=24, depth=24).count("38;2;") == 1

    def test_the_brand_ramp_remains_available_for_a_logged_deviation(self):
        """The law is challengeable, not absent -- an override must be possible and explicit."""
        out = ui.gradient_bar(0.6, width=24, depth=24, ramp=ui.BRAND_RAMP)
        assert out.count("38;2;") > 1
