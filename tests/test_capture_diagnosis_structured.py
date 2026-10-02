"""A failed capture says what happened as {reason, detail, next}, not as prose to regex.

MEASURED: given "no chat input found" as prose, the agent blamed a bot wall and spent ten
minutes on manual capture and a scripted POST; the note itself said the drive was at the site
root. The reason and the next step now travel in the JSON error envelope."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from discovery.capture import capture_diagnosis  # noqa: E402


def _ev(*notes):
    return {"notes": list(notes), "pairs": [], "send_verified": False}


def test_site_root_is_named_and_the_next_step_is_the_page_url():
    d = capture_diagnosis(_ev("browser: chrome", "no chat input found — capture may only contain page bootstrap (this is the site root: if the chat lives on a specific page, capture that page's URL)"))
    assert d["reason"] == "site_root_no_widget" and "page URL" in d["next"]


def test_no_input_on_a_real_page_asks_for_a_look_not_a_retry():
    d = capture_diagnosis(_ev("no chat input found — capture may only contain page bootstrap"))
    assert d["reason"] == "no_chat_input" and "--manual" in d["next"]


def test_typed_into_the_wrong_box():
    d = capture_diagnosis(_ev("typed prompt via input[type='text'] (score=0.0, frame=main)", "TYPED BUT NOT OBSERVED IN TRAFFIC — the input we typed into was probably not the chat widget (e.g. a site search box)"))
    assert d["reason"] == "typed_not_observed"


def test_navigation_and_manual_and_fallback():
    assert capture_diagnosis(_ev("navigation issue: DNS could not resolve the host"))["reason"] == "navigation_failed"
    assert capture_diagnosis(_ev("MANUAL MODE — drive the widget yourself; recording all traffic", "NO PROMPT SENT — manual capture timed out without seeing the prompt"))["reason"] == "manual_no_send"
    assert capture_diagnosis(_ev("NO PROMPT SENT — capture contains only page bootstrap"))["reason"] == "no_prompt_sent"
    assert capture_diagnosis(_ev())["reason"] == "capture_unverified"
    assert capture_diagnosis({"diagnosis": {"reason": "x", "next": "y"}})["reason"] == "x"


def test_the_json_error_envelope_carries_the_diagnosis(capsys, monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shells" / "cli"))
    import ascend  # noqa: PLC0415
    monkeypatch.setattr(ascend, "_wants_json", lambda: True)
    try:
        ascend._die("the capture never delivered the prompt", code=ascend.EXIT_ERROR, error_code="capture_no_prompt",
                    diagnosis={"reason": "site_root_no_widget", "detail": "d", "next": "n"})
    except SystemExit as exc:
        assert exc.code == ascend.EXIT_ERROR
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["ok"] is False and out["error"]["code"] == "capture_no_prompt"
    assert out["diagnosis"] == {"reason": "site_root_no_widget", "detail": "d", "next": "n"}
    assert out["error"]["diagnosis"]["next"] == "n"
