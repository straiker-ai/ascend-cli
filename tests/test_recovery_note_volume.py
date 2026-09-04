"""
test_recovery_note_volume.py — a recovered run that is RUNNING must not read like a failure.

`assess run` absorbs a transport error after the assessment is created: it asks the platform what
state the run is really in rather than reporting a failure the operator would retry into a
duplicate run. That recovery is correct and it fires routinely — the platform truncates the create
response often enough that the docs tour recorded it twice in a row.

What was wrong is the volume. Both outcomes came out in the same alarming sentence:

    note: the connection dropped (ConnectionError) after the assessment was created; it is on
    the platform with status 'running' - not re-created.

Nothing is wrong in that case and there is nothing to do. The other outcome — status `created` or
`paused` — genuinely needs the operator to resume, and must stay loud. `recovery_needs_action`
separates them; `--json` carries the full note either way.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
from unittest import mock  # noqa: E402

import api  # noqa: E402


class Dropped(Exception):
    pass


def _run_with_drop_after_create(state_status):
    """Create succeeds, the next call drops, and the platform reports `state_status`."""
    c = api.AscendAPI(token="t", base="https://example.invalid")
    calls = {"n": 0}

    def fake_req(method, path, **kw):
        if method == "POST" and path.endswith("/assessments"):
            return {"id": "asmt_live", "status": "created"}
        calls["n"] += 1
        if calls["n"] == 1:
            raise Dropped("Remote end closed connection without response")
        return {"id": "asmt_live", "status": state_status}

    with mock.patch.object(api.AscendAPI, "_req", side_effect=fake_req):
        return c.run("aapp_x", "n", wait=False)


@pytest.mark.parametrize("status", ["running", "complete"])
def test_a_recovered_run_that_is_healthy_needs_no_action(status):
    out = _run_with_drop_after_create(status)
    assert out["recovered"] is True
    assert out["recovery_needs_action"] is False, f"status {status!r} needs nothing from the user"
    assert out.get("recovery_note"), "--json still carries the full explanation"


@pytest.mark.parametrize("status", ["created", "paused"])
def test_a_recovered_run_that_is_not_running_still_demands_action(status):
    out = _run_with_drop_after_create(status)
    assert out["recovery_needs_action"] is True
    assert "resume" in out["recovery_note"], "it must say how to fix it"


def test_the_cli_stays_quiet_only_when_nothing_needs_doing(capsys):
    """The printer branch itself: absent flag defaults to LOUD, never accidentally silent."""
    import ascend
    src = Path(REPO / "shells/cli/ascend.py").read_text(encoding="utf-8")
    assert 'res.get("recovery_needs_action", True)' in src, (
        "the default must be True: an older payload without the flag keeps the loud note")
    assert "create response dropped" in src
