"""
test_delete_payload_contract.py — every verb that deletes an app says so with the same key.

`app delete --json` returned `deleted: true`; `target rm --json` returned `app_deleted: true` and
no `deleted` at all. A script written against one verb silently misread the other — a teardown
that checked `.get("deleted")` on `target rm` reported every successful delete as FAILED. Both
keys are now present on every delete verb, so either spelling reads correctly.
"""
import inspect
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402


def _payload_keys(fn_name):
    return inspect.getsource(getattr(ascend, fn_name))


def test_app_delete_carries_both_keys():
    src = _payload_keys("cmd_app_delete")
    assert '"deleted": True' in src and '"app_deleted": True' in src


def test_target_rm_carries_both_keys_on_success_and_failure():
    src = _payload_keys("cmd_target_rm")
    assert '"deleted": True' in src and '"app_deleted": True' in src
    assert '"deleted": False' in src and '"app_deleted": False' in src


def test_keys_rm_carries_deleted():
    src = _payload_keys("cmd_keys_rm")
    assert '"deleted": bool(app_deleted)' in src
