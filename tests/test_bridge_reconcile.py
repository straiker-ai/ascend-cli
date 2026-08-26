"""
test_bridge_reconcile — the pure decision at the heart of the self-reconciling bridge, and the
CLI-facing type label.

The overriding property here is FALSE-PASS SAFETY: the bridge must NEVER self-stop while it cannot
verify that its work is done. An unanswered probe scores a clean pass, so the safe direction is
always "keep serving". These tests pin that, plus the ordinary lifecycle (stop on terminal, keep
while running, idle-timeout only when paused).
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ("control", "runtime", "shells/cli"):
    sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402

D = ascend._reconcile_decision
IDLE = 1800
# now well past the startup grace unless a test says otherwise
NOW = 100_000.0


def _dec(assessments, *, now=NOW, started_at=0.0, last_probe_ts=0.0, control_ok=True,
         idle_timeout_s=IDLE):
    return D(assessments, now=now, started_at=started_at, last_probe_ts=last_probe_ts,
             idle_timeout_s=idle_timeout_s, control_ok=control_ok)


# ---- false-pass safety: never self-kill when state is unknown ---------------------------------
def test_cannot_read_platform_always_serves():
    # even though every assessment is terminal, an unverifiable read must keep the bridge alive
    assert _dec([{"status": "completed"}], control_ok=False) == "serve"


def test_startup_grace_serves_even_with_no_assessments():
    # ensure-before-create: the run does not exist yet when the bridge first polls
    assert _dec([], now=50.0, started_at=0.0) == "serve"


# ---- ordinary lifecycle -----------------------------------------------------------------------
def test_all_terminal_stops():
    assert _dec([{"status": "completed"}, {"status": "failed"}]) == "stop-terminal"


def test_no_assessments_after_grace_stops():
    assert _dec([]) == "stop-terminal"


def test_running_serves():
    assert _dec([{"status": "running"}]) == "serve"


def test_queued_and_in_progress_serve():
    assert _dec([{"status": "queued"}]) == "serve"
    assert _dec([{"status": "in_progress"}]) == "serve"


# ---- default: stop only on terminal, never idle-kill (bridge rides through stalls) ------------
def test_idle_kill_disabled_by_default_serves():
    # idle_timeout_s=0 is the shipped default: even a long-idle paused run is NOT reaped
    assert _dec([{"status": "paused"}], last_probe_ts=NOW - 999999, idle_timeout_s=0) == "serve"


def test_created_stalled_never_reaped():
    # a run stuck in 'created' (a platform stall) must NEVER kill the bridge, even opted in
    assert _dec([{"status": "created"}], last_probe_ts=0.0, idle_timeout_s=IDLE) == "serve"
    assert _dec([{"status": "created"}], last_probe_ts=NOW - 999999, idle_timeout_s=IDLE) == "serve"


def test_paused_never_probed_serves():
    # opted in, but no probe ever landed -> the run never really started -> keep serving
    assert _dec([{"status": "paused"}], last_probe_ts=0.0, idle_timeout_s=IDLE) == "serve"


# ---- opt-in idle cleanup: only a genuinely paused, already-probed, then-quiet run --------------
def test_paused_probed_and_idle_stops_when_opted_in():
    assert _dec([{"status": "paused"}], last_probe_ts=NOW - 2000, idle_timeout_s=IDLE) == "stop-idle"


def test_paused_but_recent_probe_serves():
    # opted in; a probe answered 1000s ago, timeout 1800 -> still within window
    assert _dec([{"status": "paused"}], last_probe_ts=NOW - 1000, idle_timeout_s=IDLE) == "serve"


# ---- per-app counting: a shared bridge stays up while ANY assessment is active -----------------
def test_mixed_terminal_and_running_serves():
    assert _dec([{"status": "completed"}, {"status": "running"}]) == "serve"


def test_mixed_paused_and_running_serves():
    # even if one is paused-and-idle, a concurrent running one keeps the shared bridge up
    assert _dec([{"status": "paused"}, {"status": "running"}], last_probe_ts=0.0) == "serve"


# ---- the CLI-facing type label (wire 'thin' -> shown 'bridge') ---------------------------------
def test_type_label_maps_thin_to_bridge():
    assert ascend._type_label("thin") == "bridge"
    assert ascend._type_label("THIN") == "bridge"


def test_type_label_passes_through_native_types():
    assert ascend._type_label("api") == "api"
    assert ascend._type_label("gcp") == "gcp"
    assert ascend._type_label("bedrock") == "bedrock"


def test_type_label_is_null_safe():
    assert ascend._type_label(None) == "?"
    assert ascend._type_label("") == "?"
