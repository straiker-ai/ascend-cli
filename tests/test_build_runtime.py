"""
test_build_runtime — the bridge must never lease more un-acked probes than its workers can drain
inside the server's ~90s reclaim window. build_runtime couples max_probes_per_lease to the worker
count, so a serial (stateful, workers=1) target leases one probe at a time instead of a batch of 10
it could never acknowledge in order before the server reclaims and re-issues them.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
import run  # noqa: E402


class FakeCaller:
    def __init__(self, workers):
        self._w = workers

    def handler(self, msg):
        return 200, {}

    def recommended_workers(self):
        return self._w


def _build(monkeypatch, *, recommended, max_workers=None):
    monkeypatch.setattr(run, "TargetCaller", lambda adapter, config_name: FakeCaller(recommended))
    return run.build_runtime("tc-x", "direct_api", "inline", max_workers=max_workers)


def test_stateful_leases_one_at_a_time(monkeypatch):
    c = _build(monkeypatch, recommended=1)
    assert c.max_workers == 1
    assert c.max_probes_per_lease == 1     # never hold a batch one worker can't drain in time


def test_stateless_leases_up_to_worker_count(monkeypatch):
    c = _build(monkeypatch, recommended=10)
    assert c.max_workers == 10
    assert c.max_probes_per_lease == 10


def test_explicit_max_workers_drives_lease_size(monkeypatch):
    c = _build(monkeypatch, recommended=10, max_workers=3)
    assert c.max_workers == 3
    assert c.max_probes_per_lease == 3
