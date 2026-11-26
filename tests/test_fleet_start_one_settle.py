"""A fleet start costs ONE settle window, not one per app or one per wave of workers.

Measured 2026-11-10: `assess run` with 13 apps ran 8 workers, and each worker blocked in its own
45 s `confirm_started` window after its submission, so the call made two waves and took ~98 s
before it returned. The fleet now SUBMITS every app together (up to FLEET_START_WORKERS at once)
and CONFIRMS them all inside one shared window (`AscendAPI.confirm_started_many`).

These run the real `assess run` command and the real settle loop against a fake platform: no
sockets, no processes, a short settle window and a small per-request latency.
"""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
for relative in ('shells/cli', 'runtime', 'control'):
    sys.path.insert(0, str(ROOT / relative))
import ascend
import api

APPS = tuple(f'aapp_fleet{i:02d}' for i in range(13))
SETTLE = 1.0          # seconds: the window, shortened from 45
EVERY = 0.05          # seconds between settle reads
LATENCY = 0.05        # seconds per platform request


class FakePlatform:
    """The calls a fleet start makes, each with LATENCY, counting what was sent and how many
    submissions were in flight at once."""

    def __init__(self, apps, paused=()):
        self.apps, self.paused = list(apps), set(paused)
        self.lock = threading.Lock()
        self.calls, self.in_flight, self.peak = [], 0, 0
        self.resumed_at = {}

    def _call(self, verb, app):
        with self.lock:
            self.calls.append((verb, app))
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
        time.sleep(LATENCY)
        with self.lock:
            self.in_flight -= 1

    def client(self):
        c = object.__new__(api.AscendAPI)
        c.list_apps = lambda: [c.get_app(app) for app in self.apps]
        c.get_app = lambda app: {'id': app, 'name': app, 'api_type': 'api',
                                 'url': 'https://synthetic.example.test/chat',
                                 'request_template': {'_adaptor_src': 'c3Jj'}}
        c.live_assessment = lambda app: None

        def create(app, name):
            self._call('create', app)
            return {'id': 'asmt_' + app, 'status': 'created'}

        def pause(app, aid):
            self._call('pause', app)
            return {'status': 'paused'}

        def resume(app, aid):
            self._call('resume', app)
            self.resumed_at[app] = time.monotonic()
            return {'status': 'running'}

        def get_assessment(app, aid):
            self._call('get', app)
            return {'id': aid, 'status': 'paused' if app in self.paused else 'running'}

        c.create_assessment, c.pause, c.resume, c.get_assessment = create, pause, resume, get_assessment
        return c


@pytest.fixture
def offline(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail('unexpected network or process')
    monkeypatch.setattr(socket.socket, 'connect', denied)
    monkeypatch.setattr(socket, 'create_connection', denied)
    monkeypatch.setattr(subprocess, 'Popen', denied)
    monkeypatch.setattr(api, 'SETTLE_SECONDS', SETTLE)
    monkeypatch.setattr(api, 'SETTLE_EVERY', EVERY)
    monkeypatch.setattr(ascend, '_scope_run_controls', lambda *a, **kw: None)
    monkeypatch.setattr(ascend, '_bind_assessment', lambda *a: None)


def _start(monkeypatch, platform, apps=APPS):
    client = platform.client()
    monkeypatch.setattr(ascend, '_client', lambda args: client)
    argv = ['--json', 'assess', 'run', '--name', 'fleet', '--no-wait',
            *[part for app in apps for part in ('--app', app)]]
    out, err, code = io.StringIO(), io.StringIO(), 0
    t0 = time.monotonic()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            ascend.main(argv)
        except SystemExit as exc:
            code = exc.code
    return time.monotonic() - t0, code, out.getvalue()


def test_thirteen_apps_start_in_about_one_settle_window(offline, monkeypatch):
    platform = FakePlatform(APPS)
    elapsed, code, stdout = _start(monkeypatch, platform)
    rows = json.loads(stdout)
    assert code == 0
    assert [row['app_id'] for row in rows] == list(APPS), 'one row per app, in the order given'
    assert all(row['started'] is True and row['status'] == 'running' for row in rows)
    # One window plus submission: three requests of LATENCY each, all apps at once.
    assert elapsed < SETTLE + 0.6, f'{elapsed:.2f}s for 13 apps: more than one settle window'
    # Every run was submitted together, and nothing was sent twice.
    assert platform.peak >= len(APPS), f'only {platform.peak} submissions were ever in flight together'
    for app in APPS:
        assert [v for v, a in platform.calls if a == app and v != 'get'] == ['create', 'pause', 'resume']
    # The shared window still watched every run for at least the whole window after its resume.
    assert max(platform.resumed_at.values()) - min(platform.resumed_at.values()) < SETTLE / 2


def test_more_apps_than_workers_still_cost_one_window(offline, monkeypatch):
    """Apps beyond FLEET_START_WORKERS wait for a submission slot, never for another window."""
    apps = tuple(f'aapp_wide{i:02d}' for i in range(ascend.FLEET_START_WORKERS + 8))
    platform = FakePlatform(apps)
    elapsed, code, stdout = _start(monkeypatch, platform, apps)
    rows = json.loads(stdout)
    assert code == 0 and len(rows) == len(apps) and all(row['started'] is True for row in rows)
    assert platform.peak <= ascend.FLEET_START_WORKERS + api.FLEET_CONFIRM_WORKERS
    assert elapsed < SETTLE + 0.9, f'{elapsed:.2f}s for {len(apps)} apps: more than one settle window'


def test_a_run_the_platform_paused_is_still_reported_not_started(offline, monkeypatch):
    """The shared window keeps the single-app verdict: paused at the end is NOT STARTED."""
    platform = FakePlatform(APPS, paused={APPS[3]})
    elapsed, code, stdout = _start(monkeypatch, platform)
    rows = {row['app_id']: row for row in json.loads(stdout)}
    assert code == 1
    assert rows[APPS[3]]['started'] is False and rows[APPS[3]]['status'] == 'paused'
    assert 'no start/pause cause was supplied' in rows[APPS[3]]['diagnosis']
    assert all(rows[a]['started'] is True for a in APPS if a != APPS[3])
    assert elapsed < SETTLE + 0.6


def test_confirm_many_shares_one_deadline_and_isolates_a_failed_read(monkeypatch):
    c = object.__new__(api.AscendAPI)
    windows, lock = {}, threading.Lock()

    def confirm(app, aid, *, settle=None, every=None):
        with lock:
            windows[app] = settle
        if app == 'aapp_bad':
            raise RuntimeError('synthetic settle failure')
        time.sleep(settle)
        return {'status': 'running', 'started': True, 'auto_paused': False}

    c.confirm_started = confirm
    c.get_assessment = lambda app, aid: (_ for _ in ()).throw(RuntimeError('unreadable'))
    pairs = [(f'aapp_{i}', f'asmt_{i}') for i in range(10)] + [('aapp_bad', 'asmt_bad')]
    t0 = time.monotonic()
    out = c.confirm_started_many(pairs, settle=0.5, every=0.01, workers=4)
    elapsed = time.monotonic() - t0
    assert [o.get('started') for o in out[:10]] == [True] * 10
    assert out[10]['started'] is None and out[10]['unconfirmed'] is True
    assert 'synthetic settle failure' in out[10]['error']
    # Ten runs on four workers: the later ones join the SAME deadline with what is left of it.
    assert elapsed < 0.5 + 0.4, f'{elapsed:.2f}s: the window was not shared'
    assert all(w <= 0.5 for w in windows.values())
    assert min(windows.values()) < 0.1, 'a run that joined late was handed a fresh full window'


def test_confirm_many_recovers_a_failed_read_from_the_runs_real_state():
    c = object.__new__(api.AscendAPI)
    c.confirm_started = lambda app, aid, **kw: (_ for _ in ()).throw(RuntimeError('synthetic'))
    c.get_assessment = lambda app, aid: {'id': aid, 'status': 'paused'}
    out = c.confirm_started_many([('aapp_1', 'asmt_1')], settle=0, every=0)
    assert out[0]['started'] is False and out[0]['recovered'] is True
    assert out[0]['recovery_needs_action'] is True and out[0]['assessment_id'] == 'asmt_1'


def test_single_app_run_still_confirms_by_default():
    """`confirm=False` is opt-in: the single-app path keeps its own settle window."""
    platform = FakePlatform(['aapp_one'])
    c = platform.client()
    out = c.run('aapp_one', 'r', wait=False, settle=0)
    assert out['started'] is True and 'awaiting_confirmation' not in out
    sub = c.run('aapp_one', 'r', wait=False, confirm=False)
    assert sub['awaiting_confirmation'] is True and sub['started'] is None
    assert sub['status'] == 'submitted' and sub['assessment_id'] == 'asmt_aapp_one'


def _start_argv(monkeypatch, platform, argv):
    client = platform.client()
    monkeypatch.setattr(ascend, '_client', lambda args: client)
    out, err, code = io.StringIO(), io.StringIO(), 0
    t0 = time.monotonic()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            ascend.main(argv)
        except SystemExit as exc:
            code = exc.code
    return time.monotonic() - t0, code, out.getvalue()


def test_submit_only_returns_at_submission_with_every_id_and_no_settle(offline, monkeypatch):
    """--submit-only (with --no-wait): the 45 s window is the caller's. MEASURED 2026-11-11: a 13-app
    start took 68.7 s, 45 s of it the window; a host that follows each run reads the same verdict there."""
    platform = FakePlatform(APPS, paused={APPS[3]})
    argv = ['--json', 'assess', 'run', '--name', 'fleet', '--no-wait', '--submit-only',
            *[part for app in APPS for part in ('--app', app)]]
    elapsed, code, stdout = _start_argv(monkeypatch, platform, argv)
    rows = json.loads(stdout)
    assert code == 0, 'a fleet whose every run was submitted is not a failure'
    assert [row['app_id'] for row in rows] == list(APPS)
    assert all(row['assessment_id'] == 'asmt_' + row['app_id'] for row in rows)
    assert all(row['status'] == 'submitted' and row['started'] is None and row['submitted'] is True
               and row['settle'] == 'deferred' for row in rows), rows[0]
    assert not any('diagnosis' in row or 'unconfirmed' in row for row in rows)
    assert not [v for v, _ in platform.calls if v == 'get'], 'no settle read: the window was skipped'
    assert elapsed < SETTLE / 2, f'{elapsed:.2f}s: submission waited on a window'
    for app in APPS:
        assert [v for v, a in platform.calls if a == app] == ['create', 'pause', 'resume']


def test_submit_only_without_no_wait_keeps_the_waiting_form(offline, monkeypatch):
    """--submit-only is a no-wait option: the waiting form still confirms and follows each run."""
    platform = FakePlatform(APPS[:2])
    monkeypatch.setattr(ascend, '_wait_for_fleet', lambda args, c, following: {
        r['app_id']: {'status': 'complete', 'id': r['assessment_id']} for r in following})
    argv = ['--json', 'assess', 'run', '--name', 'fleet', '--submit-only',
            *[part for app in APPS[:2] for part in ('--app', app)]]
    _, code, stdout = _start_argv(monkeypatch, platform, argv)
    doc = json.loads(stdout)
    assert all(row['started'] is True and 'submitted' not in row for row in doc['started'])
    assert [v for v, _ in platform.calls if v == 'get'], 'the window ran'


def test_submit_only_still_fails_a_fleet_with_a_run_that_was_never_created(offline, monkeypatch):
    platform = FakePlatform(APPS[:3])
    client = platform.client()
    real_create = client.create_assessment

    def create(app, name):
        if app == APPS[1]:
            raise api.AscendAPIError('synthetic 500 on create')
        return real_create(app, name)
    client.create_assessment = create
    monkeypatch.setattr(ascend, '_client', lambda args: client)
    argv = ['--json', 'assess', 'run', '--name', 'fleet', '--no-wait', '--submit-only',
            *[part for app in APPS[:3] for part in ('--app', app)]]
    out, code = io.StringIO(), 0
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        try:
            ascend.main(argv)
        except SystemExit as exc:
            code = exc.code
    rows = {row['app']: row for row in json.loads(out.getvalue())}
    assert code == 1 and 'error' in rows[APPS[1]] and not rows[APPS[1]].get('assessment_id')
    assert rows[APPS[0]]['submitted'] is True and rows[APPS[2]]['submitted'] is True


def test_new_reaches_every_app_of_a_fleet(offline, monkeypatch):
    """`--new` on a fleet makes a new run on each app, as on the single form; without it an unfinished run is
    picked up. Measured 2026-11-25: a 4-prompt fleet start without a way to say `--new` set someone else's
    28-control, 4,714-probe run going again."""
    open_runs = {APPS[1]: 'asmt_open1', APPS[4]: 'asmt_open4'}
    for new in (True, False):
        platform = FakePlatform(APPS)
        client = platform.client()
        client.live_assessment = lambda app: ({'id': open_runs[app], 'status': 'paused'} if app in open_runs else None)
        monkeypatch.setattr(ascend, '_client', lambda args, c=client: c)
        argv = ['--json', 'assess', 'run', '--name', 'fleet', '--no-wait',
                *[part for app in APPS for part in ('--app', app)], *(['--new'] if new else [])]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                ascend.main(argv)
            except SystemExit:
                pass
        rows = {row['app_id']: row for row in json.loads(out.getvalue())}
        for app, aid in open_runs.items():
            created = [v for v, a in platform.calls if a == app and v == 'create']
            if new:
                assert created == ['create'] and rows[app]['assessment_id'] == 'asmt_' + app
                assert rows[app]['reused_assessment'] is False
            else:
                assert created == [] and rows[app]['assessment_id'] == aid and rows[app]['reused_assessment'] is True
