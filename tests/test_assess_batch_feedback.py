"""Batch start facts through the real API orchestration, CLI and MCP envelopes."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
for relative in ('shells/cli', 'runtime', 'control'):
    sys.path.insert(0, str(ROOT / relative))
import ascend
import api
from test_mcp_shim_repeat import fleet_tool, shim

APPS = ('aapp_feedbackOne', 'aapp_feedbackTwo')


@pytest.fixture
def native(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail('unexpected network or process')
    monkeypatch.setattr(socket.socket, 'connect', denied)
    monkeypatch.setattr(socket, 'create_connection', denied)
    monkeypatch.setattr(subprocess, 'Popen', denied)
    client = object.__new__(api.AscendAPI)
    client.states = {app: {'status': 'running', 'started': True, 'auto_paused': False} for app in APPS}
    client.calls, client.reused = [], {}
    client.list_apps = lambda: [client.get_app(app) for app in APPS]
    client.get_app = lambda app: {'id': app, 'name': app, 'api_type': 'api',
        'url': 'https://synthetic.example.test/chat', 'request_template': {'_adaptor_src': 'c3Jj'}}
    client.live_assessment = lambda app: client.reused.get(app)
    def create(app, name):
        client.calls.append(('create', app))
        return {'id': 'asmt_' + app, 'status': 'created'}
    client.create_assessment = create
    def transition(verb, app, aid):
        client.calls.append((verb, app))
        return {'status': 'paused' if verb == 'pause' else 'running'}
    client.pause = lambda app, aid: transition('pause', app, aid)
    client.resume = lambda app, aid: transition('resume', app, aid)
    client.confirm_started = lambda app, aid, **kwargs: deepcopy(client.states[app])
    monkeypatch.setattr(ascend, '_client', lambda args: client)
    monkeypatch.setattr(ascend, '_scope_run_controls', lambda *a, **kw: None)
    monkeypatch.setattr(ascend, '_bind_assessment', lambda *a: None)
    def invoke(extra=(), apps=APPS, machine=True):
        argv = [*(['--json'] if machine else []), 'assess', 'run', '--name', 'synthetic',
                *[part for app in apps for part in ('--app', app)], *extra]
        out, err, code = io.StringIO(), io.StringIO(), 0
        with redirect_stdout(out), redirect_stderr(err):
            try:
                ascend.main(argv)
            except SystemExit as exc:
                code = exc.code
        return SimpleNamespace(returncode=code, stdout=out.getvalue(), stderr=err.getvalue())
    return client, invoke


@pytest.mark.parametrize('started,status,code', [(True, 'running', 0), (False, 'paused', 1),
                                               (None, 'unknown', 1), (1, 'running', 1)])
def test_no_wait_preserves_start_facts_without_promoting_ids(native, started, status, code):
    client, invoke = native
    for state in client.states.values():
        state.update(status=status, started=started, auto_paused=started is False,
                     unconfirmed=started is None)
    result = invoke(['--no-wait'])
    rows = json.loads(result.stdout)
    assert result.returncode == code
    assert [row['app_id'] for row in rows] == list(APPS)
    assert all(row['started'] == started and type(row['started']) is type(started)
               and row['auto_paused'] is (started is False) for row in rows)
    assert all(row['bridge']['ensured'] is False and not row['bridge'].get('error') for row in rows)
    assert all(row.get('diagnosis') for row in rows) is (started is False)
    assert sorted(client.calls) == sorted((verb, app) for app in APPS for verb in ('create', 'pause', 'resume'))


def test_unconfirmed_retains_error_and_safe_recovery_facts(native):
    client, invoke = native
    for state in client.states.values():
        state.update(status='unknown', started=None, unconfirmed=True, error='synthetic unreadable state',
                     recovery_needs_action=True, recovery_note='synthetic recovery', resumes=2,
                     private_payload='not a start-feedback field')
    rows = json.loads(invoke(['--no-wait']).stdout)
    for row in rows:
        assert row['started'] is None and row['unconfirmed'] is True
        assert row['error'] == 'synthetic unreadable state'
        assert row['recovery_needs_action'] is True and row['resumes'] == 2
        assert row['recovery_note'] == row['note'] == 'synthetic recovery'
        assert 'private_payload' not in row and 'diagnosis' not in row


def test_missing_diagnosis_never_replays_target_or_infers_pause_cause(native, monkeypatch):
    client, invoke = native
    for state in client.states.values():
        state.update(status='paused', started=False)
    monkeypatch.setattr(ascend, '_diagnose_not_started', lambda *a: pytest.fail('replayed target for diagnosis'))
    result = invoke(['--no-wait'])
    rows = json.loads(result.stdout)
    assert result.returncode == 1
    assert all(row['assessment_id'] == 'asmt_' + row['app_id'] and row['started'] is False for row in rows)
    assert all('no start/pause cause was supplied' in row['diagnosis'] for row in rows)
    assert all('request_outcome' not in row and 'mutation_attempted' not in row for row in rows)


@pytest.mark.parametrize('diagnosis', ['synthetic observed native detail',
                                     {'reason': 'synthetic_observed', 'detail': 'synthetic known fact'}])
def test_observed_native_diagnosis_is_retained_without_another_probe(native, monkeypatch, diagnosis):
    client, invoke = native
    for state in client.states.values():
        state.update(status='paused', started=False, diagnosis=diagnosis)
    monkeypatch.setattr(ascend, '_diagnose_not_started', lambda *a: pytest.fail('replayed target for diagnosis'))
    result = invoke(['--no-wait'])
    assert result.returncode == 1
    assert all(row['diagnosis'] == diagnosis and row['assessment_id'] == 'asmt_' + row['app_id']
               for row in json.loads(result.stdout))


def test_reused_assessment_and_recovered_create_are_not_replayed(native):
    client, invoke = native
    client.reused[APPS[0]] = {'id': 'asmt_existing', 'status': 'running'}
    original = client.create_assessment
    client.create_assessment = lambda app, name: {**original(app, name), 'recovered': True,
                                                 'recovery_note': 'synthetic lost response'}
    rows = json.loads(invoke(['--no-wait']).stdout)
    assert rows[0]['assessment_id'] == 'asmt_existing' and rows[0]['reused_assessment'] is True
    assert rows[1]['recovered'] is True and rows[1]['recovery_needs_action'] is False
    assert client.calls.count(('create', APPS[1])) == 1 and ('create', APPS[0]) not in client.calls


def test_wait_follows_unconfirmed_existing_id_without_another_start(native, monkeypatch):
    client, invoke = native
    client.states[APPS[0]].update(status='unknown', started=None, unconfirmed=True)
    followed = []
    def follow(args, c, rows):
        followed.extend(deepcopy(rows))
        return {row['app_id']: {'status': 'complete', 'severity': 'low', 'total': 1,
                               'category_summary': [{'failed': 0}]} for row in rows}
    monkeypatch.setattr(ascend, '_wait_for_fleet', follow)
    result = invoke()
    assert result.returncode == 0 and len(followed) == 2
    assert followed[0]['started'] is None and followed[0]['unconfirmed'] is True
    assert all(row['status'] == 'complete' for row in json.loads(result.stdout)['results'])
    assert all(client.calls.count(('create', app)) == 1 for app in APPS)


def test_explicit_failed_starts_are_not_followed_or_restarted(native, monkeypatch):
    client, invoke = native
    for state in client.states.values():
        state.update(status='paused', started=False, auto_paused=True)
    monkeypatch.setattr(ascend, '_wait_for_fleet', lambda *a: pytest.fail('followed a failed start'))
    result = invoke()
    assert result.returncode == 1
    assert all(row['started'] is False for row in json.loads(result.stdout))
    assert all(client.calls.count(('create', app)) == 1 for app in APPS)


def test_wait_keeps_failed_receipt_while_following_only_other_existing_run(native, monkeypatch):
    client, invoke = native
    client.states[APPS[0]].update(status='paused', started=False, auto_paused=False)
    def follow(args, c, rows):
        assert [row['app_id'] for row in rows] == [APPS[1]]
        return {APPS[1]: {'status': 'complete', 'total': 1, 'category_summary': [{'failed': 0}]}}
    monkeypatch.setattr(ascend, '_wait_for_fleet', follow)
    result = invoke()
    out = json.loads(result.stdout)
    assert result.returncode == 1
    assert out['started'][0]['started'] is False and out['started'][0]['auto_paused'] is False
    assert out['started'][0]['diagnosis']
    assert [row['status'] for row in out['results']] == ['paused', 'complete']
    assert all(client.calls.count(('create', app)) == 1 for app in APPS)


def test_post_create_read_failure_retains_recovered_paused_ids_without_replay(native):
    client, invoke = native
    def unreadable(*args, **kwargs):
        raise RuntimeError('synthetic settle interruption')
    client.confirm_started = unreadable
    client.get_assessment = lambda app, aid: {'id': aid, 'status': 'paused'}
    result = invoke(['--no-wait'])
    rows = json.loads(result.stdout)
    assert result.returncode == 1
    assert all(row['started'] is False and row['recovered'] is True
               and row['recovery_needs_action'] is True for row in rows)
    assert all(row['assessment_id'] == 'asmt_' + row['app_id'] for row in rows)
    assert all(client.calls.count(('create', app)) == 1 for app in APPS)


@pytest.mark.parametrize('bridge_issue', ['skip', 'error'])
def test_native_bridge_skip_semantics_do_not_hide_real_bridge_failures(native, monkeypatch, bridge_issue):
    client, invoke = native
    monkeypatch.setattr(ascend, '_ensure_bridge', lambda c, app, **kwargs:
                        {'app_id': app, 'ensured': False, bridge_issue: 'synthetic unavailable bridge'})
    result = invoke(['--no-wait'])
    assert result.returncode == 1
    assert all(row['started'] is True and row['bridge'][bridge_issue]
               for row in json.loads(result.stdout))


@pytest.mark.parametrize('state', [False, None])
def test_human_summary_counts_only_confirmed_starts(native, state):
    client, invoke = native
    client.states[APPS[1]].update(status='paused' if state is False else 'unknown', started=state)
    result = invoke(['--no-wait'], machine=False)
    assert result.returncode == 1 and '1/2 assessment(s) confirmed started' in result.stdout
    assert ('NOT STARTED' if state is False else 'UNCONFIRMED') in result.stdout


@pytest.mark.parametrize('started', [True, False, None])
def test_mcp_keeps_per_app_start_facts_on_success_and_nonzero(native, monkeypatch, fleet_tool, started):
    client, invoke = native
    for state in client.states.values():
        state.update(status='running' if started is True else 'paused' if started is False else 'unknown',
                     started=started, auto_paused=started is False, unconfirmed=started is None)
    fleet_tool['params']['no_wait'] = {'kind': 'flag', 'flag': '--no-wait'}
    def process(argv, **kwargs):
        assert argv.count('--app') == 2 and '--no-wait' in argv
        return invoke(['--no-wait'])
    monkeypatch.setattr(shim.subprocess, 'run', process)
    out = shim.run_tool('t_repeat', {'app': list(APPS), 'name': 'synthetic', 'no_wait': True})
    assert out['ok'] is (started is True)
    rows = out['result'] if started is True else json.loads(out['stdout'])
    assert all(row['started'] is started and row['app_id'] in APPS for row in rows)


def test_batch_scopes_each_app_before_its_one_start(native, monkeypatch):
    client, invoke = native
    scoped = set()
    monkeypatch.setattr(ascend, '_validated_control_ids', lambda *a, **kw: ['synthetic-control'])
    def scope(c, app, ids, args):
        assert ids == ['synthetic-control']
        scoped.add(app)
    monkeypatch.setattr(ascend, '_scope_run_controls', scope)
    create = client.create_assessment
    def checked(app, name):
        assert app in scoped
        return create(app, name)
    client.create_assessment = checked
    assert invoke(['--no-wait', '--controls', 'synthetic-control']).returncode == 0
    assert scoped == set(APPS)
