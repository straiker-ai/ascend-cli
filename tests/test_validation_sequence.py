"""Explicit conversation validation without removing single-turn integrations."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from runtime.discovery import validate as V


REPO = Path(__file__).resolve().parents[1]


def config(tmp_path, source):
    module = tmp_path / 'adapter.py'
    module.write_text(source)
    return {'adapter': 'custom', 'adapter_module': str(module)}


ONE_SHOT = '''calls = 0
def send_prompt(prompt):
    global calls
    calls += 1
    if calls > 1:
        raise RuntimeError('session renewal missing')
    return 'Answer: ' + prompt
'''
STATEFUL = '''calls = 0
def send_prompt(prompt):
    global calls
    calls += 1
    return str(calls) + ': ' + prompt
'''


def test_default_one_shot_is_preserved_but_sequence_requires_continuity(tmp_path):
    cfg = config(tmp_path, ONE_SHOT)
    assert V.validate_config('custom', cfg, 'first')['ok']
    result = V.validate_config('custom', cfg, 'first', followup_prompts=['second', 'third'])
    assert not result['ok'] and 'session renewal missing' in result['error']
    assert result['sequence']['requested'] == 3
    assert result['sequence']['completed'] == 1
    assert len(result['sequence']['turns']) == 2
    assert not result['answer_variation']['checked']


def test_sequence_uses_one_instance_without_extra_carry_or_variation_probe(tmp_path):
    cfg = config(tmp_path, STATEFUL)
    cfg['carry'] = {'request_field': 'conversation'}
    result = V.validate_config('custom', cfg, 'first', followup_prompts=['second', 'third'])
    assert result['ok'] and result['response'] == '3: third'
    assert [t['response'] for t in result['sequence']['turns']] == ['1: first', '2: second', '3: third']
    assert result['sequence']['same_conversation'] is True
    assert result['sequence']['completed'] == 3
    assert result['answer_variation']['checked'] and result['answer_variation']['varies']


def test_sequence_expectation_applies_to_each_turn_and_stops_on_mismatch(tmp_path):
    cfg = config(tmp_path, STATEFUL)
    result = V.validate_config('custom', cfg, 'keep first', 'keep', followup_prompts=['different', 'keep third'])
    assert not result['ok'] and not result['matched'] and result['error'] is None
    assert result['response'] == '2: different'
    assert result['sequence']['completed'] == 2 and len(result['sequence']['turns']) == 2


@pytest.mark.parametrize('followup', [[], ['same'], [1], [''], ['x' * 8193], ['x'] * 8, 'second'])
def test_invalid_sequence_rejected_before_auth_or_runtime(monkeypatch, followup):
    def refuse(*args, **kwargs):
        pytest.fail('invalid input must not authenticate or execute')
    monkeypatch.setattr(V, '_merge_auth', refuse)
    result = V.validate_config('custom', {}, 'same', followup_prompts=followup)
    assert not result['ok'] and 'sequence' in result['error']


def test_sequence_has_one_total_deadline_including_auth(monkeypatch):
    import dispatch
    clock, sends = [0.0], []
    monkeypatch.setattr(V.time, 'monotonic', lambda: clock[0])
    def auth(cfg, **kwargs):
        clock[0] += .2
        return cfg
    class Router:
        def send(self, adapter, cfg, name, prompt, conv, timeout):
            sends.append((prompt, timeout))
            clock[0] += .3
            return {'success': True, 'response': prompt}
        def reset(self):
            pass
    monkeypatch.setattr(V, '_merge_auth', auth)
    monkeypatch.setattr(dispatch, 'ConversationRouter', Router)
    result = V.validate_config('custom', {}, 'first', followup_prompts=['second', 'third'], timeout_s=.7)
    assert not result['ok'] and 'deadline' in result['error']
    assert [x[0] for x in sends] == ['first', 'second']
    assert sends[0][1] == pytest.approx(.5) and sends[1][1] == pytest.approx(.2)
    assert result['sequence']['completed'] == 2


@pytest.mark.parametrize('timeout', [0, -1, float('nan'), float('inf'), 301, True])
def test_sequence_rejects_unbounded_timeout_before_auth(monkeypatch, timeout):
    monkeypatch.setattr(V, '_merge_auth', lambda *a, **kw: pytest.fail('must reject before auth'))
    result = V.validate_config('custom', {}, 'first', followup_prompts=['second'], timeout_s=timeout)
    assert not result['ok'] and 'timeout' in result['error']


def test_failed_auth_never_sends_sequence(monkeypatch):
    import dispatch
    monkeypatch.setattr(V, '_merge_auth', lambda *a, **kw: {'_auth_error': 'denied'})
    monkeypatch.setattr(dispatch, 'ConversationRouter', lambda: pytest.fail('must not send'))
    result = V.validate_config('custom', {}, 'first', followup_prompts=['second'])
    assert not result['ok'] and result['sequence']['completed'] == 0
    assert result['error'] == 'auth failed: denied'


def cli_run(tmp_path, source, prompts, extra=()):
    cfg = config(tmp_path, source)
    config_file = tmp_path / 'config.json'; config_file.write_text(json.dumps(cfg))
    prompts_file = tmp_path / 'prompts.json'; prompts_file.write_text(json.dumps(prompts))
    env = {'PATH': os.defpath, 'HOME': str(tmp_path), 'ASCEND_HOME': str(tmp_path / 'state'),
           'NO_COLOR': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    return subprocess.run([sys.executable, str(REPO / 'shells/cli/ascend.py'), 'adapter', 'validate',
        '--file', str(config_file), '--prompts-file', str(prompts_file), '--timeout', '3', '--json', *extra],
        capture_output=True, text=True, env=env, cwd=tmp_path, timeout=12)


@pytest.mark.parametrize('source,expected_exit', [(ONE_SHOT, 1), (STATEFUL, 0),
    ("def send_prompt(prompt):\n    return 'same answer'\n", 1)])
def test_actual_cli_sequence_reports_failure_success_and_constant(tmp_path, source, expected_exit):
    run = cli_run(tmp_path, source, ['first', 'second', 'third'])
    assert run.returncode == expected_exit, run.stderr
    result = json.loads(run.stdout)
    assert result['sequence']['same_conversation'] is True
    assert result['ok'] is (expected_exit == 0)
    if source == STATEFUL:
        assert result['response'] == '3: third'
    elif source == ONE_SHOT:
        assert result['sequence']['completed'] == 1
        assert not result.get('constant_response')
    else:
        assert result['constant_response']


def test_cli_rejects_conflicting_prompt_sources(tmp_path):
    run = cli_run(tmp_path, STATEFUL, ['first', 'second'], ['--prompt', 'third'])
    assert run.returncode != 0 and 'prompt' in run.stderr.lower() + run.stdout.lower()


@pytest.mark.parametrize('prompts', [[], ['same', 'same'], ['first', 2], {'first': 'second'},
    ['a' * 40000, 'b' * 40000]])
def test_cli_rejects_invalid_sequence_before_target_call(tmp_path, prompts):
    run = cli_run(tmp_path, "def send_prompt(prompt):\n    raise Exception('TARGET CALLED')\n", prompts)
    assert run.returncode == 3 and 'TARGET CALLED' not in run.stdout + run.stderr


def test_cli_sequence_expectation_mismatch_is_findings_not_transport_error(tmp_path):
    run = cli_run(tmp_path, STATEFUL, ['keep first', 'other', 'keep third'], ['--expect', 'keep'])
    assert run.returncode == 2
    result = json.loads(run.stdout)
    assert not result['matched'] and result['error'] is None
    assert result['sequence']['completed'] == 2


def test_cli_empty_answer_is_not_a_successful_sequence(tmp_path):
    run = cli_run(tmp_path, "def send_prompt(prompt):\n    return ''\n", ['first', 'second'])
    assert run.returncode == 1
    assert not json.loads(run.stdout)['ok']
