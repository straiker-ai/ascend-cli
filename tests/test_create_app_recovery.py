"""Create response provenance at the actual HTTP producer; no network or state."""
import json
import socket
import subprocess
import sys

import pytest
import requests
from urllib3.exceptions import ProtocolError

import api
from conftest import FakeResponse, install_fake_requests
from _onboard_harness import ascend as cli


SPEC = {'name': 'synthetic-create', 'api_type': 'api', 'url': 'https://fixture.example.test/chat'}
ROW = {'id': 'aapp_synthetic', **SPEC}
TRANSPORT = (requests.ConnectionError, requests.Timeout,
             requests.exceptions.ChunkedEncodingError, requests.exceptions.ContentDecodingError)


@pytest.fixture(autouse=True)
def no_external_io(monkeypatch):
    def denied(*a, **kw):
        pytest.fail('unexpected network or process')
    monkeypatch.setattr(socket.socket, 'connect', denied)
    monkeypatch.setattr(socket, 'getaddrinfo', denied)
    monkeypatch.setattr(subprocess, 'Popen', denied)


def client():
    return api.AscendAPI(token='synthetic-direct-bearer', cache=False)


@pytest.mark.parametrize('status', [200, 201])
def test_complete_create_response_is_not_recovered(monkeypatch, status):
    def handler(method, url, kwargs):
        assert method == 'POST' and url.endswith('/ascend/applications')
        assert kwargs['json'] == SPEC
        return FakeResponse(status, ROW)
    calls = install_fake_requests(monkeypatch, handler)
    assert client().create_app(SPEC) == ROW
    assert len(calls.calls) == 1


@pytest.mark.parametrize('status', [400, 401, 403, 409, 422, 500, 503])
def test_explicit_http_failure_is_not_relabelled_as_recovered(monkeypatch, status):
    def handler(method, url, kwargs):
        return FakeResponse(status, {'error': 'synthetic refusal'}) if method == 'POST' else FakeResponse(200, [ROW])
    calls = install_fake_requests(monkeypatch, handler)
    with pytest.raises(api.AscendAPIError, match=str(status)):
        client().create_app(SPEC)
    assert [c['method'] for c in calls.calls] == ['POST']


def test_local_exception_is_not_relabelled_as_recovered(monkeypatch):
    def handler(method, url, kwargs):
        if method == 'POST':
            raise RuntimeError('synthetic local exception')
        return FakeResponse(200, [ROW])
    calls = install_fake_requests(monkeypatch, handler)
    with pytest.raises(RuntimeError, match='synthetic local exception'):
        client().create_app(SPEC)
    assert [c['method'] for c in calls.calls] == ['POST']


@pytest.mark.parametrize('error_type', TRANSPORT)
def test_transport_recovery_never_replays_or_claims_original_outcome(monkeypatch, error_type):
    def handler(method, url, kwargs):
        if method == 'POST':
            raise error_type('synthetic response loss')
        return FakeResponse(200, [ROW])
    calls = install_fake_requests(monkeypatch, handler)
    result = client().create_app(SPEC)
    assert result['id'] == ROW['id'] and result['recovered'] is True
    assert 'unconfirmed' in result['recovery_note']
    assert [c['method'] for c in calls.calls] == ['POST', 'GET']


@pytest.mark.parametrize('lookup', ['absent', 'different-name', 'fails'])
def test_unconfirmed_lookup_preserves_original_transport_exception(monkeypatch, lookup):
    original = requests.ConnectionError('synthetic response loss')
    def handler(method, url, kwargs):
        if method == 'POST':
            raise original
        if lookup == 'fails':
            raise requests.Timeout('synthetic lookup timeout')
        return FakeResponse(200, [] if lookup == 'absent' else [{**ROW, 'name': 'other'}])
    calls = install_fake_requests(monkeypatch, handler)
    with pytest.raises(requests.ConnectionError) as exc:
        client().create_app(SPEC)
    assert exc.value is original
    assert [c['method'] for c in calls.calls] == ['POST', 'GET']


@pytest.mark.parametrize('status', [200, 201])
def test_app_create_command_preserves_complete_http_receipt(monkeypatch, capsys, status):
    def handler(method, url, kwargs):
        if url.endswith('/ascend/controls'):
            return FakeResponse(200, {'controls': [{'id': 'sys_prompt_leak'}]})
        assert method == 'POST' and url.endswith('/ascend/applications')
        return FakeResponse(status, ROW)
    calls = install_fake_requests(monkeypatch, handler)
    monkeypatch.setattr(cli, '_client', lambda args: client())
    argv = ['app', 'create', '--type', 'api', '--name', SPEC['name'], '--url', SPEC['url'],
            '--target-api-key', 'synthetic-key', '--controls', 'sys_prompt_leak', '--json']
    monkeypatch.setattr(sys, 'argv', ['ascend', *argv])
    args = cli.build_parser().parse_args(argv)
    cli._reapply_globals(args, argv)
    args.func(args)
    result = json.loads(capsys.readouterr().out)
    assert result['id'] == ROW['id'] and 'recovered' not in result
    assert sum(c['method'] == 'POST' for c in calls.calls) == 1
    assert not any(c['method'] == 'GET' and c['url'].endswith('/ascend/applications') for c in calls.calls)


@pytest.mark.parametrize('status', [200, 201])
def test_real_requests_body_interruption_keeps_create_unconfirmed(status):
    calls = []
    class InterruptedBody:
        def stream(self, *args, **kwargs):
            yield json.dumps(ROW).encode()
            raise ProtocolError('synthetic incomplete response framing')
        def close(self):
            pass
    class SyntheticAdapter(requests.adapters.BaseAdapter):
        def send(self, request, **kwargs):
            calls.append(request.method)
            response = requests.Response()
            response.url, response.request = request.url, request
            response.status_code = status if request.method == 'POST' else 200
            if request.method == 'POST':
                response.raw = InterruptedBody()
            else:
                response._content = json.dumps([ROW]).encode()
            return response
        def close(self):
            pass
    c = client()
    c._s.mount('https://', SyntheticAdapter())
    result = c.create_app(SPEC)
    assert result['id'] == ROW['id'] and result['recovered'] is True
    assert 'ChunkedEncodingError' in result['recovery_note']
    assert 'unconfirmed' in result['recovery_note']
    assert calls == ['POST', 'GET']
