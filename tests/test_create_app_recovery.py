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


@pytest.mark.parametrize('status', [200, 201, 401, 403])
@pytest.mark.parametrize('pat', [False, True])
def test_real_requests_body_interruption_keeps_create_unconfirmed(status, pat):
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
    c = api.AscendAPI(token='s6r_pat_synthetic', cache=False) if pat else client()
    if pat:
        c._jwt, c._jwt_exp = 'synthetic-cached-access', float('inf')
    c._s.mount('https://', SyntheticAdapter())
    if status in (200, 201):
        result = c.create_app(SPEC)
        assert result['id'] == ROW['id'] and result['recovered'] is True
        assert 'ChunkedEncodingError' in result['recovery_note']
        assert 'unconfirmed' in result['recovery_note']
        assert calls == ['POST', 'GET']
    else:
        with pytest.raises(requests.exceptions.ChunkedEncodingError):
            c.create_app(SPEC)
        assert calls == ['POST']


@pytest.mark.parametrize('refresh', [False, True])
def test_auth_timeout_cannot_enter_app_transport_recovery(refresh):
    calls = []
    original = requests.Timeout('synthetic authentication timeout')
    class SyntheticAdapter(requests.adapters.BaseAdapter):
        def send(self, request, **kwargs):
            calls.append(request.url)
            if request.url.endswith('/synthetic-auth'):
                raise original
            assert request.url.endswith('/ascend/applications') and request.method == 'POST'
            response = requests.Response()
            response.url, response.request, response.status_code = request.url, request, 401
            response._content = b'{"error":"synthetic expired token"}'
            return response
        def close(self):
            pass
    with api.AscendAPI(token='s6r_pat_synthetic', cache=False,
            token_url='https://control.example.test/synthetic-auth') as c:
        c._s.mount('https://', SyntheticAdapter())
        if refresh:
            c._jwt, c._jwt_exp = 'synthetic-cached-access', float('inf')
        with pytest.raises(requests.Timeout) as exc:
            c.create_app(SPEC)
        assert exc.value is original
    assert len(calls) == (2 if refresh else 1)
    assert calls[-1].endswith('/synthetic-auth')


@pytest.mark.parametrize('final_status', [200, 401])
def test_complete_create_401_retains_exactly_one_auth_refresh(monkeypatch, final_status):
    posts = []
    def handler(method, url, kwargs):
        assert method == 'POST'
        posts.append(url)
        if url.endswith('/auth/token'):
            return FakeResponse(200, {'access_token': 'synthetic-refreshed-access'})
        count = sum(p.endswith('/ascend/applications') for p in posts)
        return FakeResponse(401 if count == 1 else final_status, ROW)
    install_fake_requests(monkeypatch, handler)
    with api.AscendAPI(token='s6r_pat_synthetic', cache=False) as c:
        c._jwt, c._jwt_exp = 'synthetic-cached-access', float('inf')
        if final_status == 200:
            assert c.create_app(SPEC) == ROW
        else:
            with pytest.raises(api.AscendAPIError, match='401'):
                c.create_app(SPEC)
    assert len(posts) == 3
    assert posts[0] == posts[2] and posts[1].endswith('/auth/token')


@pytest.mark.parametrize('status', [200, 201])
@pytest.mark.parametrize('close_error', [False, True])
def test_interrupted_create_closes_once_before_lookup_or_preserves_original(status, close_error):
    calls = []
    original = requests.Timeout('synthetic body interruption')
    class InterruptedBody:
        def stream(self, *args, **kwargs):
            yield b'{"synthetic":"partial"}'
            raise original
        def close(self):
            calls.append('close-post')
            if close_error:
                raise RuntimeError('synthetic close failure')
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
    with client() as c:
        c._s.mount('https://', SyntheticAdapter())
        if close_error:
            with pytest.raises(requests.Timeout) as exc:
                c.create_app(SPEC)
            assert exc.value is original
        else:
            assert c.create_app(SPEC)['recovered'] is True
    assert calls == (['POST', 'close-post'] if close_error else ['POST', 'close-post', 'GET'])


@pytest.mark.parametrize('status', [200, 201, 401, 403])
@pytest.mark.parametrize('close_error', [False, True])
def test_complete_response_finally_closes_once_without_lookup(status, close_error):
    calls = []
    class TrackedResponse(requests.Response):
        def close(self):
            calls.append('close-post')
            if close_error:
                raise RuntimeError('synthetic close failure')
            super().close()
    class SyntheticAdapter(requests.adapters.BaseAdapter):
        def send(self, request, **kwargs):
            calls.append(request.method)
            response = TrackedResponse()
            response.url, response.request, response.status_code = request.url, request, status
            response._content = json.dumps(ROW).encode()
            return response
        def close(self):
            pass
    with client() as c:
        c._s.mount('https://', SyntheticAdapter())
        if status < 400:
            assert c.create_app(SPEC) == ROW
        else:
            with pytest.raises(api.AscendAPIError, match=str(status)):
                c.create_app(SPEC)
    assert calls == ['POST', 'close-post']
