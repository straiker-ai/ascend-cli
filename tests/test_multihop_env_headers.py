"""A static credential next to a per-request minted one: env: header values in a derived_multihop
step and in its attach block resolve from the environment/store, never go out as "env:NAME"."""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from layers.auth import AuthProvider, _resolve_env_values  # noqa: E402


class _Mint(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        _Mint.seen.append(dict(self.headers))
        body = json.dumps({"token": "minted-123"}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):  # quiet
        pass


@pytest.fixture
def mint_server():
    srv = HTTPServer(("127.0.0.1", 0), _Mint)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    yield f"http://127.0.0.1:{srv.server_port}/mint"
    srv.shutdown()


def test_env_values_resolve_and_literals_stay(monkeypatch):
    monkeypatch.setenv("LAB_CODE_T", "code-9f13")
    out = _resolve_env_values({"x-lab-code": "env:LAB_CODE_T", "accept": "application/json"})
    assert out == {"x-lab-code": "code-9f13", "accept": "application/json"}


def test_multihop_step_and_attach_carry_the_resolved_static_header(monkeypatch, mint_server):
    monkeypatch.setenv("LAB_CODE_T", "code-9f13")
    _Mint.seen.clear()
    cfg = {"type": "derived_multihop",
           "steps": [{"method": "POST", "url": mint_server, "json": {},
                      "headers": {"x-lab-code": "env:LAB_CODE_T"},
                      "extract": [{"var": "MINTED", "path": "token"}]}],
           "attach": {"headers": {"x-conv-token": "{{MINTED}}", "x-lab-code": "env:LAB_CODE_T"}}}
    mat = AuthProvider(cfg).materialize(timeout_s=5, verify_tls=False)
    assert _Mint.seen and _Mint.seen[0].get("x-lab-code") == "code-9f13"     # the mint call carried it
    assert mat.headers["x-conv-token"] == "minted-123"                       # the minted value attached
    assert mat.headers["x-lab-code"] == "code-9f13"                          # and the static one resolved
