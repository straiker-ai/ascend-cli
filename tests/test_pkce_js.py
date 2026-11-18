"""
The PKCE helper in the login scaffold, EXECUTED. A hosted login adaptor may have to drive an
OAuth2 PKCE flow, where code_challenge = base64url(sha256(code_verifier)) (RFC 7636). The engine
runs adaptors in an isolate with no crypto, TextEncoder, Buffer or atob, so that challenge has to
be computed with plain integer arithmetic. This runs the shipped helper in a fresh V8 context with
none of those globals and checks it against the RFC 7636 appendix-B vector.

Skipped where `node` is absent; the engine's own gate and `ascend adaptor verify` remain the
authority for what the isolate accepts.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for _p in (REPO / "runtime", REPO):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import adaptor as AD  # noqa: E402

NODE = shutil.which("node")
RUNNER = REPO / "tests" / "_pkce_runner.js"
TEMPLATE = REPO / "templates" / "adaptor_login_scaffold.js"
pytestmark = pytest.mark.skipif(not NODE, reason="node is not installed; the engine's gate is the authority")

# RFC 7636 appendix B, the canonical PKCE S256 vector.
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
# base64url(sha256("")) — a second, independent vector (the well-known empty-string SHA-256).
EMPTY_CHALLENGE = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"


def _run(verifier: str) -> dict:
    r = subprocess.run([NODE, str(RUNNER), str(TEMPLATE), verifier],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_the_rfc7636_appendix_b_vector():
    assert _run(VERIFIER)["challenge"] == CHALLENGE


def test_a_second_independent_vector_the_empty_string():
    assert _run("")["challenge"] == EMPTY_CHALLENGE


def test_it_computes_in_a_context_with_no_node_crypto_global():
    """The bare V8 context the helper ran in exposed no Buffer/TextEncoder/crypto/atob — the same
    constraint the engine isolate imposes. If any had leaked in, the proof would be hollow."""
    assert _run(VERIFIER)["leaked"] == []


def test_the_helper_ships_in_the_login_scaffold_and_passes_the_gate():
    """Gate-accepts, the operator-side mirror: the login scaffold carrying the helper has no banned
    identifier, exactly one sendTurn, and no export. The engine gate is proven live in the PR."""
    src = TEMPLATE.read_text(encoding="utf-8")
    assert "function pkceChallenge(" in src
    assert AD.lint_source(src) == []
