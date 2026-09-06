"""
discovery.validate — the HARD GATE and the iterate loop.

A composed config is only *usable* once it has been proven to elicit a clean
answer from the LIVE target. :func:`validate_config` replays one prompt through
the config's adapter and reports whether real response text came back;
:func:`iterate` tries alternates for a shaky layer (e.g. WebSocket ``json`` vs
``text`` framing, ``done_when`` vs ``idle_ms``) and returns the first config that
validates.

Network happens only when these functions are *called*. Auth secrets are resolved
from the environment at call time via :mod:`layers.auth` and merged into the
config's headers/cookies — they are never written back into the config on disk.
"""
from __future__ import annotations

import copy
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def _ensure_runtime_on_path() -> None:
    """Put the ``runtime/`` dir on sys.path so ``dispatch``/``layers`` import.

    The existing runtime modules use flat imports (``from dispatch import ...``);
    this mirrors that convention without importing anything at module load time.
    """
    runtime_dir = str(Path(__file__).resolve().parent.parent)
    if runtime_dir not in sys.path:
        sys.path.insert(0, runtime_dir)


def _merge_auth(config: Dict[str, Any], *, timeout_s: float, verify_tls: bool) -> Dict[str, Any]:
    """Resolve the config's ``auth`` block and fold material into headers/params.

    Returns a *copy* with headers/cookies/params merged. On any auth failure the
    original config is returned unchanged (the adapter call will then surface the
    auth problem itself, which keeps error reporting in one place).
    """
    from dispatch import merge_auth  # single source of truth, shared with the live relay
    return merge_auth(config, timeout_s=timeout_s, verify_tls=verify_tls)


def validate_config(
    adapter_type: str,
    config: Dict[str, Any],
    sample_prompt: str,
    expected_substr: Optional[str] = None,
    *,
    timeout_s: float = 60.0,
    verify_tls: bool = True,
) -> Dict[str, Any]:
    """Run ``config`` against the LIVE target for one prompt (the hard gate).

    Args:
        adapter_type: adapter name (falls back to ``config["adapter"]``).
        config: a composed adapter config (as produced by :func:`compose`).
        sample_prompt: the single prompt to send.
        expected_substr: if given, ``matched`` is True only when it appears in
            the response text.
        timeout_s: overall budget for the send (and any auth network call).
        verify_tls: pass through to TLS verification for auth + adapter.

    Returns:
        ``{"ok": bool, "response": str, "error": str|None, "matched": bool,
           "adapter": str}``. ``ok`` is True only when the adapter reported
        success AND non-empty text came back. When ``expected_substr`` is set,
        ``ok`` additionally requires the substring to match.
    """
    _ensure_runtime_on_path()
    adapter = adapter_type or config.get("adapter")
    if not adapter:
        return {"ok": False, "response": "", "error": "no adapter_type given", "matched": False,
                "adapter": None}

    from dispatch import ADAPTER_REGISTRY, ConversationRouter  # lazy

    if adapter not in ADAPTER_REGISTRY:
        return {"ok": False, "response": "", "adapter": adapter, "matched": False,
                "error": f"unknown adapter {adapter!r}; known={sorted(ADAPTER_REGISTRY)}"}

    merged = _merge_auth(config, timeout_s=min(timeout_s, 20.0), verify_tls=verify_tls)
    if merged.get("_auth_error"):
        return {"ok": False, "response": "", "adapter": adapter, "matched": False,
                "error": f"auth failed: {merged['_auth_error']}"}

    router = ConversationRouter()
    try:
        result = router.send(adapter, merged, "discovery-validate", sample_prompt,
                             None, timeout_s)
        # A config that carries a conversation id forward is only proven by a SECOND turn on the
        # same adapter instance: the id from turn 1 has to be accepted on turn 2. A target that
        # rotates ids 409s a wrong one, so this is the check that separates "echoes the id" from
        # "happened to work once". Failure is reported as turn 2's error; turn 1's text stands.
        if result.get("success") and (merged.get("carry") or {}).get("request_field"):
            second = router.send(adapter, merged, "discovery-validate",
                                 "Thanks. And in one word, are you a person or a program?",
                                 None, timeout_s)
            if not second.get("success"):
                result = {**result, "success": False,
                          "error": f"turn 2 with the carried id failed: {second.get('error')}"}
    finally:
        router.reset()

    response = (result.get("response") or "").strip()
    ok = bool(result.get("success")) and bool(response)
    matched = (expected_substr is None) or (expected_substr in response)
    if expected_substr is not None:
        ok = ok and matched
    return {
        "ok": ok,
        "response": response,
        "error": result.get("error"),
        "matched": matched,
        "adapter": adapter,
        # How long the target actually took. This is the one measurement that says whether the
        # target can be assessed at all, because the platform bounds each probe (see
        # adapters.base.platform_window_warning) — so it must survive back to the caller.
        "duration_ms": result.get("duration_ms"),
        "metadata": result.get("metadata", {}),
    }


# A second question, chosen to be answerable by any assistant and to share no vocabulary with the
# onboarding prompt, so two different answers cannot coincidentally match.
_SECOND_PROMPT = "What is 17 plus 25? Reply with the number only."


def prove_answer_varies(
    adapter_type: str,
    config: Dict[str, Any],
    first_response: Any,
    *,
    timeout_s: float = 60.0,
    verify_tls: bool = True,
) -> Dict[str, Any]:
    """Ask a second, different question and require a different answer.

    This closes the worst failure the CLI has: a completed assessment reporting LOW risk that
    never invoked the model. Every gate the tool had could be passed by a config whose
    ``response_path`` lands on something that is not the answer — the request succeeds, the body
    is non-empty, a string comes back, and ``validate_config`` returns ``ok=True``. Three separate
    target shapes did exactly that in live testing:

      * a create-conversation endpoint whose "reply" was ``"new conversation"`` — the TITLE;
      * an async job endpoint whose "reply" was ``"accepted"`` — the ACK, with the real answer
        arriving later on a poll the config never made;
      * a multi-block response where the derived path pinned the second block, so every probe
        scored half an answer and the first block — where a leaked system prompt would appear —
        was discarded.

    Each was registered as "proven against the live target" and each produced a clean report.

    Latency and length are the tempting signals and both are wrong: a terse model is legitimately
    short, and a cached one is legitimately fast. The property that actually separates an answer
    from a status string is that **a constant is constant**. A model answers two different
    questions differently; a title, an ack, an id and a fixed error do not.

    Returns ``{"varies": bool, "second": <response>, "checked": bool}``. ``checked`` is False when
    the second call could not be made at all (rate limit, one-shot session, transport error) —
    the caller must not treat that as proof of a constant, because refusing a target on a failed
    follow-up would be its own false negative.
    """
    try:
        res = validate_config(adapter_type, config, _SECOND_PROMPT, None,
                              timeout_s=timeout_s, verify_tls=verify_tls)
    except Exception:
        return {"varies": True, "second": None, "checked": False}
    if not res.get("ok"):
        return {"varies": True, "second": None, "checked": False}
    a = (str(first_response) if first_response is not None else "").strip()
    b = (str(res.get("response")) if res.get("response") is not None else "").strip()
    if not a or not b:
        return {"varies": True, "second": res.get("response"), "checked": False}
    return {"varies": a != b, "second": res.get("response"), "checked": True,
            "duration_ms": res.get("duration_ms")}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` onto a copy of ``base``."""
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def iterate(
    adapter_type: str,
    config: Dict[str, Any],
    alternates: List[Dict[str, Any]],
    sample_prompt: str,
    expected_substr: Optional[str] = None,
    *,
    evidence: Optional[Dict[str, Any]] = None,
    timeout_s: float = 60.0,
    verify_tls: bool = True,
) -> Dict[str, Any]:
    """Try the base config, then each alternate override, returning the first that validates.

    ``alternates`` is a list of partial config overrides for the shaky layer, e.g.::

        [{"framing": "json"}, {"framing": "text"}]
        [{"stream": {"done_when": {"contains": "[DONE]"}}}, {"stream": {"idle_ms": 3000}}]

    Each override is deep-merged onto ``config`` and validated in turn.

    Returns:
        On success: ``{"ok": True, "config": <winning config>, "attempt": <i>,
        "validation": {...}, "tried": [...]}``. On failure: ``{"ok": False,
        "tried": [...], "evidence": evidence, "confidence": "low", ...}`` so an
        operator/agent can resolve the layer from the raw evidence.
    """
    candidates: List[Dict[str, Any]] = [config] + [_deep_merge(config, alt) for alt in alternates]
    tried: List[Dict[str, Any]] = []
    for i, cand in enumerate(candidates):
        v = validate_config(adapter_type, cand, sample_prompt, expected_substr,
                            timeout_s=timeout_s, verify_tls=verify_tls)
        label = "base" if i == 0 else f"alternate[{i - 1}]={alternates[i - 1]}"
        tried.append({"attempt": i, "label": label, "ok": v["ok"],
                      "error": v.get("error"), "matched": v.get("matched")})
        if v["ok"]:
            return {"ok": True, "config": cand, "attempt": i, "label": label,
                    "validation": v, "tried": tried}
    return {
        "ok": False,
        "tried": tried,
        "evidence": evidence,
        "confidence": "low",
        "message": ("no config variant produced a clean response; "
                    "resolve the flagged layer manually from the evidence"),
    }
