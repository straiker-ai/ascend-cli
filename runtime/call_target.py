"""
call_target.py — the SDK seam, wired to the adapter framework.

`bridge_client.py` leaves one function for you to write: take a leased probe's
body/headers, call your target, return (status_code, response). Here that seam
dispatches into the proven adapter framework (15 adapters) with a conversation/
session model, so a single implementation handles REST, SSE, WebSocket (incl.
chunked text/json framing), multi-step session APIs, browser widgets, etc.
"""
import copy
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

from dispatch import (ConversationRouter, load_config, extract_prompt,
                      shape_result, conversation_key, STATEFUL_ADAPTERS, merge_auth)

logger = logging.getLogger("ascendbridge.call_target")

# Refresh an oauth2 token this long after the last materialize — comfortably under a typical
# 1h Entra/OAuth token TTL, so a long assessment never sends an expired token.
_DEFAULT_AUTH_REFRESH_S = 2700.0

def _bridge_response_timeout_s(config: Optional[Dict[str, Any]]) -> float:
    """How long the bridge waits for the adapter before abandoning one probe.

    Derived from the platform's per-probe window rather than separately configurable — see
    adapters.base. Raising it alone cannot make a slow target work, so it is not its own knob.
    """
    from adapters.base import bridge_response_timeout_s
    return bridge_response_timeout_s()


RETRY_AFTER_DEFAULT_S = 2.0     # a 429 with no Retry-After: a short, single wait
RETRY_AFTER_MAX_S = 10.0        # never park a probe longer than this on a target's say-so


def _retry_after_seconds(headers) -> Optional[float]:
    """Seconds from a Retry-After header (delta form only), else None."""
    try:
        items = headers.items() if isinstance(headers, dict) else (headers or [])
        for k, v in items:
            if str(k).lower() == "retry-after":
                return float(str(v).strip())
    except (TypeError, ValueError, AttributeError):
        pass
    return None


class TargetCaller:
    """Builds a lease-client handler bound to one adapter config."""

    def __init__(self, adapter_type: str, config_name: str,
                 config: Optional[Dict[str, Any]] = None,
                 timeout_s: Optional[float] = None) -> None:
        raw = config if config is not None else load_config(config_name)
        if timeout_s is None:
            timeout_s = _bridge_response_timeout_s(raw)
        # Keep the pristine, unmerged config so we can re-materialize a fresh token mid-run.
        self._raw = copy.deepcopy(raw)
        # Resolve any auth block up-front so the LIVE relay sends the same credentials
        # `adapter validate` proved worked. Without this, validate=ok and every probe 401s.
        self.config = merge_auth(copy.deepcopy(self._raw))
        self.adapter_type = adapter_type or self.config.get("adapter", "direct_api")
        self.config_name = config_name if isinstance(config_name, str) else "inline"
        self.timeout_s = timeout_s
        self.router = ConversationRouter()
        # Layer 3 decides WHEN credentials must be re-acquired. That decision object already
        # exists (layers/auth.py AuthLifecycle) and covers all four kinds including a JWT `exp`
        # and a 401 challenge, so it is wired in here — at the one seam every adapter goes
        # through — rather than each adapter growing its own copy of the same logic.
        self._lifecycle = self._build_lifecycle()
        # `token=` was never passed here, so AuthLifecycle._token stayed None for the whole run
        # and the JWT-`exp` branch of refresh_on_ttl -- the accurate one -- was dead code in
        # production. Every short-lived JWT fell back to the wall-clock ttl_s guess and refreshed
        # late. The provider has always recorded the token; it just never reached the lifecycle.
        self._lifecycle.mark_refreshed(token=self.config.get("_auth_token"))

    def _build_lifecycle(self):
        from layers.auth import AuthLifecycle
        block = self._raw.get("auth_lifecycle")
        if block is None:
            # Back-compat: an oauth2 config with no explicit lifecycle used to refresh on a fixed
            # TTL. Express exactly that rather than silently downgrading it to `static`.
            auth = self._raw.get("auth")
            if isinstance(auth, dict) and auth.get("type") == "oauth2":
                ttl = float(self._raw.get("auth_refresh_ms",
                                          _DEFAULT_AUTH_REFRESH_S * 1000)) / 1000.0
                block = {"type": "refresh_on_ttl", "ttl_s": ttl}
        try:
            return AuthLifecycle(block)
        except Exception as exc:                  # a bad block must not take the relay down
            logger.warning("auth_lifecycle ignored (%s); treating credentials as static", exc)
            return AuthLifecycle(None)

    def _reauth(self, why: str) -> None:
        self.config = merge_auth(copy.deepcopy(self._raw))
        self._lifecycle.mark_refreshed(token=self.config.get("_auth_token"))
        logger.info("auth: re-acquired credentials (%s)", why)

    def _maybe_refresh_auth(self) -> None:
        """Re-acquire credentials when Layer 3 says they are stale. No-op for static auth."""
        if self._lifecycle.needs_refresh():
            self._reauth("ttl")

    @property
    def is_stateful(self) -> bool:
        """Whether probes must run one at a time to avoid sharing conversation state.

        Statefulness is not purely a property of the adapter — it can be created by the CONFIG.
        `sse_stream` is not in STATEFUL_ADAPTERS, but a `create` block without `per_prompt` mints
        exactly one conversation and reuses it for every prompt (see sse_stream._conversation).
        Such a config was still getting the stateless default of 10 workers, so ten probes
        interleaved inside a single conversation: each one saw the others' turns as its own
        context. That corrupts multi-turn results in both directions — a probe can be scored
        against a reply provoked by a different probe — and it does so silently, because every
        probe still gets answered and the run still completes.

        `conversation_key` remains the escape hatch: it means the adapter keys conversations per
        probe, so parallelism is safe again.
        """
        if self.config.get("conversation_key"):
            return False
        if self.adapter_type in STATEFUL_ADAPTERS:
            return True
        create = self.config.get("create") or {}
        return bool(create.get("url")) and not create.get("per_prompt")

    def recommended_workers(self) -> int:
        """Sequential for stateful/multi-turn targets unless they expose a key."""
        if "max_workers" in self.config:
            return int(self.config["max_workers"])
        return 1 if self.is_stateful else 10

    _last_retry_after: Optional[float] = None

    def handler(self, message: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        self._maybe_refresh_auth()
        # `merge_auth` never raises: an auth failure -- a token endpoint down, an env ref unset, a
        # re-mint that 401'd -- is recorded as `_auth_error` on the merged config, and the config
        # is otherwise returned UNAUTHENTICATED. Only `adapter validate` ever read that field. The
        # live relay did not, so a credential that died mid-run sent every remaining probe with no
        # credential at all; the target refused them, and refusals are not findings, so the run
        # finished looking clean having measured nothing. Refuse the probe with the reason instead.
        err = self.config.get("_auth_error") if isinstance(self.config, dict) else None
        if err:
            return 401, {"response": "", "_error": f"auth: {err}"}
        payload = message.get("payload", {})
        body = payload.get("body")
        try:
            prompt = extract_prompt(body, self.config)
        except Exception as e:
            return 400, {"response": "", "_error": f"prompt-extract: {e}"}
        conv = conversation_key(message, self.config)
        status, out = self._send_once(prompt, conv)
        # An auth challenge means the credential died mid-run, not that the target refused. Without
        # this, every probe after expiry scores as a refusal and the assessment finishes looking
        # clean while measuring nothing. Re-acquire and retry the probe exactly once.
        if self._lifecycle.should_reauth(status):
            self._reauth(f"HTTP {status}")
            err = self.config.get("_auth_error") if isinstance(self.config, dict) else None
            if err:                     # the re-mint itself failed: say so, do not retry naked
                return 401, {"response": "", "_error": f"auth (re-acquire failed): {err}"}
            status, out = self._send_once(prompt, conv)
        if status == 429:
            # A target rate-limiting a run that is otherwise fine. Without this every throttled
            # probe scored as unanswered, and a target that throttles one request in three lost a
            # third of its assessment. One bounded wait, one retry; a second 429 stands.
            wait = min(max(self._last_retry_after or RETRY_AFTER_DEFAULT_S, 0.0), RETRY_AFTER_MAX_S)
            logging.getLogger("ascendbridge").info("429 from the target; retrying once in %.1fs", wait)
            time.sleep(wait)
            status, out = self._send_once(prompt, conv)
        return status, out

    def _send_once(self, prompt: str, conv: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        result = self.router.send(
            self.adapter_type, self.config, self.config_name,
            prompt, conv, self.timeout_s)
        meta = result.get("metadata") or {}
        self._last_retry_after = _retry_after_seconds(meta.get("headers"))
        try:
            self._lifecycle.note_response(int(meta.get("status_code") or 0),
                                          meta.get("headers"))
        except Exception:                          # lifecycle bookkeeping must never fail a probe
            pass
        return shape_result(result, self.config)

    def reset(self) -> int:
        return self.router.reset()
