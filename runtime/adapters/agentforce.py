"""
Agentforce adapter — Salesforce Agentforce via the native, authenticated Agent API.

This is the API-based, long-lived-auth path (contrast with `scrt2_direct`, which
reverse-engineers the public unauthenticated chat widget). It mints an OAuth 2.0
client-credentials token, caches it, silently re-mints on expiry/401, and drives the
full Agent API session lifecycle:

  1. POST {instance}/services/oauth2/token   (grant_type=client_credentials)  → access_token
  2. POST {api_base}/agents/{agentId}/sessions                                → sessionId
  3. POST {api_base}/sessions/{sessionId}/messages                            → agent reply
  4. DELETE {api_base}/sessions/{sessionId}   (best-effort session teardown)

Long-lived auth:
  The client_id / client_secret of the External Client App are the durable credential.
  The ~2h access token is short-lived and NOT refreshable — the adapter just re-mints a
  fresh one from the same client_id/secret when it expires or a call 401s. No browser,
  no user login, no per-run token pasting. Because the Lambda router caches one adapter
  instance per (adapter, config), a single token is reused across many probes.

Endpoint consistency (like Bedrock):
  The Agent API data plane is a single GLOBAL host for every org:
    https://api.salesforce.com/einstein/ai-agent/v1   (Gov Cloud: api.gov.salesforce.com)
  Only the OAuth *token* endpoint is org-specific (your My Domain).

Required config keys:
  instance_url   - My Domain, e.g. https://<org>.my.salesforce.com
                   (used for the token endpoint AND instanceConfig.endpoint)
  agent_id       - BotDefinition / Agent ID, e.g. 0Xxg5000000U1DBCA0
                   (SOQL: SELECT Id FROM BotDefinition, or the agent's Setup URL)
  client_id      | client_id_env      - External Client App Consumer Key (literal or env var name)
  client_secret  | client_secret_env  - External Client App Consumer Secret (literal or env var name)

Optional config keys:
  api_base       - Agent API base (default https://api.salesforce.com/einstein/ai-agent/v1)
  bypass_user    - true → agent runs as its configured user; false → as token holder (default true)
  region         - optional x-salesforce-region header value (e.g. "us-west-2")
  end_session    - DELETE the session after each prompt (default true)
  timeout_ms     - per-request timeout in ms (default 60000). Raise for slow agentic targets; leave headroom for result delivery inside the platform's ~90s reclaim window.
  token_ttl_s    - safety window before re-minting the cached token (default 5400 = 90 min)

Setup requirements on the Salesforce side (see configs/example-agentforce.json):
  - External Client App with Client Credentials flow enabled, Run-As an integration user
  - OAuth scopes: api chatbot_api sfap_api  (plus refresh_token/offline_access)
  - "Issue JWT-based access tokens" enabled (Agent API requires a JWT-format bearer)
  - Agent Active and connected to the app under Agentforce Builder → Connections
  - Agent must NOT be type "Agentforce (Default)" (unsupported by the Agent API)
"""

import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Dict, Optional

import requests

from .base import BotAdapter

logger = logging.getLogger(__name__)

DEFAULT_API_BASE = "https://api.salesforce.com/einstein/ai-agent/v1"


class AgentforceAdapter(BotAdapter):
    """Salesforce Agentforce via the authenticated Agent API (OAuth client credentials)."""

    def __init__(self) -> None:
        # Cached token state — shared across probes on the reused adapter instance.
        self._token: Optional[str] = None
        self._token_exp: float = 0.0
        self._token_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_secret(config: Dict[str, Any], literal_key: str, env_key: str) -> str:
        """Prefer an env var (named by config[env_key]) over a literal config value."""
        env_name = config.get(env_key)
        if env_name:
            val = os.environ.get(env_name, "")
            if not val:
                raise ValueError(f"Env var '{env_name}' (from {env_key}) is not set")
            return val
        return config.get(literal_key, "") or ""

    def _get_token(self, config: Dict[str, Any], force: bool = False) -> str:
        """Return a valid access token, minting/caching one via client_credentials."""
        with self._token_lock:
            if not force and self._token and time.time() < self._token_exp:
                return self._token

            instance_url = config["instance_url"].rstrip("/")
            client_id = self._resolve_secret(config, "client_id", "client_id_env")
            client_secret = self._resolve_secret(config, "client_secret", "client_secret_env")
            if not client_id or not client_secret:
                raise ValueError("Missing client_id/client_secret (or their *_env references)")

            token_url = f"{instance_url}/services/oauth2/token"
            timeout = config.get("timeout_ms", 60000) / 1000
            logger.info("Agentforce: minting client_credentials token")
            resp = requests.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                timeout=timeout,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Token request failed {resp.status_code}: {resp.text[:300]}"
                )
            data = resp.json()
            token = data.get("access_token")
            if not token:
                raise RuntimeError(f"No access_token in token response: {json.dumps(data)[:300]}")

            self._token = token
            self._token_exp = time.time() + config.get("token_ttl_s", 5400)
            return token

    # ------------------------------------------------------------------
    # Agent API calls
    # ------------------------------------------------------------------

    def _headers(self, token: str, config: Dict[str, Any]) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        region = config.get("region")
        if region:
            headers["x-salesforce-region"] = region
        return headers

    def _create_session(self, token: str, config: Dict[str, Any], timeout: float) -> str:
        api_base = config.get("api_base", DEFAULT_API_BASE).rstrip("/")
        instance_url = config["instance_url"].rstrip("/")
        url = f"{api_base}/agents/{config['agent_id']}/sessions"
        body = {
            "externalSessionKey": str(uuid.uuid4()),
            "instanceConfig": {"endpoint": instance_url},
            "streamingCapabilities": {"chunkTypes": ["Text"]},
            "bypassUser": config.get("bypass_user", True),
        }
        resp = requests.post(url, json=body, headers=self._headers(token, config), timeout=timeout)
        if resp.status_code == 401:
            raise _Unauthorized("session creation")
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Session creation failed {resp.status_code}: {resp.text[:300]}")
        session_id = resp.json().get("sessionId")
        if not session_id:
            raise RuntimeError(f"No sessionId in response: {resp.text[:300]}")
        return session_id

    def _send_message(self, token: str, session_id: str, prompt: str,
                      config: Dict[str, Any], timeout: float) -> str:
        api_base = config.get("api_base", DEFAULT_API_BASE).rstrip("/")
        url = f"{api_base}/sessions/{session_id}/messages"
        body = {
            "message": {"sequenceId": 1, "type": "Text", "text": prompt},
            "variables": [],
        }
        resp = requests.post(url, json=body, headers=self._headers(token, config), timeout=timeout)
        if resp.status_code == 401:
            raise _Unauthorized("message send")
        if resp.status_code != 200:
            raise RuntimeError(f"Message send failed {resp.status_code}: {resp.text[:300]}")
        return _extract_reply(resp.json())

    def _end_session(self, token: str, session_id: str, config: Dict[str, Any], timeout: float) -> None:
        api_base = config.get("api_base", DEFAULT_API_BASE).rstrip("/")
        url = f"{api_base}/sessions/{session_id}"
        headers = {**self._headers(token, config), "x-session-end-reason": "UserRequest"}
        try:
            requests.delete(url, headers=headers, timeout=timeout)
        except Exception as e:  # noqa: BLE001 — teardown must never fail the probe
            logger.warning(f"Agentforce: session teardown failed (ignored): {e}")

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()

        missing = [k for k in ("instance_url", "agent_id") if not config.get(k)]
        if missing:
            return self._fail(f"Missing required config: {', '.join(missing)}", start)

        timeout = config.get("timeout_ms", 60000) / 1000

        try:
            token = self._get_token(config)
        except Exception as e:  # noqa: BLE001
            return self._fail(f"Auth error: {e}", start, adapter="agentforce")

        # One automatic re-mint + retry on a 401 (expired/revoked token).
        for attempt in (1, 2):
            session_id = None
            try:
                session_id = self._create_session(token, config, timeout)
                response = self._send_message(token, session_id, prompt, config, timeout)
                if config.get("end_session", True):
                    self._end_session(token, session_id, config, timeout)
                if not response:
                    return self._fail("Empty agent response", start,
                                      adapter="agentforce", session_id=session_id)
                return self._ok(response, start, adapter="agentforce", session_id=session_id)
            except _Unauthorized as e:
                if session_id and config.get("end_session", True):
                    self._end_session(token, session_id, config, timeout)
                if attempt == 1:
                    logger.info(f"Agentforce: 401 on {e}; re-minting token and retrying")
                    try:
                        token = self._get_token(config, force=True)
                    except Exception as te:  # noqa: BLE001
                        return self._fail(f"Auth error on re-mint: {te}", start, adapter="agentforce")
                    continue
                return self._fail(f"Unauthorized after re-mint ({e})", start, adapter="agentforce")
            except Exception as e:  # noqa: BLE001
                if session_id and config.get("end_session", True):
                    self._end_session(token, session_id, config, timeout)
                logger.error(f"Agentforce adapter error: {e}", exc_info=True)
                return self._fail(str(e), start, adapter="agentforce")

        return self._fail("Unreachable", start, adapter="agentforce")


class _Unauthorized(Exception):
    """Raised on a 401 so send_prompt can re-mint the token and retry once."""


def _extract_reply(data: Dict[str, Any]) -> str:
    """Pull the agent's text from an Agent API message response.

    The response carries a `messages` list that can mix `ProgressIndicator` /
    `SessionEnded` entries with the real `Inform` reply. Prefer `Inform`; fall back
    to any entry that has non-empty `message` text.
    """
    messages = data.get("messages") or []
    inform = [m.get("message", "") for m in messages if m.get("type") == "Inform" and m.get("message")]
    if inform:
        return "\n".join(inform).strip()
    for m in messages:
        text = m.get("message")
        if text:
            return str(text).strip()
    return ""
