"""Dialogflow CX adapter — detectIntent over REST, one session per prompt.

A published Dialogflow CX agent answers `POST …/sessions/{session}:detectIntent` with the fulfilment
messages of the matched flow. Each probe uses its own session id (stateless, parallel) unless the
config pins one. Authentication is a bearer token: Application Default Credentials by default, a
service-account key file when `sa_key_file` is set, or whatever the standard `auth` block supplies
(a pre-minted token via `--bearer`), in which case no Google library is needed.

Config keys:
  endpoint       - the agent's sessions URL, e.g.
                   https://{region}-dialogflow.googleapis.com/v3/projects/{p}/locations/{l}/agents/{a}
                   (``/sessions/{id}:detectIntent`` is appended; a full detectIntent URL is accepted and
                   its session id is replaced per prompt unless `session_id` is set)
  language_code  - default "en"
  session_id     - optional fixed session (multi-turn against one session; runs sequentially)
  sa_key_file    - optional service-account JSON key; otherwise ADC, otherwise the `auth` block
  timeout_ms     - request timeout (optional)

Response text: queryResult.responseMessages[].text.text[] joined with newlines.
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional

import requests

from .base import BotAdapter, resolve_timeout_s

logger = logging.getLogger(__name__)
_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
_SESSION_RE = re.compile(r"/sessions/[^/:]+:detectIntent$")


def detect_intent_url(endpoint: str, session_id: str) -> str:
    base = endpoint.strip().rstrip("/")
    if _SESSION_RE.search(base):
        return _SESSION_RE.sub(f"/sessions/{session_id}:detectIntent", base)
    return f"{base}/sessions/{session_id}:detectIntent"


def extract_text(body: Any) -> str:
    if not isinstance(body, dict):
        return ""
    qr = body.get("queryResult") or {}
    out: List[str] = []
    for msg in qr.get("responseMessages") or []:
        if not isinstance(msg, dict):
            continue
        text = (msg.get("text") or {}).get("text") if isinstance(msg.get("text"), dict) else None
        if isinstance(text, list):
            out.extend(str(t) for t in text if t)
        payload = msg.get("payload")
        if isinstance(payload, dict):
            for key in ("text", "message", "reply"):
                if isinstance(payload.get(key), str):
                    out.append(payload[key])
    return "\n".join(out).strip()


class DialogflowCXAdapter(BotAdapter):
    """Send a prompt to a Dialogflow CX agent and return its fulfilment text."""

    def __init__(self) -> None:
        self._creds = None

    def _google_token(self, config: Dict[str, Any]) -> Optional[str]:
        """A bearer from ADC or a service-account key; None when neither is available."""
        try:
            import os  # noqa: PLC0415
            import google.auth  # noqa: PLC0415
            import google.auth.transport.requests  # noqa: PLC0415
            if self._creds is None:
                key_file = config.get("sa_key_file") or config.get("service_account_key")
                if key_file:
                    from google.oauth2 import service_account  # noqa: PLC0415
                    self._creds = service_account.Credentials.from_service_account_file(
                        os.path.expanduser(str(key_file)), scopes=_SCOPES)
                else:
                    self._creds, _ = google.auth.default(scopes=_SCOPES)
            if not self._creds.valid:
                self._creds.refresh(google.auth.transport.requests.Request())
            return self._creds.token
        except Exception as exc:  # noqa: BLE001
            logger.info("dialogflow_cx: no Google credential available (%s)", exc)
            return None

    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        endpoint = str(config.get("endpoint") or config.get("url") or "").strip()
        if not endpoint:
            return self._fail("No endpoint configured", start)
        session_id = str(config.get("session_id") or f"ascend-{uuid.uuid4().hex[:16]}")
        url = detect_intent_url(endpoint, session_id)
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        extra = config.get("headers") or {}
        if isinstance(extra, dict):
            headers.update({str(k): str(v) for k, v in extra.items()})
        if not any(k.lower() == "authorization" for k in headers):
            token = self._google_token(config)
            if token:
                headers["Authorization"] = f"Bearer {token}"
            else:
                return self._fail("no credential: set up Application Default Credentials, `sa_key_file`, "
                                  "or supply a bearer with --bearer", start)
        body = {"queryInput": {"text": {"text": prompt}, "languageCode": str(config.get("language_code") or "en")}}
        timeout = resolve_timeout_s(config)
        try:
            logger.info("dialogflow_cx: POST %s", url)
            resp = requests.post(url, json=body, headers=headers, timeout=timeout, verify=config.get("verify_tls", True))
        except requests.RequestException as e:
            return self._fail(f"HTTP error: {e}", start)
        if resp.status_code >= 400:
            detail = ""
            try:
                detail = str((resp.json().get("error") or {}).get("message") or "")[:300]
            except Exception:  # noqa: BLE001
                detail = str(getattr(resp, "text", ""))[:300]
            return self._fail(f"HTTP {resp.status_code}: {detail}", start, status_code=resp.status_code)
        try:
            data = resp.json()
        except ValueError:
            return self._fail("expected JSON from detectIntent", start, raw=str(resp.text)[:500])
        text = extract_text(data)
        if not text:
            return self._fail("no fulfilment text in the response", start, raw=str(resp.text)[:500])
        qr = data.get("queryResult") or {}
        return self._ok(text, start, adapter="dialogflow_cx", session_id=session_id,
                        intent=((qr.get("intent") or {}).get("displayName") if isinstance(qr.get("intent"), dict) else None),
                        page=((qr.get("currentPage") or {}).get("displayName") if isinstance(qr.get("currentPage"), dict) else None))
