"""
Microsoft Copilot Studio adapter — Bot Framework Direct Line 3.0 REST.

No browser required. Reaches a published Copilot Studio agent through its
Direct Line channel, the same plumbing Copilot Studio's Web Chat uses under
the hood. Direct Line is Microsoft's recommended path for custom / headless
clients and is NOT deprecated (the newer M365 Agents SDK sits alongside it).

Flow (fresh conversation per prompt — stateless, parallelizable):
  1. Mint a Direct Line token:
       - directline_token_endpoint  → GET (Copilot Studio > Channels > Mobile app).
                                       Works with NO signed-in user ONLY if the agent's
                                       Security = "No authentication".
       - directline_secret          → POST /v3/directline/tokens/generate (classic
                                       Azure Bot Service Direct Line secret).
       - bearer_token               → use a pre-minted token directly (for Entra-gated
                                       agents the customer supplies a delegated token).
  2. POST /v3/directline/conversations           → start conversation.
     IMPORTANT: only the token RETURNED here can post activities (stale token → HTTP 502).
  3. (optional) warmup: post a startConversation event / warmup text, discard the
     greeting so probes get real answers, not consent/greeting boilerplate.
  4. POST /v3/directline/conversations/{id}/activities  → send the prompt as a message.
  5. GET  /v3/directline/conversations/{id}/activities?watermark=<w>  → poll for the
     bot turn. Keep type=="message" AND from.id != user_id (drops our own echo).
     Advance the watermark until the bot burst stops (a reply can be multiple activities).

Reachability: only agents with Security = "No authentication" are hittable headlessly
via directline_token_endpoint. Entra-gated / manual-auth agents need a delegated user
token (Power Platform API → CopilotStudio.Copilots.Invoke) — pass it as bearer_token.

Required config keys (one of the token sources):
  directline_token_endpoint  - Copilot Studio > Channels > Mobile app token URL (short-lived)
  directline_secret          - OR a classic Direct Line secret (LONG-LIVED, never expires)
  directline_secret_env      - OR the name of an env var holding the secret (keeps it out of git)
  bearer_token               - OR a pre-minted Direct Line / delegated token
  bearer_token_env           - OR the name of an env var holding the token

Optional config keys:
  user_id           - Direct Line user id, must start with "dl_" (default dl_redteam001)
  warmup_message    - throwaway first message to eat the greeting turn (default "Hello");
                      set "" to disable once a run is established (avoids first-probe 30s stall)
  warmup            - bool; if false, skip warmup entirely (default: warmup_message is non-empty)
  directline_base   - Direct Line host (default https://directline.botframework.com)
  poll_interval_ms  - poll cadence for reading the reply (default 1000; <1000 risks throttling)
  bot_settle_ms     - after the first bot activity, keep polling this long for more
                      activities in the same turn before returning (default 1500)
  locale            - message locale (default en-US)
  timeout_ms        - overall per-prompt budget in ms (default 60000). Raise for slow agentic targets; leave headroom for result delivery inside the platform's ~90s reclaim window.
"""

import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

import requests

from .base import BotAdapter

logger = logging.getLogger(__name__)

DEFAULT_DIRECTLINE_BASE = "https://directline.botframework.com"


def _from_env(var_name: Optional[str]) -> Optional[str]:
    """Read a credential from the named environment variable (keeps secrets out of git)."""
    return os.environ.get(var_name) if var_name else None


class CopilotStudioAdapter(BotAdapter):
    """Microsoft Copilot Studio via Bot Framework Direct Line 3.0 — no browser."""

    def _mint_token(
        self, config: Dict[str, Any], directline_base: str, timeout: float
    ) -> str:
        """Return a Direct Line token usable to start a conversation.

        Credential precedence: token endpoint > Direct Line secret > pre-minted bearer.
        Durable credentials (secret / bearer) may be supplied via *_env config keys that
        name an environment variable, keeping the long-lived credential out of git —
        the same pattern the `agentforce` adapter uses for client_id_env/client_secret_env.
        """
        token_endpoint = config.get("directline_token_endpoint")
        secret = config.get("directline_secret") or _from_env(config.get("directline_secret_env"))
        bearer = config.get("bearer_token") or _from_env(config.get("bearer_token_env"))

        if token_endpoint:
            resp = requests.get(token_endpoint, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            token = data.get("token")
            if not token:
                raise RuntimeError(f"Token endpoint returned no token: {json.dumps(data)[:300]}")
            return token

        if secret:
            resp = requests.post(
                f"{directline_base}/v3/directline/tokens/generate",
                headers={"Authorization": f"Bearer {secret}"},
                timeout=timeout,
            )
            resp.raise_for_status()
            token = resp.json().get("token")
            if not token:
                raise RuntimeError("tokens/generate returned no token")
            return token

        if bearer:
            return bearer

        raise RuntimeError(
            "No token source: set directline_token_endpoint, directline_secret, or bearer_token"
        )

    def _start_conversation(
        self, directline_base: str, token: str, timeout: float
    ) -> Dict[str, str]:
        """Start a conversation. Returns the conversationId and the token to use henceforth."""
        resp = requests.post(
            f"{directline_base}/v3/directline/conversations",
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        conv_id = data.get("conversationId")
        if not conv_id:
            raise RuntimeError(f"start conversation returned no conversationId: {json.dumps(data)[:300]}")
        # The token returned here is the one authorized to post activities.
        return {"conversation_id": conv_id, "token": data.get("token") or token}

    def _send_activity(
        self,
        directline_base: str,
        conv_id: str,
        token: str,
        user_id: str,
        text: str,
        locale: str,
        activity_type: str,
        timeout: float,
    ) -> None:
        activity: Dict[str, Any] = {
            "type": activity_type,
            "from": {"id": user_id},
            "locale": locale,
        }
        if activity_type == "message":
            activity["text"] = text
            activity["textFormat"] = "plain"
        else:
            # event activities (e.g. startConversation) carry a name, not text
            activity["name"] = text
        resp = requests.post(
            f"{directline_base}/v3/directline/conversations/{conv_id}/activities",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=activity,
            timeout=timeout,
        )
        resp.raise_for_status()

    def _get_activities(
        self, directline_base: str, conv_id: str, token: str, watermark: Optional[str], timeout: float
    ) -> Dict[str, Any]:
        url = f"{directline_base}/v3/directline/conversations/{conv_id}/activities"
        params = {"watermark": watermark} if watermark else {}
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def _drain(
        self, directline_base: str, conv_id: str, token: str, watermark: Optional[str], timeout: float
    ) -> Optional[str]:
        """Advance the watermark past whatever is currently buffered (used to discard the greeting)."""
        data = self._get_activities(directline_base, conv_id, token, watermark, timeout)
        return data.get("watermark") or watermark

    def _poll_reply(
        self,
        directline_base: str,
        conv_id: str,
        token: str,
        user_id: str,
        watermark: Optional[str],
        poll_interval: float,
        bot_settle: float,
        deadline: float,
        timeout: float,
    ) -> str:
        """Poll GET /activities, collect bot message turns, return concatenated text."""
        collected: List[str] = []
        first_bot_ts: Optional[float] = None

        while True:
            now = time.time()
            if now >= deadline:
                break

            data = self._get_activities(directline_base, conv_id, token, watermark, timeout)
            new_watermark = data.get("watermark")
            if new_watermark:
                watermark = new_watermark

            for act in data.get("activities", []):
                if act.get("type") != "message":
                    continue
                from_id = (act.get("from") or {}).get("id")
                if from_id == user_id:
                    continue  # our own echo
                text = act.get("text")
                if text:
                    collected.append(text)
                    if first_bot_ts is None:
                        first_bot_ts = time.time()

            # Once the first bot activity has landed, keep polling briefly for
            # continuation activities in the same turn, then stop.
            if first_bot_ts is not None and (time.time() - first_bot_ts) >= bot_settle:
                break

            # Deadline-respecting sleep (never overshoot the bridge timeout).
            time.sleep(min(poll_interval, max(0, deadline - time.time())))

        return "\n\n".join(collected).strip()

    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()

        directline_base = config.get("directline_base", DEFAULT_DIRECTLINE_BASE).rstrip("/")
        user_id = config.get("user_id", "dl_redteam001")
        if not user_id.startswith("dl_"):
            user_id = f"dl_{user_id}"
        locale = config.get("locale", "en-US")
        timeout = config.get("timeout_ms", 60000) / 1000
        poll_interval = config.get("poll_interval_ms", 1000) / 1000
        bot_settle = config.get("bot_settle_ms", 1500) / 1000
        deadline = start + timeout

        warmup_message = config.get("warmup_message", "Hello")
        do_warmup = config.get("warmup", bool(warmup_message))

        try:
            token = self._mint_token(config, directline_base, timeout)
            conv = self._start_conversation(directline_base, token, timeout)
            conv_id, token = conv["conversation_id"], conv["token"]
            logger.info(f"CopilotStudio: conversation {conv_id}")

            watermark: Optional[str] = None

            if do_warmup:
                # Fire startConversation to force the greeting deterministically, then
                # send the warmup text and discard everything up to now.
                try:
                    self._send_activity(
                        directline_base, conv_id, token, user_id,
                        "startConversation", locale, "event", timeout,
                    )
                    if warmup_message:
                        self._send_activity(
                            directline_base, conv_id, token, user_id,
                            warmup_message, locale, "message", timeout,
                        )
                    time.sleep(min(poll_interval, max(0, deadline - time.time())))
                    watermark = self._drain(directline_base, conv_id, token, watermark, timeout)
                except requests.RequestException as e:
                    logger.warning(f"CopilotStudio warmup failed (continuing): {e}")

            self._send_activity(
                directline_base, conv_id, token, user_id, prompt, locale, "message", timeout,
            )

            response = self._poll_reply(
                directline_base, conv_id, token, user_id, watermark,
                poll_interval, bot_settle, deadline, timeout,
            )

            if not response:
                return self._fail(
                    "No bot reply received before deadline", start,
                    adapter="copilot_studio", conv_id=conv_id,
                )

            logger.info(f"CopilotStudio: got response ({len(response)} chars)")
            return self._ok(response, start, adapter="copilot_studio", conv_id=conv_id)

        except requests.HTTPError as e:
            body = ""
            try:
                body = e.response.text[:500]
            except Exception:
                pass
            code = getattr(e.response, "status_code", "?")
            logger.error(f"CopilotStudio HTTP {code}: {body}")
            return self._fail(f"HTTP {code}: {body}", start, adapter="copilot_studio")
        except Exception as e:
            logger.error(f"CopilotStudio adapter error: {e}", exc_info=True)
            return self._fail(str(e), start, adapter="copilot_studio")
