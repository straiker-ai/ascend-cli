"""
session_poll — generic create → send → GET-poll adapter.

For the very common pattern where the reply is NOT in the send response: you
create a conversation (get an id), POST the user message to a per-conversation
endpoint, and then must POLL a transcript/messages endpoint (usually a GET)
until the agent's reply appears. Generalizes the hardcoded polling in
copilot_studio / amazon_connect / slack_direct into one templated adapter
(covers the "watermark / transcript polling" archetype).

Config:
  create:
    url            create-conversation endpoint
    method         default POST
    body           optional body ({{PROMPT}} allowed but usually empty)
    headers        optional
    extract        dot-path to the conversation id in the create response
                   (e.g. "conversation_id" / "id" / "data.session.id")
  send:
    url            per-conversation send endpoint; {{CONV}} is substituted
    method         default POST
    body           message body template with {{PROMPT}} (and {{CONV}})
    headers        optional
  poll:
    url            transcript/messages endpoint; {{CONV}} substituted
    method         default GET
    list_path      dot-path to the array of turns in the poll response
                   (default "messages")
    role_field     field on a turn holding its role/type (default "role")
    bot_roles      roles/types that mark an agent turn
                   (default ["assistant","bot","agent"])
    text_path      dot-path to the text inside a turn (default "text")
    interval_ms    poll interval (default 1000)
    timeout_ms     overall wait for a reply (default 30000)
    stability_ms   once a reply is seen, wait this long for it to stop
                   growing before returning (default 0 = return first hit)
  bootstrap        optional ORDERED list of {url, method, headers, body, required}
                   calls made before `create` (vendors that gate on a fixed sequence)
  headers          shared headers merged into every call
                   (a step whose Content-Type is x-www-form-urlencoded is form-encoded)
  timeout_ms       per-HTTP-call timeout (default 30000)
"""
import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from .base import BotAdapter
from .websocket_direct import _json_escape, _dot

logger = logging.getLogger(__name__)

DEFAULT_BOT_ROLES = ["assistant", "bot", "agent", "ai"]


def _encode(step, body):
    """Return requests kwargs honouring the step's Content-Type.

    Several major vendors speak form-urlencoded, not JSON; sending JSON to them
    silently fails. Encoding follows the step's declared Content-Type.
    """
    ctype = ""
    for k, v in (step.get("headers") or {}).items():
        if k.lower() == "content-type":
            ctype = str(v).lower()
    if "x-www-form-urlencoded" in ctype:
        return {"data": body}
    if "text/plain" in ctype and isinstance(body, str):
        return {"data": body}
    return {"json": body}


def _render(template: Any, prompt: str, conv: str) -> Any:
    s = json.dumps(template)
    s = s.replace("{{PROMPT}}", _json_escape(prompt)).replace("{{CONV}}", _json_escape(conv))
    return json.loads(s)


class SessionPollAdapter(BotAdapter):
    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        shared_headers = {"Content-Type": "application/json", **(config.get("headers") or {})}
        http_timeout = config.get("timeout_ms", 60000) / 1000
        create = config.get("create") or {}
        send = config.get("send") or {}
        poll = config.get("poll") or {}
        if not create.get("url") or not send.get("url") or not poll.get("url"):
            return self._fail("session_poll needs create.url, send.url and poll.url", start)

        def _headers(step):
            return {**shared_headers, **(step.get("headers") or {})}

        # run blocking requests in a thread so we don't block the loop
        loop = asyncio.get_event_loop()

        # 0. ordered bootstrap: some vendors require a fixed call sequence (ping ->
        # connect -> open -> rulesets) before a conversation may be created at all.
        for i, step in enumerate(config.get("bootstrap") or []):
            try:
                await loop.run_in_executor(None, lambda st=step: requests.request(
                    st.get("method", "POST").upper(), st["url"],
                    headers={**shared_headers, **(st.get("headers") or {})},
                    timeout=http_timeout,
                    **_encode(st, _render(st.get("body", {}), prompt, ""))))
            except requests.RequestException as e:
                if step.get("required", True):
                    return self._fail(f"bootstrap step {i} ({step.get('url')}) failed: {e}",
                                      start)
                logger.debug("optional bootstrap step %s failed: %s", i, e)

        # 1. create conversation
        try:
            cr = await loop.run_in_executor(None, lambda: requests.request(
                create.get("method", "POST").upper(), create["url"],
                headers=_headers(create), timeout=http_timeout,
                **_encode(create, _render(create.get("body", {}), prompt, ""))))
            cr.raise_for_status()
            conv = _dot(cr.json(), create.get("extract", "conversation_id"))
        except requests.RequestException as e:
            return self._fail(f"create failed: {e}", start,
                              status_code=getattr(getattr(e, "response", None), "status_code", None))
        except (ValueError, KeyError) as e:
            return self._fail(f"create response parse failed: {e}", start)
        if not conv:
            return self._fail(f"could not extract conversation id via '{create.get('extract','conversation_id')}'", start)
        conv = str(conv)

        # baseline: how many bot turns already exist (watermark) so we only take NEW replies
        baseline = await self._count_bot_turns(loop, poll, shared_headers, conv, http_timeout)

        # 2. send the message
        send_url = send["url"].replace("{{CONV}}", conv)
        try:
            sr = await loop.run_in_executor(None, lambda: requests.request(
                send.get("method", "POST").upper(), send_url,
                headers=_headers(send), timeout=http_timeout,
                **_encode(send, _render(send.get("body", {"message": "{{PROMPT}}"}),
                                        prompt, conv))))
            sr.raise_for_status()
        except requests.RequestException as e:
            return self._fail(f"send failed: {e}", start,
                              status_code=getattr(getattr(e, "response", None), "status_code", None),
                              conv=conv)

        # 3. poll for the new bot reply
        interval = poll.get("interval_ms", 1000) / 1000
        deadline = start + poll.get("timeout_ms", 60000) / 1000
        stability = poll.get("stability_ms", 0) / 1000
        last_text, last_change = None, None
        while time.time() < deadline:
            await asyncio.sleep(interval)
            turns = await self._bot_turns(loop, poll, shared_headers, conv, http_timeout)
            if len(turns) > baseline:
                text = turns[-1]
                if text != last_text:
                    last_text, last_change = text, time.time()
                if stability <= 0:
                    return self._ok(str(text).strip(), start, adapter="session_poll", conv=conv)
                if last_change and (time.time() - last_change) >= stability:
                    return self._ok(str(last_text).strip(), start, adapter="session_poll", conv=conv)
        if last_text is not None:
            return self._ok(str(last_text).strip(), start, adapter="session_poll", conv=conv, note="returned_on_timeout")
        return self._fail(f"no agent reply within {poll.get('timeout_ms',60000)}ms", start, conv=conv)

    async def _count_bot_turns(self, loop, poll, headers, conv, timeout) -> int:
        return len(await self._bot_turns(loop, poll, headers, conv, timeout))

    async def _bot_turns(self, loop, poll, headers, conv, timeout) -> List[str]:
        url = poll["url"].replace("{{CONV}}", conv)
        kw = {}
        if poll.get("body") is not None:
            # POST-as-GET: some transcript endpoints require a POST with a body
            kw = _encode(poll, _render(poll["body"], "", conv))
        try:
            r = await loop.run_in_executor(None, lambda: requests.request(
                poll.get("method", "GET").upper(), url,
                headers={**headers, **(poll.get("headers") or {})}, timeout=timeout, **kw))
            r.raise_for_status()
            data = r.json()
        except Exception:
            return []
        arr = _dot(data, poll.get("list_path", "messages"))
        if not isinstance(arr, list):
            return []
        role_field = poll.get("role_field", "role")
        bot_roles = [x.lower() for x in (poll.get("bot_roles") or DEFAULT_BOT_ROLES)]
        text_path = poll.get("text_path", "text")
        out = []
        for turn in arr:
            if not isinstance(turn, dict):
                continue
            role = str(turn.get(role_field, "")).lower()
            if role in bot_roles:
                t = _dot(turn, text_path)
                if t:
                    out.append(t)
        return out
