"""Prove a derived config reads the answer out of the capture it was derived from — offline.

Derivation picks one field as the answer (`response_path`, `stream.text_path`, a ws frame field).
When it picks wrong — the progress line instead of the reply, a status field, a fragment — the
config validates green against a live target (it gets *a* string back) and then scores every probe
against the wrong text. The capture already holds the reply the widget actually showed
(`reply_text`), so the strongest check costs no network and no live probe: replay the config's own
extraction over the captured response and see whether it reproduces that reply.

Design, because a false alarm is itself a regression:

* FAIL OPEN. Anything this cannot judge confidently — no captured reply, an adapter it does not
  model, an ambiguous match — returns ok. It only speaks when the derived field clearly does not
  read the captured answer, so a wiring that works today is never second-guessed.
* It REUSES the adapters' own extraction (`direct_api._extract`, `sse_stream` frame parsing,
  `websocket_direct._extract`), so what it checks is exactly what the adapter will do at runtime.
* It is NON-BLOCKING by contract: it returns a verdict; the caller decides whether to print it.
  Nothing here raises or exits.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


def _norm(text: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", (text or "").lower())


def _overlap(got: str, expected: str) -> float:
    """How much of the captured reply the extracted text accounts for, 0..1.

    Direction matters: the widget's rendered reply (`expected`) may be longer than the raw
    extracted string (markdown, appended UI text), and a correct field still reproduces the *words*
    of the reply. So the score is the share of the reply's words that appear, in order-free terms,
    in the extracted text — high when the field is right, near zero when it read a status line.
    """
    exp = _norm(expected)
    if not exp:
        return 1.0
    got_set = set(_norm(got))
    if not got_set:
        return 0.0
    hit = sum(1 for w in exp if w in got_set)
    return hit / len(exp)


def _chat_response(ev: Dict[str, Any], prompt: Optional[str]) -> Optional[Dict[str, Any]]:
    """The response half of the pair that carried the prompt — the one the reply came back on."""
    pairs = ev.get("pairs") or []
    prompt = (prompt or "").strip()
    best = None
    for p in pairs:
        req = p.get("request") or {}
        resp = p.get("response") or {}
        body = req.get("raw_body") or req.get("body") or ""
        if prompt and prompt[:80] in (body if isinstance(body, str) else str(body)):
            return resp
        if resp.get("raw_body") or resp.get("body"):
            best = resp            # fall back to the last pair with a body
    return best


def _text_from_stream(body: str, cfg: Dict[str, Any]) -> str:
    """Reassemble a captured SSE/NDJSON body exactly as sse_stream would."""
    try:
        from adapters.sse_stream import SSEStreamAdapter          # noqa: PLC0415
    except ImportError:
        from runtime.adapters.sse_stream import SSEStreamAdapter  # noqa: PLC0415

    class _Frozen:
        def __init__(self, text: str):
            self._lines = [ln.encode() for ln in text.splitlines()] + [b""]

        def iter_lines(self, decode_unicode=False):
            yield from self._lines

        def close(self):
            pass

        raw = None

    import time as _t
    stream_cfg = cfg.get("stream") or {k: cfg[k] for k in ("format", "text_path", "token_types",
                 "done_when", "type_path", "aggregate", "idle_ms") if k in cfg}
    text, _tr, _st = SSEStreamAdapter()._read_stream(_Frozen(body), stream_cfg, deadline=_t.time() + 5)
    return text or ""


def _text_from_ws(ev: Dict[str, Any], cfg: Dict[str, Any]) -> str:
    try:
        from adapters.websocket_direct import WebSocketAdapter          # noqa: PLC0415
    except ImportError:
        from runtime.adapters.websocket_direct import WebSocketAdapter  # noqa: PLC0415
    a = WebSocketAdapter()
    rpath = cfg.get("response_path")
    chunks: List[str] = []
    for m in ev.get("ws_messages") or []:
        for raw in m.get("received") or ([m["data"]] if m.get("data") else []):
            frame = a._decode(raw)
            if a._error_frame(frame):
                continue
            t = a._extract(frame, rpath)
            if t:
                chunks.append(t)
    return "".join(chunks) if cfg.get("aggregate") != "last" else (chunks[-1] if chunks else "")


def _text_from_json(resp: Dict[str, Any], cfg: Dict[str, Any]) -> Optional[str]:
    body = resp.get("json")
    if body is None:
        raw = resp.get("raw_body") or resp.get("body")
        if isinstance(raw, (dict, list)):
            body = raw
        elif isinstance(raw, str):
            import json as _j
            try:
                body = _j.loads(raw)
            except ValueError:
                return raw          # a plain-text bot: the raw body IS the answer
    if body is None:
        return None
    path = cfg.get("response_path")
    try:
        from adapters.direct_api import _extract          # noqa: PLC0415
    except ImportError:
        from runtime.adapters.direct_api import _extract  # noqa: PLC0415
    if not path:
        return None                # no path claimed: direct_api treats the raw text as the answer
    got = _extract(body, path)
    return got if isinstance(got, str) else ("" if got is None else str(got))


def verify_config(config: Dict[str, Any], ev: Dict[str, Any],
                  *, min_overlap: float = 0.34) -> Dict[str, Any]:
    """Does this config read the captured reply? {ok, reason, detail, next, field, overlap}.

    ok is True whenever the check cannot confidently say otherwise (fail open)."""
    reply = (ev.get("reply_text") or "").strip()
    adapter = config.get("adapter") or "direct_api"
    if not reply or len(_norm(reply)) < 3:
        return {"ok": True, "reason": "no_captured_reply",
                "detail": "no captured reply to check the field against", "checked": False}

    try:
        if adapter == "websocket_direct":
            got = _text_from_ws(ev, config)
            field = config.get("response_path") or "(heuristic)"
        elif adapter == "sse_stream":
            resp = _chat_response(ev, ev.get("prompt_sent"))
            body = (resp or {}).get("raw_body") or (resp or {}).get("body") or ""
            if not isinstance(body, str) or not body.strip():
                return {"ok": True, "reason": "no_stream_body",
                        "detail": "the streamed body was not captured; cannot check offline", "checked": False}
            got = _text_from_stream(body, config)
            field = (config.get("stream") or {}).get("text_path") or config.get("text_path") or "(heuristic)"
        elif adapter == "direct_api":
            resp = _chat_response(ev, ev.get("prompt_sent"))
            if resp is None:
                return {"ok": True, "reason": "no_response_captured",
                        "detail": "no response body in the capture to check against", "checked": False}
            got = _text_from_json(resp, config)
            if got is None:
                return {"ok": True, "reason": "unpathed_text",
                        "detail": "no response_path claimed; the raw text is taken as the answer", "checked": False}
            field = config.get("response_path") or "(raw text)"
        else:
            return {"ok": True, "reason": "adapter_not_modelled",
                    "detail": f"no offline check for adapter {adapter!r}", "checked": False}
    except Exception as exc:  # noqa: BLE001 — a check that errors must never block a wiring
        return {"ok": True, "reason": "check_errored",
                "detail": f"offline check could not run: {type(exc).__name__}", "checked": False}

    got = got or ""
    overlap = _overlap(got, reply)
    ok = overlap >= min_overlap
    out = {"ok": ok, "checked": True, "field": field, "adapter": adapter,
           "overlap": round(overlap, 2), "reply_words": len(_norm(reply))}
    if ok:
        out["reason"] = "reads_the_reply"
        out["detail"] = f"the field {field!r} reproduces the captured reply (overlap {out['overlap']})"
        return out
    out["reason"] = "wrong_field" if got.strip() else "empty_field"
    if got.strip():
        out["detail"] = (f"the field {field!r} does not reproduce the captured reply "
                         f"(overlap {out['overlap']}); it reads {got.strip()[:60]!r}, "
                         f"the widget showed {reply[:60]!r}")
        out["next"] = ("the derived answer field reads the wrong thing — a progress/status line or a "
                       "fragment. Set the field that carries the reply with ascend_adapter_patch "
                       "(response_path for JSON/websocket, stream.text_path for SSE), then re-check")
    else:
        out["detail"] = f"the field {field!r} extracts nothing from the captured response"
        out["next"] = ("the derived answer field extracts nothing from the captured reply. Set it to "
                       "the field that carries the answer with ascend_adapter_patch, then re-check")
    return out


def shape_fix(config: Dict[str, Any], ev: Dict[str, Any], capture_check: Optional[Dict[str, Any]],
              framework: Optional[Dict[str, Any]], *, min_overlap: float = 0.34) -> Dict[str, Any]:
    """Turn the envelope-shape hint into a VERIFIED correction, a suggestion, or nothing.

    Returns ``{config, fix, suggestion}``. ``config`` is the input unless a fix was applied.

    * The derived answer field failed its self-check and the shape names another path: that path
      is replayed over the captured reply exactly as the adapter would read it. If it reproduces
      the reply, the config is corrected and ``fix`` says from what, to what, and the overlap. If it
      does not, nothing is changed and ``suggestion`` carries the path with ``verified: False``.
    * Derivation found no answer field and nothing could be checked offline: ``suggestion`` only.
    * A field that passed its self-check is never touched; adapters whose answer field is not
      ``response_path`` (streams) are never touched. Nothing here raises.
    """
    out: Dict[str, Any] = {"config": config, "fix": None, "suggestion": None}
    path = (framework or {}).get("response_path")
    if not path or not isinstance(config, dict):
        return out
    adapter = config.get("adapter") or "direct_api"
    if adapter not in ("direct_api", "websocket_direct"):
        return out
    cc = capture_check or {}
    current = config.get("response_path")
    label = (framework or {}).get("framework") or "the response envelope"
    if cc.get("checked") and not cc.get("ok"):
        if current == path:
            return out
        candidate = dict(config)
        candidate["response_path"] = path
        try:
            vc = verify_config(candidate, ev, min_overlap=min_overlap)
        except Exception:  # noqa: BLE001
            vc = {"ok": False, "checked": False}
        if vc.get("checked") and vc.get("ok"):
            out["config"] = candidate
            out["fix"] = {"field": "response_path", "from": current, "to": path, "overlap": vc.get("overlap"),
                          "framework": label, "check": vc,
                          "why": (f"the derived field {current!r} does not reproduce the captured reply; the response is "
                                  f"shaped like {label}, whose reply sits at {path!r}, and that path does (overlap {vc.get('overlap')})")}
        else:
            out["suggestion"] = {"set": {"response_path": path}, "verified": False,
                                 "confidence": (framework or {}).get("confidence"),
                                 "why": (f"the derived field {current!r} does not reproduce the captured reply, and neither does the "
                                         f"{label} path {path!r} (overlap {vc.get('overlap')}); read the capture before patching")}
        return out
    if not current and not cc.get("checked"):
        out["suggestion"] = {"set": {"response_path": path}, "verified": False,
                             "confidence": (framework or {}).get("confidence"),
                             "why": f"derivation found no answer field; the response is shaped like {label}, whose reply usually sits at {path!r}"}
    return out
