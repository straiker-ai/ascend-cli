"""
capture.py — live URL capture for `ascend discover --url`.

Drives a real browser (Playwright/Chromium), intercepts ALL network traffic
including WebSocket frames, opens the page's chat widget, sends one benign
message, and returns normalized evidence for the layer classifiers.

Why a real browser: bot-protected sites (Cloudflare/Akamai) reject plain HTTP
clients, and a HAR export loses WebSocket frames and redacts auth headers. A
real browser sees the true contract, already authenticated by the page itself.

Returns the same evidence shape as `classify.load_har`:
    {"pairs": [...], "ws_messages": [...]}
so the existing per-layer classifiers work unchanged.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

BENIGN_DEFAULT = "Hello, what can you help me with?"

# Requests that are never the chat call — analytics, ads, assets, session replay.
NOISE = re.compile(
    r"(datadog|segment\.|tiktok|snapchat|doubleclick|facebook|google-analytics|googletagmanager|"
    r"adobe|qualtrics|optimizely|newrelic|hotjar|mixpanel|amplitude|braze|rokt|invoca|bing\.com|"
    r"zetaglobal|boomtrain|zineone|cloud3\.|clarity\.ms|fullstory|heap|contentsquare|omtrdc\.net|demdex\.net|everesttech\.net|adobedc\.net|sc\.omtrdc|\.png|\.jpe?g|\.svg|\.css|\.woff2?|\.gif|\.ico|\.mp4|/fonts?/)", re.I)
# Requests that plausibly carry a chat turn. Used to RANK candidates, never to decide what gets
# recorded — see the capture filter below.
INTERESTING = re.compile(
    r"(chat|message|conversation|agent|assist|bot|ask|query|prompt|completion|graphql|api)", re.I)

# Static assets and telemetry: the only things safe to discard sight-unseen.
STATIC = re.compile(r"(\.png|\.jpe?g|\.svg|\.css|\.woff2?|\.gif|\.ico|\.mp4|\.webp|\.avif|"
                    r"\.ttf|\.eot|/fonts?/)", re.I)


def _worth_recording(url: str, method: str, resource_type: str = "") -> bool:
    """What the capture keeps.

    This used to be `NOISE.search(u) or not INTERESTING.search(u)` — i.e. a request was recorded
    ONLY if its URL contained one of a dozen guessed words. A discovery tool that can only see
    endpoints it already expects is not discovering anything: a real bot whose send endpoint was
    `/digital-session/…` had its one meaningful request thrown away before anyone looked at it, and
    the tool then reported "typed but not observed in traffic" and blamed the input box.

    So: keep everything that could carry a turn, and let classification decide afterwards. Only
    static assets and known telemetry are dropped without being seen.
    """
    if STATIC.search(url) or NOISE.search(url):
        return False
    if method in ("POST", "PUT", "PATCH"):
        return True                      # any body-carrying request can be the send
    if resource_type == "document":
        # ALWAYS keep the page itself. The same argument as above applies to the document and
        # was missed: a GET was kept only when its URL contained a guessed word, and the page
        # being captured is served from `/`, which contains none of them. So the one response
        # that bootstraps everything -- the CSRF token in a <meta> tag, the session cookie, the
        # inline config -- was discarded before classification ever saw it. Auth then classified
        # as "origin not in capture" and composed a csrf block with an empty bootstrap_url, which
        # the auth layer refuses outright. The evidence was there; the filter threw it away.
        return True
    return bool(INTERESTING.search(url))  # other GETs still need a reason to be kept

LAUNCHER_SELECTORS = [
    "button[aria-label*='chat' i]", "[data-testid*='chat' i]", "button[title*='chat' i]",
    "[aria-label*='virtual' i]", "[aria-label*='assistant' i]", "[id*='chat' i] button",
    "[class*='chat' i] button", "button:has-text('Chat')", "text=Chat with us",
    "text=Need help?", "[class*='launcher' i]", "[id*='launcher' i]",
]
CHATTY = re.compile(r"(chat|message|assistant|agent|ask|bot|conversation|support|help)", re.I)
SEARCHY = re.compile(r"(search|zip|postal|email|newsletter|subscribe|coupon|promo|login|password|store)", re.I)
SEND_BUTTONS = [
    "button[aria-label*='send' i]", "button[title*='send' i]", "[data-testid*='send' i]",
    "button[type='submit']", "button:has-text('Send')",
]
INPUT_SELECTORS = [
    "textarea", "input[type='text']", "[contenteditable='true']", "[role='textbox']",
    "input[placeholder*='type' i]", "textarea[placeholder*='message' i]",
    "input[placeholder*='message' i]", "input[placeholder*='ask' i]",
]
INPUT_WAIT_S = 20.0   # how long to keep looking for the chat input after the settle


async def _await_chat_input(page, scan, wait_s: float, notes: List[str], *, clock=None):
    """Poll for a usable chat input instead of trusting one fixed settle.

    A bot challenge (WAF / CDN interstitial) solves itself in the page and then RELOADS it; a
    widget inside an SPA mounts late. One scan straight after the settle looked at the
    interstitial, found no input, and the capture came back holding nothing but the page
    bootstrap while the real widget landed a second later. Seen live against a WAF-challenged
    range: the HAR had the challenge, the token cookie and the 200 reload, never the chat call.
    Re-scan every second until an input that is not a search box shows up or ``wait_s`` runs
    out. ``scan`` returns the scored candidates; a note records the wait and any navigation."""
    import time as _time
    now = clock or _time.monotonic
    url_before = getattr(page, "url", "") or ""
    deadline = now() + max(float(wait_s or 0), 0.0)
    polls = 0
    while True:
        found = await scan()
        polls += 1
        if any(c[0] >= 0 for c in found) or now() >= deadline:
            break
        await page.wait_for_timeout(1000)
    if polls > 1:
        moved = (getattr(page, "url", "") or "") != url_before
        notes.append(f"waited {polls - 1}s more for the chat input"
                     + (" (the page navigated meanwhile: bot challenge or redirect)" if moved else "")
                     + ("" if any(c[0] >= 0 for c in found) else " — none appeared"))
    return found


def _browser_channels(preferred=None):
    """Which browsers to try, best first.

    Real Chrome before bundled Chromium: it is the browser the operator already trusts, it carries
    normal fingerprints, and bot protection treats it far better than a freshly-downloaded
    automation build. `None` means Playwright's bundled Chromium.
    """
    if preferred and preferred != "auto":
        return [None] if preferred == "chromium" else [preferred, None]
    return ["chrome", "msedge", None]


def _pairs_from_har_file(path: str) -> List[Dict[str, Any]]:
    """HAR entries in the same shape the live response handler produces."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for e in (data.get("log", {}) or {}).get("entries", []):
        req = e.get("request", {}) or {}
        resp = e.get("response", {}) or {}
        content = resp.get("content", {}) or {}
        out.append({
            "request": {"method": req.get("method", "GET"), "url": req.get("url", ""),
                        "headers": req.get("headers", []),
                        "raw_body": (req.get("postData", {}) or {}).get("text")},
            "response": {"status": resp.get("status", 0), "headers": resp.get("headers", []),
                         "raw_body": content.get("text"),
                         "content_type": content.get("mimeType", "")},
        })
    return out


def _durable_har_path(url: str) -> str:
    """A HAR path under the per-credential state home, so EVERY browser run keeps its full session
    HAR for review — not a tempfile deleted the moment its pairs are folded in.

    The whole session (page bootstrap, the create-conversation call, auth headers) is the one
    artefact that survives a run, and re-driving a bot-protected widget is often impossible, so the
    HAR is worth keeping without the operator asking. It lands beside the evidence JSON in
    `ASCEND_HOME/captures/` and is chmod 0600 after Playwright writes it (it carries auth headers).
    Falls back to a tempfile only if the state home cannot be resolved (capture.py imported outside
    the CLI runtime, e.g. a unit test), so a capture never fails for want of a place to write.
    """
    import time as _time
    host = re.sub(r"[^a-z0-9]+", "-", (url.split("//", 1)[-1].split("/", 1)[0] or "capture").lower()).strip("-") or "capture"
    stamp = _time.strftime("%Y%m%d-%H%M%S")
    try:
        import tenant as _tenant  # runtime module; on the path only under the CLI runtime
        d = _tenant.ASCEND_HOME / "captures"
        d.mkdir(parents=True, exist_ok=True)
        return str(d / f"{host}-{stamp}.har")
    except Exception:
        import tempfile
        fd, p = tempfile.mkstemp(suffix=".har", prefix=f"ascend-capture-{host}-")
        os.close(fd)
        return p


def _augment_pairs_from_har(pairs: List[Dict[str, Any]], har_path: Optional[str],
                            notes: List[str]) -> None:
    """Fold the driven session's OWN recorded HAR into the evidence — including the page bootstrap
    (GET documents/inline scripts the live filter skips) where widget config like a Salesforce ESW
    bootstrap lives. The browser was just open; there is no reason to open it a second time or ask
    the operator to save a HAR by hand (owner, 2026-09-26). Best-effort; a HAR problem is never
    fatal to a capture that already has live pairs."""
    if not har_path or not os.path.exists(har_path):
        return
    try:
        seen = {(p.get("request", {}).get("method"), p.get("request", {}).get("url")) for p in pairs}
        added = 0
        for hp in _pairs_from_har_file(har_path):
            key = (hp["request"]["method"], hp["request"]["url"])
            if key not in seen:
                pairs.append(hp)
                seen.add(key)
                added += 1
        if added:
            notes.append(f"recorded the session HAR and read {added} more request(s) from it, "
                         f"including the page bootstrap — no second capture needed")
    except Exception:
        pass
    finally:
        # KEEP the HAR — it is the full session, saved for review. It carries auth headers, so it
        # is locked to the owner like every other captured artefact (best-effort). Said in a note,
        # so every caller that prints capture notes tells the operator where it is.
        try:
            os.chmod(har_path, 0o600)
        except Exception:
            pass
        notes.append(f"HAR saved for review: {har_path}")


# The page's own view of a streamed reply. Playwright hands back neither the body of a
# text/event-stream response nor its HAR text (both measured empty on the SSE lab widget), so the
# derived config was a bare {"format": "sse"} with the field mapping left to the adapter's
# defaults. This tees every streamed fetch body inside the page and keeps the text; EventSource
# messages are kept too. Read back with _collect_streams before the context closes.
STREAM_HOOK_JS = """
(() => {
  if (window.__ascendStreams) return;
  const streams = window.__ascendStreams = [];
  const keep = (rec, chunk) => { if (rec.text.length < 200000) rec.text += chunk; };
  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = async function(input, init) {
      const res = await origFetch.apply(this, arguments);
      try {
        const ct = (res.headers && res.headers.get('content-type')) || '';
        if (res.body && (ct.includes('event-stream') || ct.includes('ndjson'))) {
          const url = (typeof input === 'string') ? input : ((input && input.url) || '');
          const method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
          const rec = {url: new URL(url, location.href).href, method, status: res.status, text: ''};
          streams.push(rec);
          const [forPage, forUs] = res.body.tee();
          (async () => {
            const reader = forUs.getReader(); const dec = new TextDecoder();
            try { while (true) { const {done, value} = await reader.read(); if (done) break; keep(rec, dec.decode(value, {stream: true})); } }
            catch (e) {}
          })();
          return new Response(forPage, {status: res.status, statusText: res.statusText, headers: res.headers});
        }
      } catch (e) {}
      return res;
    };
  }
  const OrigES = window.EventSource;
  if (OrigES) {
    window.EventSource = function(url, cfg) {
      const es = new OrigES(url, cfg);
      const rec = {url: new URL(String(url), location.href).href, method: 'GET', status: 200, text: ''};
      streams.push(rec);
      es.addEventListener('message', ev => keep(rec, 'data: ' + ev.data + '\\n\\n'));
      return es;
    };
    window.EventSource.prototype = OrigES.prototype;
  }
})();
"""


async def _collect_streams(page) -> List[Dict[str, Any]]:
    """The streamed bodies the hook kept, from the page and every frame. Never raises."""
    out: List[Dict[str, Any]] = []
    for fr in [page] + list(getattr(page, "frames", []) or []):
        try:
            recs = await fr.evaluate("() => (window.__ascendStreams || []).map(r => ({url: r.url, method: r.method, status: r.status, text: r.text.slice(0, 20000)}))")
            out.extend(r for r in (recs or []) if isinstance(r, dict))
        except Exception:
            continue
    return out


def _fill_streamed_bodies(pairs: List[Dict[str, Any]], streams: List[Dict[str, Any]],
                          notes: List[str]) -> int:
    """Give a streamed pair its body from the page hook. Matches on method and URL (the hook
    records absolute URLs); only a pair whose recorded body is empty is touched."""
    if not streams:
        return 0
    filled = 0
    for pr in pairs:
        resp = pr.get("response") or {}
        ct = (resp.get("content_type") or "").lower()
        if resp.get("raw_body") or not ("event-stream" in ct or "ndjson" in ct):
            continue
        req = pr.get("request") or {}
        for rec in streams:
            if rec.get("text") and rec.get("url") == req.get("url") and \
                    (rec.get("method") or "").upper() == (req.get("method") or "").upper():
                resp["raw_body"] = rec["text"][:20000]
                filled += 1
                break
    if filled:
        notes.append(f"read {filled} streamed reply body(ies) from the page (SSE/NDJSON bodies are not in the HAR)")
    return filled


async def _capture_async(url: str, *, prompt: str, headless: bool, timeout_s: int,
                         settle_s: int, manual: bool = False, manual_wait_s: int = 180,
                         input_wait_s: float = INPUT_WAIT_S,
                         extra_headers: Optional[Dict[str, str]] = None,
                         proxy: Optional[str] = None, insecure: bool = False,
                         browser_channel: Optional[str] = None,
                         cdp: Optional[str] = None) -> Dict[str, Any]:
    try:
        from playwright.async_api import async_playwright
    except ImportError as e:  # pragma: no cover - env dependent
        raise RuntimeError("playwright not installed: pip install playwright && playwright install chromium") from e

    pairs: List[Dict[str, Any]] = []
    ws_messages: List[Dict[str, Any]] = []
    notes: List[str] = []
    recipe: Dict[str, Any] = {}
    _har_path: Optional[str] = None

    async with async_playwright() as pw:
        launch_kw = {"headless": headless,
                     "args": ["--disable-blink-features=AutomationControlled"]}
        if proxy:
            launch_kw["proxy"] = {"server": proxy}
        if not headless:
            # A window sized to the display, not to a fixed viewport. The widget lives in the
            # bottom-right corner, so a viewport taller than the screen pushed the compose box off
            # the bottom — in --manual mode that means the operator cannot type, which defeats the
            # entire point of the mode.
            launch_kw["args"].append("--start-maximized")

        # Prefer the REAL browser the machine already has. Bundled Chromium announces itself as
        # automation in ways bot protection notices, and it is not the browser the operator sees
        # every day. `channel` drives the installed Chrome/Edge instead; we fall back to the
        # bundled build only when neither is present.
        browser, chosen = None, None
        if cdp:
            # Attach to a browser the operator is ALREADY signed into (started with
            # `chrome --remote-debugging-port=9222`). This is the only route into an Entra / SAML /
            # WS-Fed gated target: there is no credential a CLI can be handed, the session lives in
            # that browser, and a fresh Chromium launched here stops at the login wall and never
            # sees the widget. The runtime adapter attaches the same way (browser.py `cdp_url`),
            # so what the capture proves is what the assessment runs.
            endpoint = cdp if str(cdp).startswith("http") else f"http://127.0.0.1:{cdp}"
            browser = await pw.chromium.connect_over_cdp(endpoint)
            chosen = f"attached over CDP at {endpoint}"
        for channel in ([] if browser else _browser_channels(browser_channel)):
            try:
                browser = await pw.chromium.launch(channel=channel, **launch_kw) if channel \
                    else await pw.chromium.launch(**launch_kw)
                chosen = channel or "chromium (bundled)"
                break
            except Exception:
                continue
        if browser is None:
            raise RuntimeError(
                "no usable browser: install Google Chrome, or run "
                "`playwright install chromium` for the bundled build")
        notes.append(f"browser: {chosen}")

        ctx_kw = {
            "user_agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
            "locale": "en-US",
            "ignore_https_errors": bool(insecure),
        }
        # Headed: let the window BE the viewport so nothing is clipped and the operator can resize.
        # Headless: a fixed viewport keeps captures reproducible.
        if headless:
            ctx_kw["viewport"] = {"width": 1400, "height": 950}
        else:
            ctx_kw["no_viewport"] = True
        if extra_headers:
            ctx_kw["extra_http_headers"] = extra_headers
        # Record the WHOLE session as a HAR (bodies embedded). Playwright writes it when the
        # context closes; we read the bootstrap out of it below. Only for a context WE create — an
        # attached CDP browser's context cannot be given a recorder after the fact.
        if not cdp:
            _har_path = _durable_har_path(url)
            ctx_kw["record_har_path"] = _har_path
            ctx_kw["record_har_content"] = "embed"
            ctx_kw["record_har_mode"] = "full"
        # Optional: record a video of the browser as it drives itself (for demos / auditing).
        # Uses Playwright's built-in viewport recorder — no OS screen-recording permission needed.
        _viddir = os.environ.get("ASCEND_CAPTURE_VIDEO_DIR")
        if _viddir:
            os.makedirs(_viddir, exist_ok=True)
            ctx_kw["record_video_dir"] = _viddir
            ctx_kw["record_video_size"] = {"width": 1400, "height": 950}
        if cdp and browser.contexts:
            # The signed-in session is IN the existing context. A new context is a clean profile
            # with no cookies, which would defeat the reason for attaching at all.
            ctx = browser.contexts[0]
        else:
            ctx = await browser.new_context(**ctx_kw)
        try:
            await ctx.add_init_script(STREAM_HOOK_JS)
        except Exception:
            pass                          # an attached context may refuse; the capture still works
        page = await ctx.new_page()
        streams: List[Dict[str, Any]] = []

        async def on_response(resp):
            try:
                req = resp.request
                u = req.url
                if req.method not in ("POST", "GET", "PUT", "PATCH"):
                    return
                if not _worth_recording(u, req.method,
                                        getattr(req, "resource_type", "") or ""):
                    return
                body = None
                ct = (resp.headers or {}).get("content-type", "")
                if any(t in ct for t in ("json", "text", "event-stream", "ndjson")):
                    try:
                        # A streamed body (text/event-stream, NDJSON) is NOT available here, nor
                        # in the HAR: MEASURED, both come back empty. It is read by the page hook
                        # (STREAM_HOOK_JS) and folded in by _fill_streamed_bodies below.
                        body = (await resp.text())[:20000]
                    except Exception:
                        body = None
                # The headers the browser actually SENT, not the ones the page's script set.
                # `request.headers` is the initial set and never includes Cookie; a widget whose
                # access is a cookie (set by the page, sent by the browser) therefore captured with
                # no credential at all, and the replay 401'd. MEASURED on a gated lab widget.
                try:
                    sent = await req.all_headers()
                except Exception:
                    sent = req.headers or {}
                pairs.append({
                    "request": {
                        "method": req.method, "url": u,
                        "headers": [{"name": k, "value": v} for k, v in (sent or {}).items()],
                        "raw_body": (req.post_data or None),
                    },
                    "response": {
                        "status": resp.status,
                        "headers": [{"name": k, "value": v} for k, v in (resp.headers or {}).items()],
                        "raw_body": body,
                        "content_type": ct,
                    },
                })
            except Exception:
                pass

        pending_tasks: List[Any] = []

        def _track(r):
            # Keep a handle: these were fire-and-forget, so browser.close() could run
            # while `await resp.text()` was still in flight and the pair was silently
            # dropped by the bare except below. Intermittent "capture delivered nothing".
            t = asyncio.create_task(on_response(r))
            pending_tasks.append(t)

        page.on("response", _track)

        def on_ws(ws):
            rec = {"url": ws.url, "sent": [], "received": []}
            ws_messages.append(rec)
            ws.on("framesent", lambda p: rec["sent"].append(
                str(p.get("payload") if isinstance(p, dict) else p)[:4000]))
            ws.on("framereceived", lambda p: rec["received"].append(
                str(p.get("payload") if isinstance(p, dict) else p)[:4000]))

        page.on("websocket", on_ws)

        nav_failed = False
        nav_diag: Dict[str, str] = {}
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_s * 1000)
        except Exception as e:
            nav_failed = True
            nav_diag = diagnose_browser_failure(e, url)   # DNS / refused / timeout / bot-wall
            notes.append(f"navigation issue: {nav_diag.get('message', e)}")
        await page.wait_for_timeout(settle_s * 1000)

        if manual:
            notes.append("MANUAL MODE — drive the widget yourself; recording all traffic")
            print("\n" + "=" * 68, flush=True)
            print("  MANUAL CAPTURE", flush=True)
            print(f"  1. In the browser window, open the chat widget", flush=True)
            print(f"  2. Type EXACTLY this prompt and send it:", flush=True)
            print(f"       {prompt}", flush=True)
            print(f"  3. Wait for the bot to reply, then leave the window alone.", flush=True)
            print(f"  Recording for up to {manual_wait_s}s (Ctrl-C when done).", flush=True)
            print("=" * 68 + "\n", flush=True)
            waited = 0
            while waited < manual_wait_s:
                await page.wait_for_timeout(2000)
                waited += 2
                if any(prompt.strip() in (pr["request"].get("raw_body") or "") for pr in pairs) or \
                   any(prompt.strip() in str(f) for w in ws_messages for f in (w.get("sent") or [])):
                    notes.append(f"prompt observed in traffic after {waited}s")
                    await page.wait_for_timeout(8000)   # let the reply land
                    break
            sent = True
            reply_text = None
            if pending_tasks:
                try:
                    await asyncio.wait(pending_tasks, timeout=10)
                except Exception:
                    pass
            streams = await _collect_streams(page)
            if not cdp:                       # flush the HAR: Playwright writes it on CONTEXT close;
                try:                          # this is our own context, never the operator's
                    await ctx.close()
                except Exception:
                    pass
            if not cdp:                       # never close the operator's own browser
                await browser.close()
            _augment_pairs_from_har(pairs, _har_path, notes)
            _fill_streamed_bodies(pairs, streams, notes)

            def _in_traffic_m(needle):
                if not needle: return False
                for pr in pairs:
                    if needle in (pr["request"].get("raw_body") or ""): return True
                for w in ws_messages:
                    if any(needle in str(f) for f in (w.get("sent") or [])): return True
                return False
            verified_m = _in_traffic_m(prompt.strip())
            if not verified_m:
                notes.append("NO PROMPT SENT — manual capture timed out without seeing the prompt")
            return {"pairs": pairs, "ws_messages": ws_messages, "notes": notes,
                    "prompt_sent": prompt if verified_m else None,
                    "send_attempted": True, "send_verified": verified_m,
                    "reply_text": None, "url": url,
                    "har_path": _har_path if _har_path and os.path.exists(_har_path) else None}

        # ---- consent / cookie gate first ---------------------------------------
        # A banner that has to be accepted before the widget mounts (often the chat iframe is
        # only injected after acceptance). Same list the browser adapter replays per session.
        # Let the page paint first: headful, the banner was not visible yet when this ran.
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        await page.wait_for_timeout(800)
        try:
            from consent import selectors as _consent_selectors  # noqa: PLC0415  (runtime/ on sys.path under the CLI)
        except ImportError:
            from runtime.consent import selectors as _consent_selectors  # noqa: PLC0415
        for target in [page] + list(page.frames):
            if recipe.get("consent"):
                break
            for sel in _consent_selectors():
                try:
                    el = target.locator(sel).first
                    if await el.count() and await el.is_visible():
                        await el.click(timeout=4000)
                        notes.append(f"dismissed consent gate via {sel}")
                        recipe["consent"] = sel
                        await page.wait_for_timeout(2500)   # the widget frame mounts after acceptance
                        break
                except Exception:
                    continue

        # ---- open the widget -------------------------------------------------
        # Widgets live in the page, in shadow DOM, or in a cross-origin iframe. Try the
        # main frame first, then every child frame.
        opened = False
        for target in [page] + list(page.frames):
            if opened:
                break
            for sel in LAUNCHER_SELECTORS:
                try:
                    el = target.locator(sel).first
                    if await el.count() and await el.is_visible():
                        await el.click(timeout=4000)
                        notes.append(f"clicked launcher {sel}")
                        recipe["launcher"] = sel
                        opened = True
                        await page.wait_for_timeout(4000)
                        break
                except Exception:
                    continue
        if not opened:
            notes.append("no launcher matched (widget may auto-open or be inside an iframe)")

        # give a lazily-injected widget iframe time to appear
        await page.wait_for_timeout(3000)

        # ---- find the REAL chat input ----------------------------------------
        # Scoring beats first-match: a site search box also matches "input[type=text]".
        # Prefer inputs that look like chat, sit inside a chat-ish container, or live in
        # a frame whose URL looks like a chat vendor.
        async def score_input(fr, loc, sel) -> float:
            score = 0.0
            try:
                if "textarea" in sel or "contenteditable" in sel or "textbox" in sel:
                    score += 2.0
                ph = (await loc.get_attribute("placeholder") or "").lower()
                aria = (await loc.get_attribute("aria-label") or "").lower()
                name = (await loc.get_attribute("name") or "").lower()
                idv = (await loc.get_attribute("id") or "").lower()
                blob = " ".join([ph, aria, name, idv])
                if CHATTY.search(blob):
                    score += 5.0
                if SEARCHY.search(blob):
                    score -= 6.0          # a site search box, not the bot
                furl = getattr(fr, "url", "") or ""
                if fr is not page and CHATTY.search(furl):
                    score += 4.0          # inside a chat vendor iframe
            except Exception:
                pass
            return score

        async def scan_inputs():
            found = []
            for fr in [page] + list(page.frames):
                for sel in INPUT_SELECTORS:
                    try:
                        loc = fr.locator(sel).first
                        if await loc.count() and await loc.is_visible():
                            found.append((await score_input(fr, loc, sel), fr, loc, sel))
                    except Exception:
                        continue
            found.sort(key=lambda c: c[0], reverse=True)
            return found

        # not one scan on a fixed settle: a bot challenge reloads the page, a widget mounts late
        candidates = await _await_chat_input(page, scan_inputs, input_wait_s, notes)

        sent = False
        for score, fr, loc, sel in candidates:
            if score < 0:
                continue                  # never type into something that looks like search
            try:
                await loc.click(timeout=3000)
                await loc.fill(prompt)
                await page.wait_for_timeout(400)
                # a STABLE selector for this exact input (id/name beats the generic match, so the
                # browser adapter re-finds the real chat box, not a hidden recaptcha textarea)
                recipe["input_selector"] = await _stable_selector(loc, sel)
                recipe["input_frame_url"] = "" if fr is page else (getattr(fr, "url", "") or "")
                recipe["send"] = "enter"
                await loc.press("Enter")
                await page.wait_for_timeout(2500)
                # If Enter didn't submit, try an explicit send button near the input.
                for bsel in SEND_BUTTONS:
                    try:
                        b = fr.locator(bsel).first
                        if await b.count() and await b.is_visible():
                            await b.click(timeout=2500)
                            notes.append(f"clicked send button {bsel}")
                            recipe["send"] = bsel
                            break
                    except Exception:
                        continue
                recipe["input_fr"] = fr           # kept in-process for reply derivation; stripped below
                notes.append(f"typed prompt via {sel} (score={score:.1f}, frame="
                             f"{'main' if fr is page else (getattr(fr,'url','') or '')[:60]})")
                sent = True
                break
            except Exception:
                continue
        if not sent:
            # The site root is usually a landing page: the widget lives on a page of its own. Seen
            # live: a drive at `/` (the operator had given `/rest`) captured the bootstrap and nothing else.
            root = not urlsplit(url).path.strip("/")
            notes.append("no chat input found — capture may only contain page bootstrap"
                         + (" (this is the site root: if the chat lives on a specific page, capture that page's URL)" if root else ""))

        # ---- try to read the bot's reply back off the page -------------------
        reply_text = None
        await page.wait_for_timeout(6000)
        if sent:
            for fr in [page] + list(page.frames):
                try:
                    body = await fr.locator("body").first.inner_text(timeout=3000)
                except Exception:
                    continue
                if body and prompt in body:
                    tail = body.split(prompt, 1)[1].strip()
                    tail = "\n".join([ln for ln in tail.splitlines() if ln.strip()][:6]).strip()
                    if tail:
                        reply_text = tail[:600]
                        break
            # derive the reply-container selector from the DOM (for the browser adapter), in the
            # frame where the input lives
            try:
                ifr = recipe.pop("input_fr", None) or page
                await _derive_reply_recipe(ifr, prompt, reply_text, recipe)
            except Exception:
                recipe.pop("input_fr", None)

        await page.wait_for_timeout(settle_s * 2000)
        if pending_tasks:
            try:
                await asyncio.wait(pending_tasks, timeout=10)
            except Exception:
                pass
        streams = await _collect_streams(page)
        if not cdp:                       # flush the HAR: Playwright writes it on CONTEXT close;
            try:                          # this is our own context, never the operator's
                await ctx.close()
            except Exception:
                pass
        if not cdp:                       # never close the operator's own browser
            await browser.close()

    _augment_pairs_from_har(pairs, _har_path, notes)
    _fill_streamed_bodies(pairs, streams, notes)

    # HARD VERIFICATION: typing into a box proves nothing — the prompt must appear in
    # real traffic. Two silent failure modes this catches: (a) we typed into a site
    # search box instead of the chat widget, (b) the widget never actually submitted.
    def _in_traffic(needle: str) -> bool:
        if not needle:
            return False
        for pr in pairs:
            if needle in (pr["request"].get("raw_body") or ""):
                return True
        for w in ws_messages:
            if any(needle in str(f) for f in (w.get("sent") or [])):
                return True
        return False

    verified = _in_traffic(prompt.strip())
    if sent and not verified:
        notes.append("TYPED BUT NOT OBSERVED IN TRAFFIC — the input we typed into was "
                     "probably not the chat widget (e.g. a site search box)")
    if not sent:
        notes.append("NO PROMPT SENT — capture contains only page bootstrap")

    recipe.pop("input_fr", None)
    result = {"pairs": pairs, "ws_messages": ws_messages, "notes": notes,
              "prompt_sent": prompt if verified else None,
              "send_attempted": sent, "send_verified": verified,
              "reply_text": reply_text, "url": url,
              "har_path": _har_path if _har_path and os.path.exists(_har_path) else None,
              "browser_recipe": recipe if recipe.get("input_selector") else None}
    if nav_failed and not verified and nav_diag:
        # surface the real cause (DNS/refused/timeout/bot-wall) instead of a generic stop
        result.update(nav_diag)
    return result


async def _stable_selector(loc, fallback: str) -> str:
    """A selector that re-finds THIS exact input later.

    Prefer #id, then a scoped [name=], then a placeholder/aria match — anything more specific than
    the generic "textarea" that also matches a hidden recaptcha field. Falls back to the generic
    selector that matched during capture.
    """
    try:
        idv = await loc.get_attribute("id")
        if idv and not any(c in idv for c in " .:>[]"):
            return f"#{idv}"
    except Exception:
        pass
    for attr in ("name", "data-testid", "aria-label", "placeholder"):
        try:
            v = await loc.get_attribute(attr)
            if v:
                tag = "textarea" if "textarea" in fallback else "input"
                return f'{tag}[{attr}="{v}"]'
        except Exception:
            continue
    return fallback


async def _derive_reply_recipe(fr, prompt, reply_text, recipe) -> None:
    """Find where the bot's reply rendered and record a container/text selector + user-echo filter.

    Uses the reply text we already read: locate the deepest element containing it, then climb to the
    nearest ancestor whose class looks like a message bubble. Records the container selector (by a
    class token), the text selector, and — if user and bot share the bubble class — a token that
    marks the USER bubble so the adapter can exclude the echo.
    """
    if not reply_text:
        return
    needle = reply_text.split("\n", 1)[0][:60]
    if not needle:
        return
    js = r"""(needle) => {
      const hit = [...document.querySelectorAll('*')].find(
        el => el.children.length <= 3 && (el.innerText||'').includes(needle));
      if (!hit) return null;
      // climb to a 'message/bubble/chat' container
      let node = hit, container = null;
      for (let i = 0; i < 6 && node; i++, node = node.parentElement) {
        const c = (node.className || '').toString().toLowerCase();
        if (/message|bubble|msg|chat-|response|turn/.test(c)) { container = node; break; }
      }
      const pick = (el) => {
        const cls = (el.className||'').toString().trim().split(/\s+/)
          .filter(c => /message|bubble|msg|response|turn/i.test(c) && !/wrapper|list|container/i.test(c));
        return cls[0] || null;
      };
      const token = container ? pick(container) : null;
      // does a sibling with the SAME token hold the USER's prompt? then find the user-only token
      let userToken = null;
      if (token) {
        for (const el of document.querySelectorAll('.' + CSS.escape(token))) {
          if ((el.innerText||'').includes(needle)) continue;
          const utoks = (el.className||'').toString().trim().split(/\s+/)
            .filter(c => /user|self|out(going)?|sent|right/i.test(c));
          if (utoks.length) { userToken = utoks[0]; break; }
        }
      }
      return {token, userToken, tag: (hit.tagName||'').toLowerCase()};
    }"""
    try:
        info = await fr.evaluate(js, needle)
    except Exception:
        info = None
    if not info or not info.get("token"):
        # robust generic fallback: any message-ish element, newest wins
        recipe["reply_container"] = "[class*='message'], [class*='bubble'], [class*='chat']"
        recipe["reply_strategy"] = "text_settle"
        return
    token = info["token"]
    container = f".{token}"
    if info.get("userToken"):
        container = f".{token}:not(.{info['userToken']})"   # exclude the user echo
    recipe["reply_container"] = container
    recipe["reply_strategy"] = "new_element"


def capture_diagnosis(ev: Dict[str, Any], url: str = "") -> Dict[str, str]:
    """What a failed capture means, as {reason, detail, next} — read off the notes the drive
    left. One reason each; the first that matches wins, most specific first."""
    notes = [str(n) for n in (ev or {}).get("notes", [])]
    text = "\n".join(notes)
    if (ev or {}).get("diagnosis") and isinstance(ev["diagnosis"], dict):
        return ev["diagnosis"]
    if "this is the site root" in text:
        return {"reason": "site_root_no_widget",
                "detail": "the drive was at the site root and found no chat input; the widget lives on a page of its own",
                "next": "capture the exact page URL that shows the chat widget (keep its path and query); do not retry the root"}
    if "no chat input found" in text:
        return {"reason": "no_chat_input",
                "detail": "the page rendered but no visible chat input was found within the wait",
                "next": "open the page yourself to see where the widget is; if it needs a click to appear, use --manual once; if it loads slowly, raise --settle"}
    if "TYPED BUT NOT OBSERVED IN TRAFFIC" in text:
        return {"reason": "typed_not_observed",
                "detail": "text was typed into an input but never appeared in any request: that box was not the chat widget (a site search, a form)",
                "next": "capture the page whose input is the chat box, or drive it with --manual once so the real send is recorded"}
    if "navigation issue" in text:
        return {"reason": "navigation_failed", "detail": notes[0] if notes else "the page did not load",
                "next": "fix reachability first (DNS, VPN, the bot wall): a plain probe of the URL says which"}
    if "MANUAL MODE" in text and "NO PROMPT SENT" in text:
        return {"reason": "manual_no_send",
                "detail": "manual mode waited for a message and none was sent in the browser",
                "next": "someone must type in the opened browser during manual mode; otherwise use the driven capture"}
    if "NO PROMPT SENT" in text:
        return {"reason": "no_prompt_sent", "detail": "the capture holds only the page bootstrap",
                "next": "capture the page that carries the widget; if a consent gate or login stands in front, deal with it first (--manual, or a login capture)"}
    return {"reason": "capture_unverified", "detail": "the prompt was not seen in the traffic",
            "next": "inspect the saved capture; pass a HAR of a real conversation with --har if you have one"}


def diagnose_browser_failure(exc: Exception, url: str) -> Dict[str, str]:
    """Turn a Playwright failure into something a human can act on.

    Bot protection (Akamai/Cloudflare/Kasada) commonly TERMINATES the browser session, and
    Playwright then reports "Target page, context or browser has been closed" — which tells
    the user nothing. Region-gated sites behave the same way.
    """
    msg = str(exc)
    low = msg.lower()
    # A LOCAL / private-network target cannot be behind Akamai/Cloudflare/Kasada — so never blame
    # bot protection for one. A crash there is a real browser/launch problem, and saying "bot
    # protection" sends the operator down a wrong path (it did, on localhost).
    import re as _re
    host = ""
    m = _re.search(r"https?://([^/:]+)", url or "")
    if m:
        host = m.group(1).lower()
    is_local = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".local") \
        or _re.match(r"(10|127)\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.", host or "")
    if "has been closed" in low or "target closed" in low or "crashed" in low:
        if is_local:
            return {"diagnosis": "browser_crashed",
                    "message": f"the browser closed while loading {url} (a local target)",
                    "hint": ("a local address can't be behind bot protection, so this is a browser "
                             "or page-load problem, not a defence. Confirm the URL points at the "
                             "actual chat page (not a landing/marketing page), try --settle 20, or "
                             "--manual to drive it yourself.")}
        return {"diagnosis": "bot_protection",
                "message": f"the browser session was terminated while loading {url}",
                "hint": ("this is what Akamai/Cloudflare/Kasada style protection looks like, "
                         "and region-gated sites do it too. Try --manual (you drive a real "
                         "browser while we record), export a HAR yourself and use --har, or "
                         "if the target has an API use --api / --curl.")}
    if "timeout" in low:
        return {"diagnosis": "navigation_timeout",
                "message": f"{url} did not finish loading in time",
                "hint": "try --settle 20, or --manual if the page needs interaction first."}
    if "err_name_not_resolved" in low or "dns" in low:
        return {"diagnosis": "dns",
                "message": f"could not resolve the host for {url}",
                "hint": "check the URL, your DNS, or whether it needs a VPN."}
    return {"diagnosis": "browser_error", "message": msg[:200],
            "hint": "try --manual, or --har with a capture from your own browser."}


def capture_url(url: str, *, prompt: str = BENIGN_DEFAULT, headless: bool = False,
                timeout_s: int = 60, settle_s: int = 6, manual: bool = False,
                manual_wait_s: int = 180, extra_headers: Optional[Dict[str, str]] = None,
                input_wait_s: float = INPUT_WAIT_S,
                proxy: Optional[str] = None, insecure: bool = False,
                browser_channel: Optional[str] = None,
                cdp: Optional[str] = None) -> Dict[str, Any]:
    """Capture live evidence from a chat page. Returns classifier-ready evidence.

    manual=True opens the page and waits for YOU to drive the widget (type the prompt
    yourself) while every request/WebSocket frame is recorded. Use it when the widget
    is unreachable by automation, or when a customer prefers a human in the loop.

    extra_headers/proxy/insecure let the browser reach auth-gated or internal targets the
    same way the requests-based paths do (so `--url` behaves like `--api`).
    """
    try:
        return asyncio.run(_capture_async(url, prompt=prompt, headless=headless,
                                          timeout_s=timeout_s, settle_s=settle_s,
                                          manual=manual, manual_wait_s=manual_wait_s,
                                          input_wait_s=input_wait_s,
                                          cdp=cdp,
                                          extra_headers=extra_headers, proxy=proxy,
                                          insecure=insecure,
                                          browser_channel=browser_channel))
    except KeyboardInterrupt:
        # In manual mode we literally tell the user "Ctrl-C when done" — losing the whole
        # capture at that point would be the worst possible behaviour.
        return {"pairs": [], "ws_messages": [], "notes": ["interrupted by the operator"],
                "prompt_sent": None, "send_attempted": manual, "send_verified": False,
                "reply_text": None, "url": url, "diagnosis": "interrupted"}
    except Exception as exc:  # noqa: BLE001 - boundary: never leak a Playwright traceback
        d = diagnose_browser_failure(exc, url)
        return {"pairs": [], "ws_messages": [], "notes": [d["message"], d["hint"]],
                "prompt_sent": None, "send_attempted": False, "send_verified": False,
                "reply_text": None, "url": url, **d}
