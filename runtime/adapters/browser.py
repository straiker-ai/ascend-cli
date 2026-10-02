"""
Browser adapter — uses Playwright headless Chromium to interact with web chatbots.

For chatbots that have no direct API (e.g., Salesforce SCRT2 widgets, embedded chat UIs).
The adapter opens the chatbot in a headless browser, types the prompt, waits for the
bot response to appear in the DOM, and extracts it.

Maintains a persistent browser session so pre-actions (navigate, open chat widget)
only run once. Subsequent prompts reuse the open chat — just fill + send + wait.

Config keys:
  url              - Target URL to navigate to
  pre_actions      - List of actions to run before interacting (click, wait, dismiss_popup, etc.)
  iframe.selector  - CSS selector for chat widget iframe (null if no iframe)
  wait_for_widget  - Selector + timeout_ms to wait for chat input to be ready
  input.selector   - CSS selector for the chat input field
  send.method      - "click" or "enter"
  send.selector    - CSS selector for the send button (if method=click)
  response         - wait_strategy, container_selector, text_selector, timeout_ms, etc.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .base import BotAdapter

if TYPE_CHECKING:  # type hints only — the runtime import is lazy (see send_prompt)
    from playwright.async_api import Page, Frame, ElementHandle

logger = logging.getLogger(__name__)

def _sandbox_flags(config):
    """Chromium sandbox stays ON by default (we render adversarial target content).
    Opt out ONLY in a locked-down container via config or $ABV2_BROWSER_NO_SANDBOX=1."""
    import os
    if config.get("no_sandbox") or os.environ.get("ABV2_BROWSER_NO_SANDBOX") == "1":
        return ["--no-sandbox", "--disable-setuid-sandbox"]
    return []




class BrowserAdapter(BotAdapter):
    """Interact with a web chatbot via headless Chromium with session reuse."""

    def __init__(self):
        self._playwright = None
        self._browser = None
        self._page = None
        self._target = None  # Page or Frame (after iframe resolution)
        self._ready = False
        self._config = None
        self._cdp_attached = False  # when True, never close the user's real browser

    async def _ensure_session(self, config: Dict[str, Any]) -> None:
        """Launch browser and run pre-actions once. Subsequent calls are no-ops."""
        if self._ready and self._page and self._target:
            try:
                await self._page.title()
                return
            except Exception:
                logger.warning("Browser: session died, reinitializing")
                self._ready = False

        logger.info("Browser: initializing new session")
        self._config = config

        await self._cleanup()

        from playwright.async_api import async_playwright  # lazy: only needed for this adapter
        self._playwright = await async_playwright().start()
        cdp = config.get("cdp_url") or config.get("cdp")
        if cdp:
            # Attach to a REAL, human-warmed Chrome (already past Cloudflare/Akamai, already
            # logged in). Start it with: chrome --remote-debugging-port=9222. This is the
            # single most effective answer to bot-detection + OOPiF widgets.
            if isinstance(cdp, bool):
                endpoint = "http://127.0.0.1:9222"
            elif isinstance(cdp, int):
                endpoint = f"http://127.0.0.1:{cdp}"
            else:
                endpoint = cdp if str(cdp).startswith("http") else f"http://127.0.0.1:{cdp}"
            logger.info(f"Browser: attaching over CDP to {endpoint} (real, warmed session)")
            self._browser = await self._playwright.chromium.connect_over_cdp(endpoint)
            self._cdp_attached = True
            context = (self._browser.contexts[0] if self._browser.contexts
                       else await self._browser.new_context())
            self._page = context.pages[0] if context.pages else await context.new_page()
        else:
            self._browser = await self._playwright.chromium.launch(
                headless=config.get("headless", True),
                args=[*_sandbox_flags(config), "--disable-dev-shm-usage", "--disable-gpu"],
            )
            context = await self._browser.new_context(
                viewport={"width": 1280, "height": 900},
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/145.0.0.0 Safari/537.36"
                ),
            )
            self._page = await context.new_page()

        # Navigate unless we're reusing the warmed page as-is (cdp with no url).
        url = config.get("url")
        if url and not (cdp and config.get("use_current_page")):
            logger.info(f"Browser: navigating to {url}")
            await self._page.goto(url, wait_until="domcontentloaded", timeout=30000)

        await self._run_pre_actions(self._page, config.get("pre_actions", []))

        self._target = await self._resolve_frame(self._page, config.get("iframe"))

        widget_cfg = config.get("wait_for_widget", {})
        if widget_cfg.get("selector"):
            logger.info(f"Browser: waiting for widget {widget_cfg['selector']}")
            await self._target.wait_for_selector(
                widget_cfg["selector"],
                timeout=widget_cfg.get("timeout_ms", 15000),
            )

        self._ready = True
        logger.info("Browser: session ready — pre-actions complete, chat widget open")

    async def _cleanup(self):
        try:
            # Never close a CDP-attached browser — that's the user's real Chrome. Only
            # disconnect (drop our reference); Playwright's stop() releases the CDP link.
            if self._browser and not self._cdp_attached:
                await self._browser.close()
        except Exception:
            pass
        self._cdp_attached = False
        try:
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass
        self._browser = None
        self._playwright = None
        self._page = None
        self._target = None
        self._ready = False

    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()

        url = config.get("url")
        cdp = config.get("cdp_url") or config.get("cdp")
        if not url and not cdp:
            return self._fail("No url configured (or attach a warmed browser with "
                              "cdp_url + use_current_page)", start)
        try:
            import playwright.async_api  # noqa: F401  lazy: only needed for this adapter
        except ImportError:
            return self._fail(
                "The 'playwright' package is required for the browser adapter "
                "(pip install playwright && playwright install chromium).", start)

        try:
            await self._ensure_session(config)

            target = self._target
            resp_cfg = config.get("response", {})
            container_sel = resp_cfg.get("container_selector", "")

            pre_count = 0
            if container_sel:
                pre_elements = await target.query_selector_all(container_sel)
                pre_count = len(pre_elements)
                logger.info(f"Browser: {pre_count} existing messages")

            input_cfg = config.get("input", {})
            input_sel = input_cfg.get("selector", "textarea, input[type='text']")

            logger.info(f"Browser: entering prompt ({len(prompt)} chars)")
            input_el = await target.wait_for_selector(input_sel, timeout=10000)
            await input_el.click()
            await input_el.fill(prompt)

            send_cfg = config.get("send", {})
            send_method = send_cfg.get("method", "click")
            if send_method == "enter":
                await input_el.press("Enter")
            else:
                send_sel = send_cfg.get("selector", "button[type='submit'], button:has-text('Send')")
                send_btn = await target.wait_for_selector(send_sel, timeout=5000)
                await send_btn.click()

            logger.info("Browser: prompt sent, waiting for response")

            strategy = resp_cfg.get("wait_strategy", "new_element")
            timeout_ms = resp_cfg.get("timeout_ms", 30000)
            poll_ms = resp_cfg.get("poll_interval_ms", 500)

            response_text = await self._wait_for_response(
                target, resp_cfg, strategy, pre_count, timeout_ms, poll_ms
            )

            if not response_text:
                try:
                    debug_dir = Path(__file__).parent.parent / "debug_screenshots"
                    debug_dir.mkdir(exist_ok=True)
                    await self._page.screenshot(path=str(debug_dir / "timeout_failure.png"))
                except Exception:
                    pass
                return self._fail("Timed out waiting for bot response", start, adapter="browser")

            logger.info(f"Browser: got response ({len(response_text)} chars)")
            return self._ok(response_text.strip(), start, adapter="browser")

        except Exception as e:
            logger.error(f"Browser adapter error: {e}", exc_info=True)
            self._ready = False
            return self._fail(str(e), start, adapter="browser")

    async def _run_pre_actions(self, page: Page, actions: List[Dict]) -> None:
        """Execute pre-actions like clicking the chat icon or dismissing banners."""
        for action in actions:
            act = action.get("action")
            desc = action.get("description", "")
            logger.info(f"Browser pre-action: {desc}")

            try:
                if act == "click":
                    sel = action["selector"]
                    el = await page.wait_for_selector(sel, timeout=action.get("timeout_ms", 10000))
                    if el:
                        await el.click()
                elif act == "click_force":
                    sel = action["selector"]
                    el = await page.wait_for_selector(sel, timeout=action.get("timeout_ms", 10000))
                    if el:
                        await el.click(force=True)
                elif act == "wait":
                    await page.wait_for_timeout(action.get("ms", 1000))
                elif act == "wait_for_selector":
                    await page.wait_for_selector(
                        action["selector"], timeout=action.get("timeout_ms", 10000)
                    )
                elif act == "dismiss_popup":
                    selectors = action.get("selectors", [])
                    for sel in selectors:
                        try:
                            el = await page.wait_for_selector(sel, timeout=2000)
                            if el and await el.is_visible():
                                await el.click()
                                logger.info(f"Dismissed popup via: {sel}")
                                await page.wait_for_timeout(500)
                                break
                        except Exception:
                            continue
                    else:
                        try:
                            await page.keyboard.press("Escape")
                            await page.wait_for_timeout(500)
                        except Exception:
                            pass
                elif act == "dismiss_cookie":
                    # The selector the capture actually clicked comes first, then the shared list
                    # (runtime/consent.py) — the same one discovery uses, so the two cannot drift.
                    try:
                        from consent import selectors as _consent_selectors  # noqa: PLC0415  (runtime/ on sys.path under the CLI)
                    except ImportError:
                        from runtime.consent import selectors as _consent_selectors  # noqa: PLC0415
                    first = (action.get("selectors") or [None])[0]
                    for sel in _consent_selectors(first):
                        try:
                            el = await page.wait_for_selector(sel, timeout=1500)
                            if el and await el.is_visible():
                                await el.click()
                                await page.wait_for_timeout(1500)
                                break
                        except Exception:
                            continue
            except Exception as e:
                logger.warning(f"Pre-action '{desc}' failed: {e}")

    async def _resolve_frame(self, page: Page, iframe_cfg: Optional[Dict]) -> "Page | Frame":
        """If the chat widget is inside an iframe, return the frame. Otherwise return the page."""
        if not iframe_cfg or not (iframe_cfg.get("selector") or iframe_cfg.get("url_contains")):
            return page

        # Frame-by-URL first: robust for widgets that NEST frames (Genesys, Intercom, Salesforce),
        # where the chat frame is not a top-level <iframe> a CSS selector on the page can reach. We
        # already know the frame's URL from discovery, so match on it across ALL frames.
        needle = iframe_cfg.get("url_contains")
        if needle:
            deadline = asyncio.get_running_loop().time() + 20
            while asyncio.get_running_loop().time() < deadline:
                for fr in page.frames:
                    if needle in (fr.url or ""):
                        logger.info(f"Browser: switched to iframe by url ~ {needle!r}")
                        return fr
                await page.wait_for_timeout(500)
            # A configured iframe that never appeared is a real failure, not a reason to silently
            # search the wrong context (that finds a hidden recaptcha textarea and times out later).
            raise RuntimeError(
                f"chat iframe (url contains {needle!r}) never appeared — the widget did not open")

        selector = iframe_cfg["selector"]
        logger.info(f"Browser: resolving iframe {selector}")
        try:
            frame_el = await page.wait_for_selector(selector, timeout=15000)
            frame = await frame_el.content_frame()
            if frame:
                logger.info("Browser: switched to iframe context")
                return frame
        except Exception as e:
            raise RuntimeError(f"could not resolve chat iframe {selector!r}: {e}")
        raise RuntimeError(f"chat iframe {selector!r} resolved to no frame")

    async def _wait_for_response(
        self,
        target: "Page | Frame",
        resp_cfg: Dict,
        strategy: str,
        pre_count: int,
        timeout_ms: int,
        poll_ms: int,
    ) -> Optional[str]:
        container_sel = resp_cfg.get("container_selector", "")
        text_sel = resp_cfg.get("text_selector", "")
        deadline = time.time() + (timeout_ms / 1000)
        stabilization_ms = resp_cfg.get("stabilization_delay_ms", 1500)

        if strategy == "new_element":
            return await self._wait_new_element(
                target, container_sel, text_sel, pre_count, deadline, poll_ms, stabilization_ms
            )
        elif strategy == "loading_indicator":
            return await self._wait_loading_indicator(
                target, resp_cfg, container_sel, text_sel, deadline, poll_ms
            )
        elif strategy == "text_change":
            return await self._wait_text_change(target, container_sel, deadline, poll_ms)
        else:
            wait_ms = resp_cfg.get("fixed_wait_ms", 10000)
            await asyncio.sleep(wait_ms / 1000)
            return await self._get_last_message(target, container_sel, text_sel)

    async def _wait_new_element(self, target, container_sel, text_sel, pre_count, deadline, poll_ms, stabilization_ms=1500):
        while time.time() < deadline:
            elements = await target.query_selector_all(container_sel)
            if len(elements) > pre_count:
                last = elements[-1]
                text = await self._extract_text(last, text_sel)
                if text and len(text.strip()) > 0:
                    await asyncio.sleep(stabilization_ms / 1000)
                    elements = await target.query_selector_all(container_sel)
                    last = elements[-1]
                    return await self._extract_text(last, text_sel)
            await asyncio.sleep(poll_ms / 1000)
        return None

    async def _wait_loading_indicator(self, target, resp_cfg, container_sel, text_sel, deadline, poll_ms):
        indicator_sel = resp_cfg.get("loading_selector", "[class*='typing'], [class*='loading']")
        indicator_appeared = False
        while time.time() < deadline:
            try:
                el = await target.query_selector(indicator_sel)
                if el and await el.is_visible():
                    indicator_appeared = True
                    break
            except Exception:
                pass
            await asyncio.sleep(poll_ms / 1000)

        if not indicator_appeared:
            await asyncio.sleep(2)
            return await self._get_last_message(target, container_sel, text_sel)

        while time.time() < deadline:
            try:
                el = await target.query_selector(indicator_sel)
                if not el or not await el.is_visible():
                    await asyncio.sleep(0.5)
                    return await self._get_last_message(target, container_sel, text_sel)
            except Exception:
                pass
            await asyncio.sleep(poll_ms / 1000)
        return None

    async def _wait_text_change(self, target, container_sel, deadline, poll_ms):
        initial_text = ""
        try:
            el = await target.query_selector(container_sel)
            if el:
                initial_text = (await el.inner_text()) or ""
        except Exception:
            pass

        while time.time() < deadline:
            try:
                el = await target.query_selector(container_sel)
                if el:
                    current = (await el.inner_text()) or ""
                    if current != initial_text and len(current.strip()) > 0:
                        await asyncio.sleep(1)
                        el = await target.query_selector(container_sel)
                        return (await el.inner_text()).strip() if el else current.strip()
            except Exception:
                pass
            await asyncio.sleep(poll_ms / 1000)
        return None

    async def _get_last_message(self, target, container_sel, text_sel):
        if not container_sel:
            return None
        elements = await target.query_selector_all(container_sel)
        if not elements:
            return None
        return await self._extract_text(elements[-1], text_sel)

    async def _extract_text(self, element: ElementHandle, text_sel: str) -> str:
        if text_sel:
            sub = await element.query_selector(text_sel)
            if sub:
                return (await sub.inner_text()) or ""
        return (await element.inner_text()) or ""
