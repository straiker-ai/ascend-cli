"""
lease_client.py — hardened, importable v2 pull-mode bridge client.

Built on the official reference (`transport/bridge_client.py`) but productized:
  * importable LeaseClient class with a pluggable `handler(probe_message)`
  * stable consumer, retry/backoff, 401/403 fatal (unchanged semantics)
  * QPM throttle (the legacy Go bridge had no rate knob)
  * session-aware concurrency (max_workers; force 1 for sequential/stateful)
  * structured logging + optional capture of full probe/result envelopes
  * graceful shutdown (stop()) so runs end cleanly, not on a killed socket

The pull transport has no persistent socket, so the entire class of WebSocket
failures the legacy bridge hit (broken pipe → bad handshake, ping/pong misses,
assessment auto-pause on drop) simply cannot occur here: a dropped lease is just
retried; the server reclaims an un-acked probe after ~90s.
"""
import json
import logging
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger("ascendbridge.lease")


# handler: takes the full leased `message` dict, returns (status_code, body_dict)
Handler = Callable[[Dict[str, Any]], Tuple[int, Dict[str, Any]]]

DEFAULT_BASE_URL = "https://ascendai-bridge.prod.straiker.ai"


@dataclass
class LeaseClient:
    api_key: str
    handler: Handler
    base_url: str = DEFAULT_BASE_URL
    consumer: str = field(default_factory=lambda: f"abv2-{socket.gethostname()}")
    max_probes_per_lease: int = 10
    wait_ms: int = 25000
    result_timeout: float = 20.0   # /v2/result is an ordinary POST; it must NOT inherit the
    #                                long-poll's (wait_ms + 10)s ceiling, or a slow ack looks like
    #                                a lease timeout and the result is dropped.
    max_workers: int = 10          # set to 1 for stateful/sequential targets
    qpm: Optional[int] = None      # queries-per-minute throttle (None = unlimited)
    capture_path: Optional[str] = None  # jsonl file to record every probe+result
    _stop: threading.Event = field(default_factory=threading.Event)
    _min_interval: float = 0.0
    _last_call: float = 0.0
    _rate_lock: threading.Lock = field(default_factory=threading.Lock)
    stats: Dict[str, int] = field(default_factory=lambda: {
        "leased": 0, "answered": 0, "delivered": 0, "failed": 0,
        "lease_errors": 0, "submit_errors": 0, "empty_polls": 0})
    fatal_error: Optional[str] = None  # set instead of SystemExit so a daemon thread can report
    last_probe_ts: float = 0.0     # wall-clock of the last real probe handled; drives idle-timeout

    def __post_init__(self) -> None:
        self.lease_url = f"{self.base_url}/v2/lease"
        self.result_url = f"{self.base_url}/v2/result"
        self.http_timeout = (self.wait_ms / 1000) + 10
        if self.qpm and self.qpm > 0:
            self._min_interval = 60.0 / self.qpm
        if self.capture_path:
            Path(self.capture_path).parent.mkdir(parents=True, exist_ok=True)

    # ---- transport ----------------------------------------------------------
    def _post(self, url: str, payload: Dict[str, Any],
              timeout: Optional[float] = None) -> Dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"})
        with urllib.request.urlopen(req, timeout=(timeout or self.http_timeout)) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _lease(self) -> Dict[str, Any]:
        return self._post(self.lease_url, {
            "consumer": self.consumer, "max": self.max_probes_per_lease,
            "wait_ms": self.wait_ms})

    def _submit(self, request_id: str, msg_id: str, status_code: int,
                body: Any, headers: Optional[Dict] = None) -> Dict[str, Any]:
        return self._post(self.result_url, {
            "request_id": request_id, "msg_id": msg_id,
            "payload": {"status_code": status_code, "body": body,
                        "headers": headers or {}}},
            timeout=self.result_timeout)

    def _submit_with_retry(self, request_id: str, msg_id: str, status_code: int,
                           body: Any, attempts: int = 4) -> bool:
        """Deliver a result, retrying transient failures with backoff (same policy as the lease
        loop). Returns True once the server acks it. A result computed and then dropped is the most
        expensive failure in the system: it burns a target call and a ~90s server reclaim, then the
        probe is re-issued and re-run. Retrying costs a few seconds; sustained failure is a
        server-side problem, which the submit_errors counter then makes visible."""
        delay = 1.0
        for i in range(attempts):
            try:
                self._submit(request_id, msg_id, status_code, body)
                self.stats["delivered"] += 1
                return True
            except Exception as e:  # noqa: BLE001 - any transport error is retryable here
                if i == attempts - 1 or self._stop.is_set():
                    self.stats["submit_errors"] += 1
                    logger.warning("submit_result failed for %s after %d attempt(s): %s",
                                   request_id, i + 1, e)
                    return False
                logger.warning("submit_result retry %d/%d for %s: %s",
                               i + 1, attempts, request_id, e)
                self._sleep(delay)
                delay = min(delay * 2, 15)
        return False

    # ---- throttle -----------------------------------------------------------
    def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        with self._rate_lock:
            wait = self._min_interval - (time.time() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.time()

    # ---- capture ------------------------------------------------------------
    _SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key",
                          "api-key", "x-csrf-token", "x-amz-security-token",
                          "x-amz-access-token", "proxy-authorization"}

    def _redact(self, obj):
        """Recursively redact known-sensitive header values before persisting.
        Capture files hold whatever a target leaks — treat as sensitive, but never
        persist request auth headers in the clear."""
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() in self._SENSITIVE_HEADERS:
                    out[k] = "[REDACTED]"
                else:
                    out[k] = self._redact(v)
            return out
        if isinstance(obj, list):
            return [self._redact(x) for x in obj]
        return obj

    def _capture(self, kind: str, obj: Dict[str, Any]) -> None:
        if not self.capture_path:
            return
        try:
            rec = self._redact({"ts": time.time(), "kind": kind, **obj})
            # 0600 — transcripts contain whatever the target leaked.
            fd = os.open(self.capture_path,
                         os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as fh:
                fh.write(json.dumps(rec) + "\n")
        except Exception as e:  # capture must never break a run
            logger.debug("capture write failed: %s", e)

    # ---- lifecycle ----------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()

    def run_forever(self, ready_cb: Optional[Callable[[], None]] = None) -> None:
        logger.info("starting consumer=%s base=%s workers=%d qpm=%s",
                    self.consumer, self.base_url, self.max_workers, self.qpm)
        printed_ready = False
        backoff = 1
        pool = ThreadPoolExecutor(max_workers=max(1, self.max_workers))
        try:
            while not self._stop.is_set():
                try:
                    leased = self._lease()
                    backoff = 1
                except urllib.error.HTTPError as e:
                    if e.code in (401, 403):
                        # Do NOT SystemExit here: run_forever often runs in a daemon thread
                        # (onboard), where SystemExit dies silently and the caller then
                        # misreports a bad key as an egress timeout. Record and return.
                        # "bridge" is the LOCAL process; the thing rejecting us is the remote
                        # lease service. Saying "the bridge rejected the bridge key" made it read
                        # as though the process had rejected its own credential.
                        self.fatal_error = (
                            f"Ascend rejected this bridge key (HTTP {e.code}). Check "
                            f"$STRAIKER_BRIDGE_API_KEY, or `ascend keys list` for the app's key.")
                        logger.error("%s", self.fatal_error)
                        return
                    self.stats["lease_errors"] += 1
                    logger.warning("lease HTTP %s, retry in %ss", e.code, backoff)
                    self._sleep(backoff); backoff = min(backoff * 2, 30); continue
                except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as e:
                    self.stats["lease_errors"] += 1
                    logger.warning("lease error %s, retry in %ss", e, backoff)
                    self._sleep(backoff); backoff = min(backoff * 2, 30); continue

                if not printed_ready:
                    logger.info("ready — first lease OK; watching for probes")
                    printed_ready = True
                    if ready_cb:
                        ready_cb()

                probes = leased.get("probes", [])
                if not probes:
                    self.stats["empty_polls"] += 1
                    continue
                self.stats["leased"] += len(probes)
                list(pool.map(self._process, probes))
        finally:
            pool.shutdown(wait=False)
            logger.info("stopped; stats=%s", self.stats)

    def _sleep(self, seconds: float) -> None:
        # interruptible sleep so stop() is responsive
        self._stop.wait(timeout=seconds)

    def _process(self, probe: Dict[str, Any]) -> None:
        request_id = probe.get("request_id")
        msg_id = probe.get("msg_id")
        message = probe.get("message", {})
        self.last_probe_ts = time.time()      # real activity — resets the idle-timeout clock
        self._capture("probe", {"request_id": request_id, "message": message})

        self._throttle()
        try:
            status_code, body = self.handler(message)
        except Exception as e:
            status_code, body = 500, {"response": "", "_error": f"{type(e).__name__}: {e}"}
            logger.exception("handler raised for %s", request_id)
        if status_code == 200:
            self.stats["answered"] += 1     # LOCAL: the handler produced an answer
        else:
            self.stats["failed"] += 1
        self._capture("result", {"request_id": request_id,
                                 "status_code": status_code, "body": body})
        # Deliver with retry; `delivered` counts what the server actually acked. `answered` and
        # `delivered` diverge exactly when result delivery is failing, which is the signal to watch.
        self._submit_with_retry(request_id, msg_id, status_code, body)
