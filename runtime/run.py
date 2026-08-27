"""
run.py — start the bridge runtime: lease probes and relay them to a target via
an adapter config. Importable (build_runtime) and runnable (python -m runtime.run).

    STRAIKER_BRIDGE_API_KEY=tc-... \
      python3 run.py --adapter direct_api --config acme [--capture captures/acme.jsonl]
"""
import argparse
import logging
import os
import signal
import sys
from typing import Optional

from call_target import TargetCaller
from lease_client import LeaseClient, DEFAULT_BASE_URL


def build_runtime(api_key: str, adapter: str, config_name: str, *,
                  base_url: str = DEFAULT_BASE_URL, consumer: Optional[str] = None,
                  qpm: Optional[int] = None, max_workers: Optional[int] = None,
                  capture_path: Optional[str] = None,
                  wait_ms: int = 25000) -> LeaseClient:
    caller = TargetCaller(adapter, config_name)
    workers = max_workers if max_workers is not None else caller.recommended_workers()
    client = LeaseClient(
        api_key=api_key, handler=caller.handler, base_url=base_url,
        max_workers=workers, qpm=qpm, wait_ms=wait_ms,
        # Never hold more un-acked probes than the workers can drain inside the ~90s reclaim
        # window. A probe is un-acked from lease until its result is submitted, so a serial
        # (stateful, workers=1) target that leased a batch of 10 could ack only the first before
        # the rest were reclaimed and re-run out of order against a session. Leasing exactly
        # `workers` bounds the in-flight set to what the pool processes concurrently.
        max_probes_per_lease=workers,
        capture_path=capture_path,
        consumer=consumer or f"abv2-{adapter}-{config_name}",
    )
    client._caller = caller  # keep a handle for reset/introspection
    return client


def main() -> None:
    p = argparse.ArgumentParser(prog="ascendbridge-run",
                                description="Run the Ascend Bridge v2 pull-mode runtime.")
    p.add_argument("--adapter", help="adapter type (default: from config or direct_api)")
    p.add_argument("--config", required=True, help="config name (configs/<name>.json) or path")
    p.add_argument("--base-url", default=os.environ.get("STRAIKER_BRIDGE_URL", DEFAULT_BASE_URL))
    p.add_argument("--api-key", default=os.environ.get("STRAIKER_BRIDGE_API_KEY"),
                   help="bridge key (tc-...); defaults to $STRAIKER_BRIDGE_API_KEY")
    p.add_argument("--consumer", default=None)
    p.add_argument("--qpm", type=int, default=None, help="queries-per-minute throttle")
    p.add_argument("--max-workers", type=int, default=None,
                   help="override concurrency (auto: 1 for stateful, 10 stateless)")
    p.add_argument("--capture", default=None, help="jsonl file to record probe/result envelopes")
    p.add_argument("--wait-ms", type=int, default=25000)
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not args.api_key:
        p.error("no api key: pass --api-key or set STRAIKER_BRIDGE_API_KEY")

    client = build_runtime(
        args.api_key, args.adapter, args.config, base_url=args.base_url,
        consumer=args.consumer, qpm=args.qpm, max_workers=args.max_workers,
        capture_path=args.capture, wait_ms=args.wait_ms)

    signal.signal(signal.SIGINT, lambda *_: client.stop())
    signal.signal(signal.SIGTERM, lambda *_: client.stop())
    client.run_forever()


if __name__ == "__main__":
    main()
