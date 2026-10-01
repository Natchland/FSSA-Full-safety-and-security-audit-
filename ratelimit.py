#!/usr/bin/env python3
"""
ratelimit — Rate-Limiting & Resource-Exhaustion compliance tester.

Sends a BOUNDED burst of concurrent requests to a single endpoint and checks
whether the server throttles (HTTP 429, or 503 + Retry-After). If the server
keeps returning 2xx with no throttling, that's a compliance gap: no automated
rate-limiting control.

This is intentionally a fixed, capped burst — a control-presence check, not a
flood. Authorized targets only.

Dependency direction:  probecore  <-  ratelimit  <-  scan_launcher
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

import probecore as pc

# Hard safety ceilings so this stays a compliance probe, not a stress weapon.
MAX_TOTAL = 500
MAX_CONCURRENCY = 100


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = max(0, min(len(sorted_vals) - 1, int(round(pct / 100 * len(sorted_vals))) - 1))
    return sorted_vals[idx]


def rate_limit_test(
    url: str,
    method: str = "GET",
    total: int = 50,
    concurrency: int = 20,
    headers: Optional[dict] = None,
    log: Callable = print,
    cancel: Optional[threading.Event] = None,
    record: Optional[Callable] = None,
) -> None:
    """Fire a bounded concurrent burst and report throttling / timing."""
    cancel = cancel or threading.Event()
    total = max(1, min(total, MAX_TOTAL))
    concurrency = max(1, min(concurrency, MAX_CONCURRENCY))
    log(f"[rate-limit] bursting {total} {method} requests to {url} "
        f"(concurrency {concurrency})")

    results: list[tuple] = []  # (status, elapsed_seconds)
    errors = 0

    def one(_i: int):
        if cancel.is_set():
            return None
        t0 = time.monotonic()
        status, body = pc.send_api(method, url, None, timeout=15, extra_headers=headers)
        return status, body, time.monotonic() - t0

    wall_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one, i) for i in range(total)]
        for fut in as_completed(futures):
            res = fut.result()
            if res is None:
                continue
            status, body, elapsed = res
            if pc.is_transport_error(body) or status is None:
                errors += 1
            else:
                results.append((status, elapsed))
    wall = time.monotonic() - wall_start

    sent = len(results)
    if sent == 0:
        log(f"[rate-limit] no successful responses ({errors} transport error(s)).")
        return

    codes = Counter(s for s, _ in results)
    times = sorted(t for _, t in results)
    avg = sum(times) / len(times)
    throughput = sent / wall if wall else 0.0
    throttled = codes.get(429, 0)
    retry_503 = codes.get(503, 0)
    ok_2xx = sum(c for s, c in codes.items() if 200 <= s < 300)

    dist = ", ".join(f"{code}×{n}" for code, n in sorted(codes.items()))
    log(f"[rate-limit] responses: {dist}" + (f" (+{errors} errors)" if errors else ""))
    log(f"[rate-limit] timing: avg {avg * 1000:.0f} ms, "
        f"p95 {_percentile(times, 95) * 1000:.0f} ms, "
        f"max {times[-1] * 1000:.0f} ms | {throughput:.1f} req/s over {wall:.2f}s")

    if throttled:
        log(f"[rate-limit] OK — server throttled with {throttled}×429 "
            "(rate limiting present).")
        return
    if retry_503:
        log(f"[rate-limit] partial — {retry_503}×503 seen (possible throttling); "
            "no explicit 429.")

    # No 429 across the whole burst and the server kept serving 2xx: gap.
    if ok_2xx >= sent * 0.9:
        log(f"[rate-limit] COMPLIANCE GAP — {ok_2xx}/{sent} requests returned 2xx with "
            "no 429 throttling: no automated rate-limiting control detected.")
        if record:
            record({
                "source": "rate_limit", "severity": "medium",
                "endpoint": f"{method} {url}",
                "requests": sent, "ok_2xx": ok_2xx, "status_distribution": dict(codes),
                "avg_ms": round(avg * 1000), "max_ms": round(times[-1] * 1000),
                "throughput_rps": round(throughput, 1),
                "title": f"No rate limiting on {method} {url}",
            })
    else:
        log("[rate-limit] no 429, but server did not uniformly return 2xx "
            f"({ok_2xx}/{sent}); review the status distribution above.")
