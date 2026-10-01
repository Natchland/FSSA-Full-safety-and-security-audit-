#!/usr/bin/env python3
"""
Example custom internal script for the FSSA Scan Launcher.

Each custom script receives the target URL as its first argument and writes
results to stdout. This one does a lightweight security-headers check using
only the Python standard library, so it needs no extra dependencies.

Use this as a template for your own internal checks.
"""

import sys
import urllib.request

# Response headers commonly reviewed during a security audit.
RECOMMENDED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: example_headers_check.py <url>", file=sys.stderr)
        return 2

    url = argv[1]
    print(f"[headers-check] fetching {url}")
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "FSSA/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
    except Exception as exc:  # noqa: BLE001 - report any fetch failure plainly
        print(f"[headers-check] request failed: {exc}", file=sys.stderr)
        return 1

    print(f"[headers-check] HTTP {status}\n")
    for header in RECOMMENDED_HEADERS:
        present = header.lower() in headers
        mark = "OK  " if present else "MISSING"
        value = f" -> {headers[header.lower()]}" if present else ""
        print(f"  [{mark}] {header}{value}")

    missing = [h for h in RECOMMENDED_HEADERS if h.lower() not in headers]
    print(f"\n[headers-check] {len(missing)} recommended header(s) missing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
