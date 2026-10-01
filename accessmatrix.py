#!/usr/bin/env python3
"""
accessmatrix — Access-Control Diffing Matrix for the FSSA Scan Launcher.

Probes every endpoint with every identity (anonymous, low-priv user(s),
admin, …) in one pass, builds a response grid, and derives authorization
findings from it:

  - missing auth      : the anonymous identity gets a 2xx
  - privilege-escalation : a lesser identity gets the SAME response as the
                           privileged reference (it sees privileged data)
  - lesser-access-differs : a lesser identity gets a 2xx but different data
                            (review for horizontal access / IDOR)
  - enforced          : a lesser identity is blocked (401/403) — not a finding

The first identity in the list is treated as the privileged *reference*;
list identities most-privileged first. Standard library only.

Dependency direction:  probecore  <-  accessmatrix  <-  scan_launcher
"""

from __future__ import annotations

import re
import threading
from typing import Callable, Optional
from urllib.parse import urljoin

import probecore as pc

_SECTION_RE = re.compile(r"^\[(.+)\]$")


def parse_identities(text: str, include_anon: bool = True) -> list[dict]:
    """Parse the identities box into [{name, headers}], reference first.

    Block syntax (most-privileged first):

        [admin]
        Authorization: Bearer admin-token
        [userA]
        Cookie: session=aaa
        [userB]
        Cookie: session=bbb

    When ``include_anon`` is set, an anonymous identity (no headers) is
    appended as the lowest-privilege identity.
    """
    blocks: list[tuple[str, list[str]]] = []
    current: Optional[str] = None
    buf: list[str] = []
    for raw in (text or "").splitlines():
        m = _SECTION_RE.match(raw.strip())
        if m:
            if current is not None:
                blocks.append((current, buf))
            current = m.group(1).strip()
            buf = []
        elif raw.strip():
            buf.append(raw)
    if current is not None:
        blocks.append((current, buf))

    identities = [
        {"name": name, "headers": pc.parse_auth_headers("\n".join(lines))}
        for name, lines in blocks
    ]
    if include_anon:
        identities.append({"name": "anon", "headers": None})
    return identities


def resolve_endpoints(base_url: str, openapi_src: Optional[str],
                      routes: Optional[list], ref_headers: Optional[dict],
                      fallback_paths: list[str], log: Callable) -> list[tuple[str, str]]:
    """Endpoint discovery: custom routes, then OpenAPI, then sensitive paths."""
    if routes:
        log(f"[matrix] using {len(routes)} custom route(s)")
        return list(routes)
    src = openapi_src or urljoin(base_url, "/openapi.json")
    try:
        eps = pc.load_openapi_routes(base_url, src, ref_headers)
        log(f"[matrix] discovered {len(eps)} operation(s) from {src}")
        return eps
    except Exception as exc:  # noqa: BLE001
        log(f"[matrix] no OpenAPI spec ({exc}); using sensitive-path list")
        return [("GET", p) for p in fallback_paths]


def _classify(ref_status, ref_body, status, body, is_anon) -> tuple[str, str, bool]:
    """Compare a lesser identity against the reference. (verdict, severity, finding)."""
    if pc.is_2xx(status):
        if pc.is_2xx(ref_status) and pc.bodies_similar(ref_body, body):
            # Same privileged data reaches a lesser (or anonymous) identity.
            return ("missing-auth" if is_anon else "privilege-escalation",
                    "critical", True)
        # Reachable but different content.
        return ("anonymous-access" if is_anon else "lesser-access-differs",
                "high" if is_anon else "medium", True)
    if status in (401, 403) and pc.is_2xx(ref_status):
        return "enforced", "info", False
    return "inconclusive", "info", False


def run_matrix(
    base_url: str,
    endpoints: list[tuple[str, str]],
    identities: list[dict],
    log: Callable,
    cancel: threading.Event,
    record: Optional[Callable] = None,
    max_endpoints: int = 40,
) -> None:
    """Probe endpoints × identities, log the grid, and record findings."""
    if len(identities) < 2:
        log("[matrix] need at least 2 identities (e.g. one session + anonymous).")
        return
    endpoints = endpoints[:max_endpoints]
    names = [i["name"] for i in identities]
    reference = identities[0]
    log(f"[matrix] {len(endpoints)} endpoint(s) × {len(identities)} identities "
        f"[{', '.join(names)}] — reference: {reference['name']}")

    grid: list[dict] = []
    flagged = 0
    for method, path in endpoints:
        if cancel.is_set():
            log("[matrix] cancelled.")
            break
        cpath = pc.SEG_PARAM.sub("1", path)
        url = urljoin(base_url, cpath)
        body = "{}" if method in pc.BODY_METHODS else None

        responses: dict[str, tuple] = {}
        cells: dict[str, str] = {}
        for ident in identities:
            if cancel.is_set():
                break
            status, rbody = pc.send_api(method, url, body, 12.0, ident["headers"])
            responses[ident["name"]] = (status, rbody)
            cells[ident["name"]] = "ERR" if pc.is_transport_error(rbody) else str(status)
        grid.append({"method": method, "path": cpath, "cells": dict(cells)})
        log(f"  {method} {cpath}: " + "  ".join(f"{n}={cells[n]}" for n in names))

        ref_status, ref_body = responses[reference["name"]]
        if pc.is_transport_error(ref_body):
            log(f"    [err ] reference request failed: {ref_body}")
            continue
        for ident in identities[1:]:
            name = ident["name"]
            status, rbody = responses[name]
            if pc.is_transport_error(rbody):
                continue
            verdict, severity, finding = _classify(
                ref_status, ref_body, status, rbody, is_anon=not ident["headers"]
            )
            if not finding:
                continue
            flagged += 1
            level = {"critical": "CRIT", "high": "HIGH", "medium": "MED "}.get(severity, "WARN")
            log(f"    [{level}] {name}: {verdict} (vs {reference['name']}; "
                f"{reference['name']}={ref_status} {name}={status})")
            if record:
                record({
                    "source": "access_matrix", "severity": severity,
                    "method": method, "path": cpath,
                    "identity": name, "reference": reference["name"],
                    "verdict": verdict,
                    "ref_status": ref_status, "identity_status": status,
                    "title": f"{method} {path}: {name} {verdict}",
                })

    # Record the full grid once so the report can render the matrix table.
    if record and grid:
        record({
            "source": "access_matrix_grid",
            "identities": names,
            "rows": grid,
        })
    log(f"[matrix] done — {flagged} finding(s) across {len(grid)} endpoint(s).")
