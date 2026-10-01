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
from urllib.parse import quote, urljoin

import probecore as pc

_SECTION_RE = re.compile(r"^\[(.+)\]$")


def parse_identities(text: str, include_anon: bool = True) -> list[dict]:
    """Parse the identities box into [{name, headers, objects}], reference first.

    Block syntax (most-privileged first). Within a block, lines beginning
    with ``@`` declare per-identity object IDs (``@param=value``) used for
    the horizontal-IDOR test; every other line is a header/cookie:

        [admin]
        Authorization: Bearer admin-token
        [userA]
        Cookie: session=aaa
        @id=1001            # userA owns object id 1001
        @order=5001
        [userB]
        Cookie: session=bbb
        @id=1002
        @order=5002

    When ``include_anon`` is set, an anonymous identity (no headers, no
    objects) is appended as the lowest-privilege identity.
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

    identities = []
    for name, lines in blocks:
        header_lines: list[str] = []
        objects: dict[str, str] = {}
        for line in lines:
            s = line.strip()
            if s.startswith("@") and "=" in s:
                key, value = s[1:].split("=", 1)
                objects[key.strip()] = value.strip()
            else:
                header_lines.append(line)
        identities.append({
            "name": name,
            "headers": pc.parse_auth_headers("\n".join(header_lines)),
            "objects": objects,
        })
    if include_anon:
        identities.append({"name": "anon", "headers": None, "objects": {}})
    return identities


def _placeholder_names(path: str) -> list[str]:
    """Names of {param} placeholders in an OpenAPI-style path."""
    return [p[1:-1].split(":")[0].strip() for p in pc.SEG_PARAM.findall(path)]


def _fill_path(path: str, overrides: Optional[dict] = None) -> str:
    """Substitute {param} placeholders from overrides (default '1')."""
    overrides = overrides or {}

    def repl(match: re.Match) -> str:
        name = match.group(0)[1:-1].split(":")[0].strip()
        return quote(str(overrides.get(name, "1")), safe="")

    return pc.SEG_PARAM.sub(repl, path)


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


# ---------------------------------------------------------------------
# Horizontal IDOR: swap one identity's object ID into another identity's
# authenticated request and see whether the attacker reads the victim's data.
# ---------------------------------------------------------------------

def _classify_idor(a_status, a_body, v_status, v_body) -> tuple[str, str, bool]:
    """Compare attacker's response (a_) to the victim's own data (v_)."""
    if pc.is_2xx(a_status):
        if pc.bodies_similar(a_body, v_body):
            # Attacker received the victim's object data.
            return "horizontal-idor", "critical", True
        # Attacker reached the object but got different content.
        return "cross-access-differs", "medium", True
    if a_status in (401, 403, 404):
        return "enforced", "info", False  # blocked or hidden — expected
    return "inconclusive", "info", False


def run_idor(
    base_url: str,
    endpoints: list[tuple[str, str]],
    identities: list[dict],
    log: Callable,
    cancel: threading.Event,
    record: Optional[Callable] = None,
    max_endpoints: int = 40,
) -> None:
    """Horizontal access test: each attacker requests each victim's object ID."""
    owners = [i for i in identities if i.get("objects")]
    if len(owners) < 2:
        log("[idor] need >=2 identities with @object IDs (e.g. '@id=1001') to "
            "test horizontal access.")
        return
    endpoints = endpoints[:max_endpoints]
    log(f"[idor] {len(owners)} identities with object IDs: "
        f"{', '.join(i['name'] for i in owners)}")

    crossed = 0
    flagged = 0
    for method, path in endpoints:
        if cancel.is_set():
            log("[idor] cancelled.")
            break
        params = _placeholder_names(path)
        body = "{}" if method in pc.BODY_METHODS else None
        for param in params:
            relevant = [i for i in owners if param in i["objects"]]
            if len(relevant) < 2:
                continue
            for victim in relevant:
                if cancel.is_set():
                    break
                # The victim's own legitimate view of their object (baseline).
                v_over = {**victim["objects"], param: victim["objects"][param]}
                v_url = urljoin(base_url, _fill_path(path, v_over))
                v_status, v_body = pc.send_api(method, v_url, body, 12.0, victim["headers"])
                if pc.is_transport_error(v_body) or not pc.is_2xx(v_status):
                    continue  # can't establish victim baseline; skip
                for attacker in relevant:
                    if attacker["name"] == victim["name"] or cancel.is_set():
                        continue
                    # Attacker keeps its own IDs for other params, but requests
                    # the VICTIM's object for the targeted param.
                    a_over = {**attacker["objects"], param: victim["objects"][param]}
                    a_url = urljoin(base_url, _fill_path(path, a_over))
                    a_status, a_body = pc.send_api(method, a_url, body, 12.0, attacker["headers"])
                    crossed += 1
                    if pc.is_transport_error(a_body):
                        continue
                    verdict, severity, finding = _classify_idor(
                        a_status, a_body, v_status, v_body
                    )
                    obj = victim["objects"][param]
                    detail = (f"{attacker['name']} -> {victim['name']}'s {param}={obj} "
                              f"({attacker['name']}={a_status}, owner={v_status})")
                    if not finding:
                        continue
                    flagged += 1
                    level = {"critical": "CRIT", "medium": "MED "}.get(severity, "WARN")
                    log(f"  [{level}] {method} {path} — {verdict}: {detail}")
                    if record:
                        record({
                            "source": "idor", "severity": severity,
                            "method": method, "path": path, "param": param,
                            "attacker": attacker["name"], "victim": victim["name"],
                            "object_id": obj, "verdict": verdict,
                            "attacker_status": a_status, "owner_status": v_status,
                            "title": (f"{method} {path}: {attacker['name']} reads "
                                      f"{victim['name']}'s {param}"),
                        })
    log(f"[idor] done — {crossed} cross-request(s), {flagged} horizontal IDOR finding(s).")
