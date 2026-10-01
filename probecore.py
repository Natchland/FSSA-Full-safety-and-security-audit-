#!/usr/bin/env python3
"""
probecore — shared HTTP probing primitives for the FSSA Scan Launcher.

Lowest layer of the architecture: the request helpers, header parsing, and
endpoint discovery used by both the passive/active audits in
``scan_launcher`` and the ``accessmatrix`` authorization-matrix module.
Standard library only, no GUI dependencies.

Dependency direction:  probecore  <-  accessmatrix  <-  scan_launcher
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urljoin

UA = {"User-Agent": "FSSA-Scan-Launcher/1.0"}

# OpenAPI path placeholder (e.g. {id}) and methods that carry a request body.
SEG_PARAM = re.compile(r"\{[^/}]+\}")
BODY_METHODS = ("POST", "PUT", "PATCH")


# ------------------------------------------------------------- headers ---

def parse_auth_headers(text: str) -> dict:
    """Parse a session-auth text block into a headers dict.

    One item per line (blank lines and #comments ignored):
      - "Header-Name: value"  -> that header
      - "name=value"          -> accumulated into a single Cookie header
    """
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line and not (line.count("=") and line.index("=") < line.index(":")):
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
        elif "=" in line:
            cookies.append(line)
    if cookies:
        existing = headers.get("Cookie")
        joined = "; ".join(cookies)
        headers["Cookie"] = f"{existing}; {joined}" if existing else joined
    return headers


def merge_headers(extra: Optional[dict]) -> dict:
    """Default UA merged with caller-supplied session headers (extra wins)."""
    merged = dict(UA)
    if extra:
        merged.update(extra)
    return merged


# ---------------------------------------------------------- responses ---

def is_2xx(status) -> bool:
    return status is not None and 200 <= status < 300


def bodies_similar(a: str, b: str) -> bool:
    """True if two response bodies are near-identical by length (±5%)."""
    a, b = a or "", b or ""
    if a == b:
        return True
    longest = max(len(a), len(b))
    return longest == 0 or abs(len(a) - len(b)) / longest < 0.05


def is_transport_error(body) -> bool:
    return isinstance(body, str) and body.startswith("__transport_error__")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Opener handler that turns redirects into HTTPError instead of following
    them, so a 301/302 to a login page is not mistaken for an exposed file."""

    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003, D401
        return None


# ----------------------------------------------------------- requests ---

def probe_path(base_url: str, path: str, timeout: float = 10.0,
               extra_headers: Optional[dict] = None) -> tuple:
    """GET base_url+path (no redirects). Returns (path, status, size, error)."""
    url = urljoin(base_url, path)
    req = urllib.request.Request(url, method="GET", headers=merge_headers(extra_headers))
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(2048)  # enough to gauge a real response
            return path, resp.status, len(body), None
    except urllib.error.HTTPError as exc:
        return path, exc.code, 0, None
    except Exception as exc:  # noqa: BLE001 - report any transport failure
        return path, None, 0, str(exc)


def send_api(method: str, url: str, body: Optional[str], timeout: float = 12.0,
             extra_headers: Optional[dict] = None):
    """Send one request; return (status, response_text) or (None, '__error__…')."""
    data = body.encode("utf-8") if body is not None else None
    headers = merge_headers(extra_headers)
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        text = ""
        try:
            text = exc.read(8192).decode("utf-8", "replace")  # error-page body
        except Exception:  # noqa: BLE001
            pass
        return exc.code, text
    except Exception as exc:  # noqa: BLE001 - transport failure
        return None, f"__transport_error__: {exc}"


# ------------------------------------------------------- endpoint spec ---

def parse_api_routes(text: str) -> list[tuple[str, str]]:
    """Parse a routes box: comma/newline separated, optional method.

    Examples: "/api/v1/users/1", "POST /api/v1/items".
    """
    routes: list[tuple[str, str]] = []
    for chunk in re.split(r"[,\n]", text or ""):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        if len(parts) == 2 and parts[0].upper() in (
            "GET", "POST", "PUT", "PATCH", "DELETE",
        ):
            routes.append((parts[0].upper(), parts[1]))
        else:
            routes.append(("GET", parts[-1]))
    return routes


def load_openapi_routes(base_url: str, src: str,
                        extra_headers: Optional[dict] = None) -> list[tuple[str, str]]:
    """Load (METHOD, path) operations from an openapi.json URL or file path."""
    data = None
    if re.match(r"^https?://", src):
        url = src
    elif os.path.exists(src):
        with open(src, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        url = None
    else:
        url = urljoin(base_url, src)
    if data is None:
        req = urllib.request.Request(url, headers=merge_headers(extra_headers))
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))

    routes: list[tuple[str, str]] = []
    for path, item in (data.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete"):
            if method in item:
                routes.append((method.upper(), path))
    return routes
