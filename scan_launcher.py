#!/usr/bin/env python3
"""
FSSA Scan Launcher
==================

A simple local Tkinter GUI that launches standard security scanners
(nuclei, nikto) and custom internal scripts against a target URL.

Intended for AUTHORIZED security auditing only. You are responsible for
having explicit permission to scan any target you enter here.

Scans run in background threads and stream their output into the GUI,
so the window stays responsive while a scan is running.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import toolmanager


class _Signal:
    """Marker pushed through the output queue to report completion."""

    def __init__(self, kind: str) -> None:
        self.kind = kind


class _Finding:
    """A structured finding pushed through the output queue to be collected
    on the main thread (keeps self._findings single-threaded)."""

    def __init__(self, data: dict) -> None:
        self.data = data


# Matches ANSI/VT100 escape sequences (colors, cursor moves) that CLI tools
# like nuclei emit; Tkinter's Text widget shows them as literal junk.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


# =====================================================================
# Passive compliance / data-exposure checks (pure Python, stdlib only)
# ---------------------------------------------------------------------
# Both functions take a ``log(str)`` callable and a ``threading.Event``
# used for cooperative cancellation (the Stop button). They only send
# plain GET requests — no exploitation, no payloads.
# =====================================================================

# A small, standard list of administrative / backup paths that should not
# be publicly readable on a production server.
SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.htaccess",
    "/.DS_Store",
    "/config.bak",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/backup.sql",
    "/backup.zip",
    "/db.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/server-status",
]

# Response headers reviewed by the security-header auditor, with why each
# one matters for data protection / compliance.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — forces HTTPS, prevents downgrade",
    "Content-Security-Policy": "CSP — mitigates XSS / content injection",
    "X-Frame-Options": "clickjacking protection",
    "X-Content-Type-Options": "blocks MIME-type sniffing",
    "Referrer-Policy": "controls referrer leakage",
    "Permissions-Policy": "restricts powerful browser features",
}

_UA = {"User-Agent": "FSSA-Scan-Launcher/1.0"}

# nuclei prints findings as: [template-id] [protocol] [severity] target ...
_NUCLEI_LINE_RE = re.compile(
    r"^\[([^\]]+)\] \[([^\]]+)\] \[(critical|high|medium|low|info|unknown)\] (.+)$"
)


def parse_tool_line(source: str, line: str) -> Optional[dict]:
    """Turn a single nuclei/nikto output line into a finding dict, or None."""
    s = line.strip()
    if source == "nuclei":
        m = _NUCLEI_LINE_RE.match(s)
        if m:
            return {
                "source": "nuclei",
                "severity": m.group(3),
                "template": m.group(1),
                "protocol": m.group(2),
                "target": m.group(4),
            }
    elif source == "nikto":
        # nikto itemizes findings with a leading "+ ".
        if line.startswith("+ "):
            return {"source": "nikto", "severity": "info", "detail": line[2:].strip()}
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Opener handler that turns redirects into HTTPError instead of following
    them, so a 301/302 to a login page is not mistaken for an exposed file."""

    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003, D401
        return None


def _probe_path(base_url: str, path: str, timeout: float = 10.0) -> tuple:
    """GET base_url+path (no redirects). Returns (path, status, size, error)."""
    url = urljoin(base_url, path)
    req = urllib.request.Request(url, method="GET", headers=_UA)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(2048)  # enough to gauge a real response
            return path, resp.status, len(body), None
    except urllib.error.HTTPError as exc:
        return path, exc.code, 0, None
    except Exception as exc:  # noqa: BLE001 - report any transport failure
        return path, None, 0, str(exc)


def data_exposure_scan(base_url: str, log, cancel: threading.Event, record=None) -> None:
    """Flag sensitive paths that return 200 OK (exposed server files)."""
    log(f"[data-exposure] probing {len(SENSITIVE_PATHS)} paths on {base_url}")
    flagged = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(_probe_path, base_url, p): p for p in SENSITIVE_PATHS
        }
        for future in as_completed(futures):
            if cancel.is_set():
                log("[data-exposure] cancelled.")
                break
            path, status, size, error = future.result()
            if error:
                log(f"  [err ] {path} — {error}")
            elif status == 200:
                flagged += 1
                log(f"  [WARN] {path} -> 200 OK ({size}+ bytes) — POSSIBLY EXPOSED")
                if record:
                    record({
                        "source": "data_exposure", "severity": "medium",
                        "path": path, "status": status,
                        "title": f"Exposed file {path}",
                    })
            else:
                log(f"  [ ok ] {path} -> {status}")
    log(f"[data-exposure] done — {flagged} path(s) flagged as possibly exposed.")
    if flagged:
        log("[data-exposure] NOTE: verify manually; some servers return 200 "
            "for soft-404 pages.")


def _header_quality(name: str, value: str) -> str:
    """Return a short validity note for a present header, or '' if fine."""
    v = value.lower()
    if name == "Strict-Transport-Security":
        if "max-age=0" in v:
            return "  (weak: max-age=0 disables HSTS)"
        if "max-age" not in v:
            return "  (weak: no max-age directive)"
    elif name == "Content-Security-Policy":
        if "unsafe-inline" in v:
            return "  (weak: allows 'unsafe-inline')"
    elif name == "X-Frame-Options":
        if v not in ("deny", "sameorigin"):
            return "  (unusual value; expected DENY or SAMEORIGIN)"
    elif name == "X-Content-Type-Options":
        if v != "nosniff":
            return "  (expected 'nosniff')"
    return ""


def security_header_audit(url: str, log, cancel: threading.Event, record=None) -> None:
    """Fetch the target and report presence/validity of protection headers."""
    log(f"[headers] fetching {url}")
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=15) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
            final_url = resp.geturl()
    except Exception as exc:  # noqa: BLE001 - report any transport failure
        log(f"[headers] request failed: {exc}")
        return
    if cancel.is_set():
        log("[headers] cancelled.")
        return

    log(f"[headers] HTTP {status} (final URL: {final_url})")
    present = 0
    for header, why in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if value:
            present += 1
            note = _header_quality(header, value)
            log(f"  [ ok ] {header}: {value}{note}")
            if note and record:
                record({
                    "source": "headers", "type": "weak", "severity": "low",
                    "header": header, "note": note.strip(" ()"),
                    "title": f"Weak header {header}",
                })
        else:
            log(f"  [GAP ] {header} — MISSING ({why})")
            if record:
                record({
                    "source": "headers", "type": "missing", "severity": "low",
                    "header": header, "title": f"Missing header {header}",
                })
    total = len(SECURITY_HEADERS)
    log(f"[headers] gap analysis: {present}/{total} present, {total - present} missing.")


# =====================================================================
# Active API schema validator (input-handling / error-leakage fuzzer)
# ---------------------------------------------------------------------
# ACTIVE: sends mutated requests (type changes, malformed JSON) to API
# endpoints and flags responses that leak raw DB errors or verbose stack
# traces — a sign of improper input handling. Bounded by max_endpoints /
# max_requests and cancellable via Stop. Authorized targets only.
# =====================================================================

_SEG_PARAM = re.compile(r"\{[^/}]+\}")  # OpenAPI path placeholder, e.g. {id}
_BODY_METHODS = ("POST", "PUT", "PATCH")

# Path/param type mutations — mainly integer -> other types.
_PATH_PARAM_MUTATIONS = [
    ("int->string", "FSSAstr"),
    ("sql-quote", "1'"),
    ("negative", "-1"),
    ("overflow", "9" * 20),
    ("null-word", "null"),
]

# Malformed / wrong-type JSON bodies for endpoints that accept a body.
_MALFORMED_BODIES = [
    ("truncated-json", '{"id": '),
    ("trailing-comma", '{"id": 1,}'),
    ("not-json", "this is not json"),
    ("wrong-root-type", "[1, 2, 3]"),
    ("type-swapped", '{"id": "not_a_number", "enabled": "maybe", "count": [1,2,3]}'),
]

# Signatures of leaked database errors.
_DB_PATTERNS = [
    r"you have an error in your sql syntax",
    r"\bSQL syntax\b", r"\bSQLSTATE\b", r"ORA-\d{5}", r"\bPG::\w+",
    r"\bpsql\b", r"postgresql", r"mysql_fetch", r"unclosed quotation mark",
    r"sqlite3\.\w+", r"SQLiteException", r"MongoError", r"\bpymongo\b",
    r"System\.Data\.SqlClient", r"org\.hibernate", r"\bJDBC\b",
    r"SequelizeDatabaseError", r"psycopg2\.\w+",
]

# Signatures of verbose stack traces / debug error pages.
_STACK_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r'File ".*", line \d+',
    r"\bat [\w.$]+\([\w.]+\.java:\d+\)",
    r"Exception in thread",
    r"NullPointerException", r"RuntimeException",
    r"Werkzeug Debugger", r"werkzeug",
    r"Whitelabel Error Page",
    r"Fatal error:", r"Warning: .* on line \d+", r"Notice: .* on line \d+",
    r"Microsoft OLE DB", r"ASP\.NET",
    r"panic:", r"goroutine \d+ \[",
    r"stack trace", r"\.rb:\d+:in ",
]

_COMPILED_SIGNATURES = (
    [("db-error", re.compile(p, re.I)) for p in _DB_PATTERNS]
    + [("stack-trace", re.compile(p, re.I)) for p in _STACK_PATTERNS]
)


def parse_api_routes(text: str) -> list[tuple[str, str]]:
    """Parse the custom-routes box: comma/newline separated, optional method.

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


def _load_openapi_routes(base_url: str, src: str) -> list[tuple[str, str]]:
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
        req = urllib.request.Request(url, headers=_UA)
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


def _api_variants(method: str, path: str) -> list[tuple[str, str, Optional[str]]]:
    """Build (description, concrete_path, body) request variants for an op."""
    has_body = method in _BODY_METHODS
    base = _SEG_PARAM.sub("1", path)  # fill placeholders with a sample value
    default_body = "{}" if has_body else None
    variants: list[tuple[str, str, Optional[str]]] = [("baseline", base, default_body)]

    # Path-parameter type mutations (placeholder or numeric segment).
    placeholders = _SEG_PARAM.findall(path)
    if placeholders:
        for desc, val in _PATH_PARAM_MUTATIONS:
            mutated = path.replace(placeholders[0], quote(val, safe=""), 1)
            mutated = _SEG_PARAM.sub("1", mutated)
            variants.append((f"path/{desc}", mutated, default_body))
    else:
        segs = base.split("/")
        idx = next((i for i, s in enumerate(segs) if s.isdigit()), None)
        if idx is not None:
            for desc, val in _PATH_PARAM_MUTATIONS:
                seg = segs[:]
                seg[idx] = quote(val, safe="")
                variants.append((f"path/{desc}", "/".join(seg), default_body))

    # Malformed / wrong-type JSON bodies.
    if has_body:
        for desc, body in _MALFORMED_BODIES:
            variants.append((f"body/{desc}", base, body))
    return variants


def _send_api(method: str, url: str, body: Optional[str], timeout: float = 12.0):
    """Send one request; return (status, response_text) or (None, '__error__…')."""
    data = body.encode("utf-8") if body is not None else None
    headers = dict(_UA)
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
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


def _scan_api_response(body: str) -> tuple[Optional[str], str]:
    """Return (kind, matching_line) if a DB error / stack trace is leaked."""
    for kind, rx in _COMPILED_SIGNATURES:
        m = rx.search(body)
        if m:
            start = body.rfind("\n", 0, m.start()) + 1
            end = body.find("\n", m.end())
            end = len(body) if end < 0 else end
            return kind, body[start:end].strip()[:200]
    return None, ""


def api_schema_validator(
    base_url: str,
    openapi_src: Optional[str],
    routes: Optional[list[tuple[str, str]]],
    log,
    cancel: threading.Event,
    record=None,
    max_endpoints: int = 25,
    max_requests: int = 300,
) -> None:
    """Fuzz API endpoints with type/JSON mutations; flag leaked errors."""
    if routes:
        endpoints = routes
        log(f"[api-fuzz] using {len(endpoints)} custom route(s)")
    else:
        src = openapi_src or urljoin(base_url, "/openapi.json")
        log(f"[api-fuzz] loading OpenAPI spec from {src}")
        try:
            endpoints = _load_openapi_routes(base_url, src)
        except Exception as exc:  # noqa: BLE001
            log(f"[api-fuzz] could not load OpenAPI spec: {exc}")
            log("[api-fuzz] tip: provide custom routes instead, e.g. /api/v1/users/1")
            return
        log(f"[api-fuzz] discovered {len(endpoints)} operation(s)")

    if not endpoints:
        log("[api-fuzz] no endpoints to test.")
        return
    endpoints = endpoints[:max_endpoints]

    sent = 0
    flagged = 0
    for method, path in endpoints:
        if cancel.is_set() or sent >= max_requests:
            break
        variants = _api_variants(method, path)
        log(f"[api-fuzz] {method} {path} — {len(variants)} variant(s)")
        for desc, cpath, body in variants:
            if cancel.is_set() or sent >= max_requests:
                break
            status, resp = _send_api(method, urljoin(base_url, cpath), body)
            sent += 1
            if resp.startswith("__transport_error__"):
                log(f"    [err ] [{desc}] -> {resp}")
                continue
            kind, line = _scan_api_response(resp)
            is_5xx = status is not None and 500 <= status < 600
            if kind or is_5xx:
                flagged += 1
                tag = kind or "server-error(5xx)"
                log(f"    [WARN] [{desc}] -> {status}  LEAK: {tag}")
                if line:
                    log(f"           ↳ {line}")
                if record:
                    record({
                        "source": "api", "severity": "high",
                        "method": method, "path": cpath, "variant": desc,
                        "status": status, "leak": tag, "detail": line,
                        "title": f"{method} {path} leaks {tag}",
                    })
    if cancel.is_set():
        log("[api-fuzz] cancelled.")
    log(f"[api-fuzz] done — {sent} request(s) sent, {flagged} leaking response(s).")
    if sent >= max_requests:
        log(f"[api-fuzz] NOTE: stopped at the {max_requests}-request safety cap.")


# =====================================================================
# Configuration file — make the lists above editable without code edits
# =====================================================================

CONFIG_PATH = Path(
    os.environ.get("FSSA_CONFIG", Path(__file__).resolve().parent / "fssa_config.json")
)


def _rebuild_signatures() -> None:
    global _COMPILED_SIGNATURES
    _COMPILED_SIGNATURES = (
        [("db-error", re.compile(p, re.I)) for p in _DB_PATTERNS]
        + [("stack-trace", re.compile(p, re.I)) for p in _STACK_PATTERNS]
    )


def load_config(path: Path = CONFIG_PATH, log=None) -> bool:
    """Override the built-in path/header/mutation/signature lists from JSON.

    Any key present replaces the corresponding default; missing keys keep the
    defaults. Returns True if a config file was found and applied.
    """
    global SENSITIVE_PATHS, SECURITY_HEADERS, _PATH_PARAM_MUTATIONS
    global _MALFORMED_BODIES, _DB_PATTERNS, _STACK_PATTERNS

    path = Path(path)
    if not path.is_file():
        return False
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        if log:
            log(f"[config] failed to read {path}: {exc}")
        return False

    applied = []
    if isinstance(cfg.get("sensitive_paths"), list):
        SENSITIVE_PATHS = [str(p) for p in cfg["sensitive_paths"]]
        applied.append("sensitive_paths")
    if isinstance(cfg.get("security_headers"), dict):
        SECURITY_HEADERS = {str(k): str(v) for k, v in cfg["security_headers"].items()}
        applied.append("security_headers")
    if isinstance(cfg.get("api_path_mutations"), list):
        _PATH_PARAM_MUTATIONS = [(str(a), str(b)) for a, b in cfg["api_path_mutations"]]
        applied.append("api_path_mutations")
    if isinstance(cfg.get("api_malformed_bodies"), list):
        _MALFORMED_BODIES = [(str(a), str(b)) for a, b in cfg["api_malformed_bodies"]]
        applied.append("api_malformed_bodies")
    if isinstance(cfg.get("db_error_patterns"), list):
        _DB_PATTERNS = [str(p) for p in cfg["db_error_patterns"]]
        applied.append("db_error_patterns")
    if isinstance(cfg.get("stack_trace_patterns"), list):
        _STACK_PATTERNS = [str(p) for p in cfg["stack_trace_patterns"]]
        applied.append("stack_trace_patterns")

    if "db_error_patterns" in applied or "stack_trace_patterns" in applied:
        try:
            _rebuild_signatures()
        except re.error as exc:
            if log:
                log(f"[config] invalid regex in patterns: {exc}")
    if log:
        log(f"[config] loaded {path.name}: overrode {', '.join(applied) or 'nothing'}")
    return True


# Directory that holds your custom internal scripts. Override with the
# FSSA_SCRIPTS_DIR environment variable if you keep them elsewhere.
DEFAULT_SCRIPTS_DIR = Path(
    os.environ.get("FSSA_SCRIPTS_DIR", Path(__file__).resolve().parent / "scripts")
)


class ScanLauncher(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("FSSA Scan Launcher")
        self.geometry("860x620")
        self.minsize(700, 500)

        # State for the currently running scan / install.
        self._proc: subprocess.Popen | None = None
        self._output_q: "queue.Queue[str | _Signal]" = queue.Queue()
        self._scripts_dir = DEFAULT_SCRIPTS_DIR
        self._scan_running = False
        self._installing = False
        self._cancel = threading.Event()  # cooperative stop for Python tasks
        self._findings: list[dict] = []   # live structured findings (main thread)

        self._build_ui()
        # Apply any user config overrides (paths, headers, signatures, …).
        if load_config(CONFIG_PATH, log=self._append):
            pass
        self._refresh_tool_status()
        self._poll_output_queue()
        # Offer to install missing scanners once the window is visible.
        self.after(400, self._autostart_install)

    # ---------------------------------------------------------------- UI ---

    def _build_ui(self) -> None:
        pad = {"padx": 8, "pady": 6}

        # --- Target URL row ------------------------------------------------
        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Target URL:").pack(side="left")
        self.url_var = tk.StringVar(value="https://")
        self.url_entry = ttk.Entry(top, textvariable=self.url_var)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))

        # --- Authorization acknowledgement --------------------------------
        self.authorized_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self,
            text="I am authorized to scan this target.",
            variable=self.authorized_var,
        ).pack(anchor="w", padx=8)

        # --- Scanner buttons ----------------------------------------------
        btns = ttk.LabelFrame(self, text="Scans")
        btns.pack(fill="x", **pad)

        self.nuclei_btn = ttk.Button(
            btns, text="Run nuclei (standard templates)", command=self.run_nuclei
        )
        self.nuclei_btn.grid(row=0, column=0, sticky="ew", padx=6, pady=6)

        self.nikto_btn = ttk.Button(
            btns, text="Run nikto", command=self.run_nikto
        )
        self.nikto_btn.grid(row=0, column=1, sticky="ew", padx=6, pady=6)

        btns.columnconfigure(0, weight=1)
        btns.columnconfigure(1, weight=1)

        # --- nuclei options -----------------------------------------------
        opts = ttk.LabelFrame(self, text="nuclei options")
        opts.pack(fill="x", **pad)

        ttk.Label(opts, text="Severity:").grid(row=0, column=0, padx=6, pady=4, sticky="w")
        sev_box = ttk.Frame(opts)
        sev_box.grid(row=0, column=1, columnspan=4, sticky="w")
        # Default to the noise-reducing high-signal set; untick for everything.
        self.severity_vars: dict[str, tk.BooleanVar] = {}
        defaults = {"critical", "high", "medium"}
        for i, sev in enumerate(("critical", "high", "medium", "low", "info")):
            var = tk.BooleanVar(value=sev in defaults)
            self.severity_vars[sev] = var
            ttk.Checkbutton(sev_box, text=sev, variable=var).grid(
                row=0, column=i, padx=(0, 8)
            )

        ttk.Label(opts, text="Tags:").grid(row=1, column=0, padx=6, pady=4, sticky="w")
        self.tags_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.tags_var).grid(
            row=1, column=1, columnspan=3, sticky="ew", padx=6, pady=4
        )
        ttk.Label(
            opts, text="comma-separated, e.g. cves,misconfig (blank = all)"
        ).grid(row=1, column=4, padx=6, pady=4, sticky="w")
        opts.columnconfigure(3, weight=1)

        # --- Compliance & data-exposure audits ----------------------------
        audit = ttk.LabelFrame(self, text="Compliance & Data Exposure Audits (passive)")
        audit.pack(fill="x", **pad)

        self.data_exposure_btn = ttk.Button(
            audit, text="Data exposure scan", command=self.run_data_exposure
        )
        self.data_exposure_btn.grid(row=0, column=0, sticky="ew", padx=6, pady=6)

        self.header_audit_btn = ttk.Button(
            audit, text="Security header audit", command=self.run_header_audit
        )
        self.header_audit_btn.grid(row=0, column=1, sticky="ew", padx=6, pady=6)

        self.audit_all_btn = ttk.Button(
            audit, text="Run both audits", command=self.run_all_audits
        )
        self.audit_all_btn.grid(row=0, column=2, sticky="ew", padx=6, pady=6)

        for col in range(3):
            audit.columnconfigure(col, weight=1)

        # --- Active API schema validator ----------------------------------
        api = ttk.LabelFrame(
            self, text="Active API Schema Validator (sends mutated requests)"
        )
        api.pack(fill="x", **pad)

        ttk.Label(api, text="OpenAPI URL/path:").grid(
            row=0, column=0, padx=6, pady=4, sticky="w"
        )
        self.openapi_var = tk.StringVar()
        ttk.Entry(api, textvariable=self.openapi_var).grid(
            row=0, column=1, sticky="ew", padx=6, pady=4
        )
        ttk.Label(api, text="blank = <target>/openapi.json").grid(
            row=0, column=2, padx=6, pady=4, sticky="w"
        )

        ttk.Label(api, text="Custom routes:").grid(
            row=1, column=0, padx=6, pady=4, sticky="nw"
        )
        self.routes_text = tk.Text(api, height=3, width=40)
        self.routes_text.grid(row=1, column=1, sticky="ew", padx=6, pady=4)
        ttk.Label(
            api,
            text="one per line or comma-sep,\noptional method, e.g.\nPOST /api/v1/users",
            justify="left",
        ).grid(row=1, column=2, padx=6, pady=4, sticky="w")

        self.api_validate_btn = ttk.Button(
            api, text="Validate API schema", command=self.run_api_validator
        )
        self.api_validate_btn.grid(row=2, column=1, sticky="w", padx=6, pady=6)

        api.columnconfigure(1, weight=1)

        # --- Custom internal scripts --------------------------------------
        custom = ttk.LabelFrame(self, text="Custom internal scripts")
        custom.pack(fill="x", **pad)

        ttk.Label(custom, text="Script:").grid(row=0, column=0, padx=6, pady=6)
        self.script_var = tk.StringVar()
        self.script_combo = ttk.Combobox(
            custom, textvariable=self.script_var, state="readonly", width=40
        )
        self.script_combo.grid(row=0, column=1, sticky="ew", padx=6, pady=6)

        ttk.Button(custom, text="Refresh", command=self._load_scripts).grid(
            row=0, column=2, padx=6, pady=6
        )
        ttk.Button(custom, text="Folder…", command=self._choose_scripts_dir).grid(
            row=0, column=3, padx=6, pady=6
        )
        self.custom_btn = ttk.Button(
            custom, text="Run script", command=self.run_custom_script
        )
        self.custom_btn.grid(row=0, column=4, padx=6, pady=6)

        custom.columnconfigure(1, weight=1)

        # --- Control row ---------------------------------------------------
        control = ttk.Frame(self)
        control.pack(fill="x", **pad)

        self.stop_btn = ttk.Button(
            control, text="Stop scan", command=self.stop_scan, state="disabled"
        )
        self.stop_btn.pack(side="left")
        ttk.Button(control, text="Clear output", command=self.clear_output).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(control, text="Save output…", command=self.save_output).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(control, text="Save report…", command=self.save_report).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(control, text="Clear findings", command=self.clear_findings).pack(
            side="left", padx=(6, 0)
        )
        self.install_btn = ttk.Button(
            control, text="Install / update tools", command=self.install_tools
        )
        self.install_btn.pack(side="left", padx=(6, 0))
        ttk.Button(control, text="Reload config", command=self.reload_config).pack(
            side="left", padx=(6, 0)
        )

        self.status_var = tk.StringVar(value="Idle.")
        ttk.Label(control, textvariable=self.status_var).pack(side="right")
        self.findings_var = tk.StringVar(value="Findings: 0")
        ttk.Label(control, textvariable=self.findings_var).pack(side="right", padx=(0, 12))

        # --- Output pane ---------------------------------------------------
        out_frame = ttk.LabelFrame(self, text="Output")
        out_frame.pack(fill="both", expand=True, **pad)

        self.output = tk.Text(out_frame, wrap="word", state="disabled", height=18)
        self.output.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(out_frame, command=self.output.yview)
        scroll.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=scroll.set)

        self._load_scripts()

    # -------------------------------------------------------- validation ---

    def _valid_target(self) -> str | None:
        """Validate the URL and authorization; return the URL or None."""
        url = self.url_var.get().strip()
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            messagebox.showerror(
                "Invalid URL",
                "Enter a full URL including scheme, e.g. https://example.com",
            )
            return None
        if not self.authorized_var.get():
            messagebox.showwarning(
                "Authorization required",
                "Confirm you are authorized to scan this target before running a scan.",
            )
            return None
        return url

    def _busy(self) -> bool:
        if self._installing:
            messagebox.showinfo("Busy", "Tools are installing. Please wait.")
            return True
        if self._scan_running or (self._proc is not None and self._proc.poll() is None):
            messagebox.showinfo("Busy", "A scan is already running. Stop it first.")
            return True
        return False

    # --------------------------------------------------------- scanners ---

    def run_nuclei(self) -> None:
        if self._busy():
            return
        url = self._valid_target()
        if not url:
            return
        cmd = toolmanager.nuclei_cmd()
        if cmd is None:
            self._offer_install(["nuclei"])
            return
        # Standard templates: nuclei ships them and auto-updates on first run.
        args = cmd + ["-u", url, "-nc"]  # -nc: no color (we also strip ANSI)

        severities = [s for s, v in self.severity_vars.items() if v.get()]
        if severities:
            args += ["-severity", ",".join(severities)]

        tags = self.tags_var.get().strip()
        if tags:
            # Normalize spacing: "cves, misconfig" -> "cves,misconfig"
            tags = ",".join(t.strip() for t in tags.split(",") if t.strip())
            args += ["-tags", tags]

        self._start(args, label="nuclei", source="nuclei")

    def run_nikto(self) -> None:
        if self._busy():
            return
        url = self._valid_target()
        if not url:
            return
        cmd = toolmanager.nikto_cmd()
        if cmd is None:
            self._offer_install(["nikto"])
            return
        self._start(cmd + ["-h", url], label="nikto", source="nikto")

    def run_custom_script(self) -> None:
        if self._busy():
            return
        url = self._valid_target()
        if not url:
            return
        name = self.script_var.get().strip()
        if not name:
            messagebox.showinfo("No script", "Select a custom script to run.")
            return
        script_path = self._scripts_dir / name
        if not script_path.is_file():
            messagebox.showerror("Not found", f"Script not found:\n{script_path}")
            return
        # Run via the interpreter matching the extension; the target URL is
        # passed as the first argument.
        cmd = self._interpreter_for(script_path) + [str(script_path), url]
        self._start(cmd, label=f"custom:{name}")

    # ------------------------------------------- compliance audits (py) ---

    def run_data_exposure(self) -> None:
        if self._busy():
            return
        url = self._valid_target()
        if not url:
            return
        self._start_task(
            lambda log, cancel: data_exposure_scan(url, log, cancel, record=self._record),
            label="data exposure scan",
        )

    def run_header_audit(self) -> None:
        if self._busy():
            return
        url = self._valid_target()
        if not url:
            return
        self._start_task(
            lambda log, cancel: security_header_audit(url, log, cancel, record=self._record),
            label="security header audit",
        )

    def run_all_audits(self) -> None:
        if self._busy():
            return
        url = self._valid_target()
        if not url:
            return

        def both(log, cancel) -> None:
            security_header_audit(url, log, cancel, record=self._record)
            if not cancel.is_set():
                log("")
                data_exposure_scan(url, log, cancel, record=self._record)

        self._start_task(both, label="compliance audits")

    def run_api_validator(self) -> None:
        if self._busy():
            return
        url = self._valid_target()
        if not url:
            return
        openapi_src = self.openapi_var.get().strip() or None
        routes_text = self.routes_text.get("1.0", "end").strip()
        routes = parse_api_routes(routes_text) if routes_text else None
        self._start_task(
            lambda log, cancel: api_schema_validator(
                url, openapi_src, routes, log, cancel, record=self._record
            ),
            label="API schema validation",
        )

    def _start_task(self, target, label: str) -> None:
        """Run a pure-Python check in a background thread, streaming via log."""
        self._append(f"\n=== {label} ===\n")
        self.status_var.set(f"Running {label}…")
        self._scan_running = True
        self._cancel.clear()
        self._update_buttons()

        def log(line: str) -> None:
            self._output_q.put(line + "\n")

        def worker() -> None:
            try:
                target(log, self._cancel)
            except Exception as exc:  # noqa: BLE001 - surface any failure
                self._output_q.put(f"[error] {label} failed: {exc}\n")
            self._output_q.put(f"[{label} finished]\n")
            self._output_q.put(_Signal("scan_done"))

        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _interpreter_for(path: Path) -> list[str]:
        suffix = path.suffix.lower()
        if suffix == ".py":
            # Use the same interpreter running this GUI (works on Windows,
            # where there is usually no "python3" command).
            return [sys.executable]
        if suffix in (".sh", ".bash"):
            return ["bash"]
        # Fall back to executing the file directly (relies on its shebang).
        return []

    # ---------------------------------------------- subprocess plumbing ---

    def _start(self, cmd: list[str], label: str, source: str | None = None) -> None:
        self._append(f"\n$ {' '.join(shlex.quote(c) for c in cmd)}\n")
        self.status_var.set(f"Running {label}…")
        self._scan_running = True
        self._cancel.clear()
        self._update_buttons()

        # Put the child in its own process group so Stop can kill the whole
        # tree. The mechanism differs between Windows and POSIX.
        if os.name == "nt":
            group_kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            group_kwargs = {"start_new_session": True}
        env = toolmanager.scan_env()  # locally installed tools on PATH

        def worker() -> None:
            try:
                # Binary pipe + os.read streams output as soon as it arrives,
                # so in-place progress (carriage returns, e.g. nuclei's
                # template download) shows up live instead of looking frozen.
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                    env=env,
                    **group_kwargs,
                )
            except OSError as exc:  # pragma: no cover - defensive
                self._output_q.put(f"[error] could not start process: {exc}\n")
                self._output_q.put(_Signal("scan_done"))
                return

            assert self._proc.stdout is not None
            fd = self._proc.stdout.fileno()
            line_buf = ""  # accumulate complete lines for finding detection
            while True:
                data = os.read(fd, 4096)
                if not data:
                    break
                text = data.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
                self._output_q.put(text)
                if source:
                    line_buf += text
                    while "\n" in line_buf:
                        line, line_buf = line_buf.split("\n", 1)
                        found = parse_tool_line(source, line)
                        if found:
                            self._output_q.put(_Finding(found))
            if source and line_buf.strip():
                found = parse_tool_line(source, line_buf)
                if found:
                    self._output_q.put(_Finding(found))
            self._proc.wait()
            self._output_q.put(f"\n[{label} finished, exit code {self._proc.returncode}]\n")
            self._output_q.put(_Signal("scan_done"))

        threading.Thread(target=worker, daemon=True).start()

    def stop_scan(self) -> None:
        # Signal cooperative cancellation for Python audit tasks.
        self._cancel.set()
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                # Kill the whole process tree so child scanners die too.
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        capture_output=True,
                    )
                else:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                proc.terminate()
        self._append("\n[stop requested]\n")

    # ------------------------------------------------------ tool install ---

    def _autostart_install(self) -> None:
        """On launch, offer to install any scanners that are missing."""
        missing = toolmanager.missing_tools()
        if missing:
            self._offer_install(missing)

    def _offer_install(self, tools: list[str]) -> None:
        if self._installing or self._scan_running:
            return
        names = ", ".join(tools)
        msg = (
            f"These scanners were not found: {names}.\n\n"
            f"Install them now into:\n{toolmanager.TOOLS_DIR}\n\n"
            "• nuclei: official release binary from GitHub.\n"
            "• nikto: source from GitHub (needs Perl installed to run).\n\n"
            "This downloads files from the internet. Proceed?"
        )
        if messagebox.askyesno("Install scanners?", msg):
            self._run_install(tools)

    def install_tools(self) -> None:
        """Manual button: (re)install both scanners."""
        if self._busy():
            return
        self._run_install(["nuclei", "nikto"])

    def _run_install(self, tools: list[str]) -> None:
        self._installing = True
        self._update_buttons()
        self.status_var.set("Installing tools…")

        def log(line: str) -> None:
            self._output_q.put(line + "\n")

        def worker() -> None:
            for tool in tools:
                installer = toolmanager.INSTALLERS.get(tool)
                if installer is None:
                    continue
                log(f"\n=== Installing {tool} ===")
                try:
                    installer(log)
                except Exception as exc:  # noqa: BLE001 - report any failure
                    log(f"[error] {tool} install failed: {exc}")
            self._output_q.put(_Signal("install_done"))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_output_queue(self) -> None:
        try:
            while True:
                item = self._output_q.get_nowait()
                if isinstance(item, _Signal):
                    if item.kind == "scan_done":
                        self._scan_running = False
                        self.status_var.set("Idle.")
                    elif item.kind == "install_done":
                        self._installing = False
                        self.status_var.set("Idle.")
                        self._refresh_tool_status()
                    self._update_buttons()
                elif isinstance(item, _Finding):
                    self._findings.append(item.data)
                    self._update_findings_count()
                else:
                    self._append(item)
        except queue.Empty:
            pass
        self.after(100, self._poll_output_queue)

    def _update_buttons(self) -> None:
        """Enable/disable buttons based on scan + install state."""
        idle = not self._scan_running and not self._installing
        state = "normal" if idle else "disabled"
        for btn in (
            self.nuclei_btn,
            self.nikto_btn,
            self.custom_btn,
            self.install_btn,
            self.data_exposure_btn,
            self.header_audit_btn,
            self.audit_all_btn,
            self.api_validate_btn,
        ):
            btn.configure(state=state)
        self.stop_btn.configure(state="normal" if self._scan_running else "disabled")

    # ---------------------------------------------------- findings (live) ---

    def _record(self, finding: dict) -> None:
        """Thread-safe: enqueue a finding to be collected on the main thread."""
        self._output_q.put(_Finding(finding))

    def _update_findings_count(self) -> None:
        self.findings_var.set(f"Findings: {len(self._findings)}")

    def clear_findings(self) -> None:
        self._findings.clear()
        self._update_findings_count()
        self.status_var.set("Findings cleared.")

    # -------------------------------------------------------- scripts UI ---

    def _choose_scripts_dir(self) -> None:
        chosen = filedialog.askdirectory(
            title="Select scripts folder",
            initialdir=str(self._scripts_dir if self._scripts_dir.exists() else Path.home()),
        )
        if chosen:
            self._scripts_dir = Path(chosen)
            self._load_scripts()

    def _load_scripts(self) -> None:
        scripts: list[str] = []
        if self._scripts_dir.is_dir():
            for entry in sorted(self._scripts_dir.iterdir()):
                if entry.is_file() and entry.suffix.lower() in (".py", ".sh", ".bash", ""):
                    scripts.append(entry.name)
        self.script_combo["values"] = scripts
        if scripts and not self.script_var.get():
            self.script_var.set(scripts[0])
        self._append(
            f"[scripts folder: {self._scripts_dir} — {len(scripts)} script(s)]\n"
        )

    # --------------------------------------------------------- output IO ---

    def _append(self, text: str) -> None:
        text = _ANSI_RE.sub("", text)
        self.output.configure(state="normal")
        self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    def clear_output(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")

    def save_output(self) -> None:
        default = f"scan-{datetime.now():%Y%m%d-%H%M%S}.txt"
        path = filedialog.asksaveasfilename(
            title="Save output", initialfile=default, defaultextension=".txt"
        )
        if path:
            Path(path).write_text(self.output.get("1.0", "end"), encoding="utf-8")
            self.status_var.set(f"Saved to {path}")

    # --------------------------------------------------- findings report ---

    def _collect_findings(self) -> dict:
        """Aggregate the live findings list into a report structure."""
        by = {s: [f for f in self._findings if f.get("source") == s]
              for s in ("nuclei", "nikto", "data_exposure", "headers", "api")}
        headers = {
            "missing": [f["header"] for f in by["headers"] if f.get("type") == "missing"],
            "weak": [{"header": f["header"], "note": f.get("note", "")}
                     for f in by["headers"] if f.get("type") == "weak"],
        }
        return {
            "target": self.url_var.get().strip(),
            "generated": datetime.now().isoformat(timespec="seconds"),
            "total_findings": len(self._findings),
            "nuclei": by["nuclei"],
            "nikto": by["nikto"],
            "data_exposure": by["data_exposure"],
            "security_headers": headers,
            "api_schema": by["api"],
        }

    @staticmethod
    def _render_markdown(f: dict) -> str:
        out = [
            "# FSSA Findings Report",
            "",
            f"- **Target:** {f['target']}",
            f"- **Generated:** {f['generated']}",
            f"- **Total findings:** {f['total_findings']}",
            "",
        ]
        if f["nuclei"]:
            out.append(f"## nuclei ({len(f['nuclei'])})")
            for n in f["nuclei"]:
                out.append(
                    f"- **[{n['severity']}]** `{n['template']}` "
                    f"({n['protocol']}) — {n['target']}"
                )
            out.append("")
        if f["nikto"]:
            out.append(f"## nikto ({len(f['nikto'])})")
            out += [f"- {item['detail']}" for item in f["nikto"]]
            out.append("")
        if f["data_exposure"]:
            out.append(f"## Data exposure ({len(f['data_exposure'])})")
            out += [f"- `{d['path']}` → {d['status']} OK" for d in f["data_exposure"]]
            out.append("")
        headers = f["security_headers"]
        if headers["missing"] or headers["weak"]:
            out.append("## Security headers")
            if headers["missing"]:
                out.append(f"**Missing ({len(headers['missing'])}):** "
                           + ", ".join(headers["missing"]))
            for w in headers["weak"]:
                out.append(f"- weak: {w['header']} — {w['note']}")
            out.append("")
        if f["api_schema"]:
            out.append(f"## API schema validation ({len(f['api_schema'])})")
            for a in f["api_schema"]:
                out.append(f"- `{a['variant']}` → {a['status']} — {a['leak']}")
                if a["detail"]:
                    out.append(f"  - {a['detail']}")
            out.append("")
        if f["total_findings"] == 0:
            out.append("_No findings parsed from the current output._")
        return "\n".join(out) + "\n"

    def save_report(self) -> None:
        findings = self._collect_findings()
        if findings["total_findings"] == 0 and not messagebox.askyesno(
            "No findings",
            "No findings were parsed from the output. Save an empty report anyway?",
        ):
            return
        default = f"fssa-report-{datetime.now():%Y%m%d-%H%M%S}.md"
        path = filedialog.asksaveasfilename(
            title="Save findings report",
            initialfile=default,
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        if path.lower().endswith(".json"):
            Path(path).write_text(json.dumps(findings, indent=2), encoding="utf-8")
        else:
            Path(path).write_text(self._render_markdown(findings), encoding="utf-8")
        self.status_var.set(
            f"Report saved ({findings['total_findings']} findings) to {path}"
        )

    # ----------------------------------------------------------- config ---

    def reload_config(self) -> None:
        if load_config(CONFIG_PATH, log=self._append):
            self.status_var.set(f"Config reloaded from {CONFIG_PATH.name}")
        else:
            self._append(f"[config] no config file at {CONFIG_PATH} (using defaults)\n")

    def _refresh_tool_status(self) -> None:
        nuclei = toolmanager.nuclei_cmd()
        nikto = toolmanager.nikto_cmd()
        self._append(
            "[tools] "
            f"nuclei: {'OK' if nuclei else 'missing'} | "
            f"nikto: {'OK' if nikto else 'missing'}\n"
        )
        if not nuclei or not nikto:
            self._append(
                "[tools] Use 'Install / update tools' to download the missing "
                "scanner(s) into the local tools folder.\n"
            )


def main() -> None:
    app = ScanLauncher()
    app.mainloop()


if __name__ == "__main__":
    main()
