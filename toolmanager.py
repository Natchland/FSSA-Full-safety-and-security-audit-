#!/usr/bin/env python3
"""
Tool manager for the FSSA Scan Launcher.

Detects and installs the external scanners the GUI drives (nuclei, nikto)
into a local ``tools/`` directory, without needing admin rights or a package
manager. Everything is fetched from the projects' official GitHub releases
using only the standard library.

- nuclei is a single Go binary; we download the release archive for the
  current OS/arch and extract the binary.
- nikto is a Perl script; we download the source archive and run it with the
  system Perl interpreter (Perl must be installed separately).

Each installer takes a ``log`` callable (``log(str) -> None``) so the GUI can
stream progress into its output pane.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable, Optional

# Where downloaded tools live. Override with FSSA_TOOLS_DIR.
TOOLS_DIR = Path(
    os.environ.get("FSSA_TOOLS_DIR", Path(__file__).resolve().parent / "tools")
)

_UA = {"User-Agent": "FSSA-Scan-Launcher"}
LogFn = Callable[[str], None]


# --------------------------------------------------------------- helpers ---

def _os_arch() -> tuple[str, str]:
    """Return (nuclei_os_tag, arch_tag) for the current machine."""
    system = platform.system()
    os_tag = {"Windows": "windows", "Linux": "linux", "Darwin": "macOS"}.get(
        system, system.lower()
    )
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("i386", "i686", "x86"):
        arch = "386"
    else:
        arch = machine
    return os_tag, arch


def _download(url: str, dest: Path, log: LogFn) -> None:
    """Download ``url`` to ``dest``, logging progress at ~20% steps."""
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
        total = int(resp.headers.get("Content-Length", 0))
        read = 0
        next_mark = 20
        while True:
            chunk = resp.read(64 * 1024)
            if not chunk:
                break
            fh.write(chunk)
            read += len(chunk)
            if total:
                pct = read * 100 // total
                if pct >= next_mark:
                    log(f"  …{pct}% ({read // 1024} KB)")
                    next_mark += 20
    log(f"  download complete ({read // 1024} KB)")


def _exe(name: str) -> str:
    return name + ".exe" if os.name == "nt" else name


# ------------------------------------------------------------- detection ---

def nuclei_cmd() -> Optional[list[str]]:
    """Return the command to run nuclei, or None if not available."""
    local = TOOLS_DIR / _exe("nuclei")
    if local.is_file():
        return [str(local)]
    found = shutil.which("nuclei")
    return [found] if found else None


def nikto_cmd() -> Optional[list[str]]:
    """Return the command to run nikto, or None if not available."""
    perl = shutil.which("perl")
    local_pl = TOOLS_DIR / "nikto" / "program" / "nikto.pl"
    if local_pl.is_file() and perl:
        return [perl, str(local_pl)]
    found = shutil.which("nikto")
    if found:
        return [found]
    found_pl = shutil.which("nikto.pl")
    if found_pl and perl:
        return [perl, found_pl]
    return None


def missing_tools() -> list[str]:
    missing = []
    if nuclei_cmd() is None:
        missing.append("nuclei")
    if nikto_cmd() is None:
        missing.append("nikto")
    return missing


# ------------------------------------------------------------ installers ---

def _latest_tag_via_redirect(repo: str) -> str:
    """Discover the latest release tag by following the /releases/latest redirect.

    Fallback for when the GitHub API is rate-limited (403). Returns e.g. 'v3.4.7'.
    """
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # noqa: D401, ANN002, ANN003
            return None

    url = f"https://github.com/{repo}/releases/latest"
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        opener.open(urllib.request.Request(url, headers=_UA), timeout=60)
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location", "")
        if "/tag/" in location:
            return location.rsplit("/tag/", 1)[1].strip()
    raise RuntimeError("could not resolve latest release tag")


def _nuclei_asset(os_tag: str, arch: str, log: LogFn) -> tuple[str, str]:
    """Return (asset_name, download_url) for nuclei, via API then redirect."""
    want = f"{os_tag}_{arch}"
    api = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
    try:
        with urllib.request.urlopen(
            urllib.request.Request(api, headers=_UA), timeout=60
        ) as r:
            release = json.load(r)
        asset = next(
            (a for a in release.get("assets", [])
             if a["name"].endswith(".zip") and want in a["name"]),
            None,
        )
        if asset is None:
            raise RuntimeError(f"no nuclei download found for {want}")
        return asset["name"], asset["browser_download_url"]
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        log(f"  GitHub API unavailable ({exc}); trying release redirect…")
        tag = _latest_tag_via_redirect("projectdiscovery/nuclei")
        version = tag.lstrip("v")
        name = f"nuclei_{version}_{want}.zip"
        url = f"https://github.com/projectdiscovery/nuclei/releases/download/{tag}/{name}"
        return name, url


def install_nuclei(log: LogFn) -> list[str]:
    """Download the official nuclei release binary into TOOLS_DIR."""
    os_tag, arch = _os_arch()
    log(f"Resolving latest nuclei release for {os_tag}_{arch}…")
    asset_name, download_url = _nuclei_asset(os_tag, arch, log)

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    archive = TOOLS_DIR / asset_name
    log(f"Downloading {asset_name}…")
    _download(download_url, archive, log)

    log("Extracting nuclei binary…")
    with zipfile.ZipFile(archive) as zf:
        for member in zf.namelist():
            if os.path.basename(member) in ("nuclei", "nuclei.exe"):
                target = TOOLS_DIR / _exe("nuclei")
                with zf.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                if os.name != "nt":
                    target.chmod(0o755)
                break
    archive.unlink(missing_ok=True)

    cmd = nuclei_cmd()
    if cmd is None:
        raise RuntimeError("nuclei binary missing after extraction")
    log(f"nuclei ready: {cmd[0]}")
    return cmd


def install_nikto(log: LogFn) -> list[str]:
    """Download nikto source into TOOLS_DIR (needs Perl to actually run)."""
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    url = "https://github.com/sullo/nikto/archive/refs/heads/master.zip"
    archive = TOOLS_DIR / "nikto-master.zip"
    log("Downloading nikto source…")
    _download(url, archive, log)

    log("Extracting nikto…")
    target = TOOLS_DIR / "nikto"
    if target.exists():
        shutil.rmtree(target)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(TOOLS_DIR)
    extracted = TOOLS_DIR / "nikto-master"
    if extracted.exists():
        extracted.rename(target)
    archive.unlink(missing_ok=True)

    if shutil.which("perl") is None:
        log("[warning] Perl was not found. nikto is a Perl script and needs Perl.")
        if os.name == "nt":
            log("  Install it with:  winget install StrawberryPerl.StrawberryPerl")
            log("  then restart your terminal and relaunch this app.")
        else:
            log("  Install perl with your package manager (e.g. apt install perl).")
        raise RuntimeError("nikto downloaded, but Perl is required to run it")

    cmd = nikto_cmd()
    if cmd is None:
        raise RuntimeError("nikto script missing after extraction")
    log(f"nikto ready: {' '.join(cmd)}")
    return cmd


INSTALLERS: dict[str, Callable[[LogFn], list[str]]] = {
    "nuclei": install_nuclei,
    "nikto": install_nikto,
}


def scan_env() -> dict[str, str]:
    """Environment for child scans, with TOOLS_DIR on PATH."""
    env = os.environ.copy()
    env["PATH"] = str(TOOLS_DIR) + os.pathsep + env.get("PATH", "")
    return env
