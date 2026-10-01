# FSSA Scan Launcher

A simple local **Tkinter** GUI for launching standard security scanners and
custom internal scripts against a target URL during authorized security audits.

> ⚠️ **Authorized use only.** Only scan targets you own or have explicit written
> permission to test. The GUI requires you to tick an authorization box before
> any scan runs.

## Features

- **Target URL field** with basic validation (scheme + host required).
- **Run nuclei** — runs the standard nuclei templates (`nuclei -u <url>`).
- **Run nikto** — runs a nikto web-server scan (`nikto -h <url>`).
- **Custom internal scripts** — pick any `.py`, `.sh`/`.bash`, or executable
  file from a scripts folder; it is run with the target URL as its first
  argument.
- Non-blocking: scans run in a background thread and stream output live.
- **Stop**, **Clear**, and **Save output** controls.

## Requirements

- Python 3.9+ with Tkinter (`python3-tk` on Debian/Ubuntu; included with the
  python.org installer on Windows/macOS).
- **The scanners are installed automatically** — see below. The only external
  dependency you may need to install yourself is **Perl**, which nikto requires
  to run.

## Usage

Launch with whatever Python command your machine uses:

```bash
python3 scan_launcher.py     # Linux / macOS
py scan_launcher.py          # Windows
```

1. Enter the target URL (e.g. `https://example.com`).
2. Tick **"I am authorized to scan this target."**
3. Click a scan button, or pick a custom script and click **Run script**.

### nuclei options

- **Severity** — tick which severities to run (`critical`/`high`/`medium` are
  on by default to cut noise). Passes `-severity`. Untick all to run every
  severity.
- **Tags** — comma-separated template tags to restrict the scan, e.g.
  `cves,misconfig`. Passes `-tags`. Leave blank to run all templates.

Narrowing severity and/or tags makes scans much faster and quieter — useful
against WAF/CDN-fronted hosts where the full 10k+ template set is overkill.

## Automatic tool installation

On launch, the app checks for `nuclei` and `nikto`. If either is missing it
offers to download it into a local `tools/` folder next to the script — no
admin rights, no package manager, and no PATH/terminal-restart needed. This
works the same on **Linux, Windows, and macOS**, so you can clone the repo on
any machine and it provisions itself.

- **nuclei** — the official release binary for your OS/arch is downloaded from
  GitHub and extracted into `tools/`.
- **nikto** — the source is downloaded into `tools/nikto/` and run via Perl.
  nikto is a Perl script, so Perl is also handled automatically:
  - **Windows:** if Perl is missing, a self-contained **portable Strawberry
    Perl** (~140 MB, one-time) is downloaded into `tools/perl/` — no installer,
    no admin rights, no PATH changes.
  - **Linux/macOS:** Perl is almost always preinstalled; if not, install it
    with your package manager (e.g. `sudo apt install perl`).

Use the **Install / update tools** button to re-download or update them later.
Override the download location with the `FSSA_TOOLS_DIR` environment variable.
The `tools/` folder is git-ignored.

## Custom scripts

By default the launcher looks in the `scripts/` folder next to
`scan_launcher.py`. Override it with the `FSSA_SCRIPTS_DIR` environment
variable, or pick a folder from the GUI (**Folder…**).

Each script receives the target URL as its first argument and writes results to
stdout/stderr. See [`scripts/example_headers_check.py`](scripts/example_headers_check.py)
for a dependency-free template.

```bash
FSSA_SCRIPTS_DIR=/path/to/my/scripts python3 scan_launcher.py
```
