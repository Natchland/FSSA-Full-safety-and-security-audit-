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

- Python 3.9+ with Tkinter (`python3-tk` on Debian/Ubuntu).
- [`nuclei`](https://github.com/projectdiscovery/nuclei) and
  [`nikto`](https://github.com/sullo/nikto) on your `PATH` for those buttons.
  Missing tools are reported in the output pane; the rest of the GUI still works.

## Usage

```bash
python3 scan_launcher.py
```

1. Enter the target URL (e.g. `https://example.com`).
2. Tick **"I am authorized to scan this target."**
3. Click a scan button, or pick a custom script and click **Run script**.

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
