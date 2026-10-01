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

## Session-authenticated auditing

The **Custom Session Headers/Cookies** field lets you probe *authenticated*
endpoints to verify access-control logic. Enter one item per line:

```
Authorization: Bearer <token>
Cookie: session=abc; csrf=xyz
```

`Name: value` lines become request headers; bare `name=value` lines are
collected into a `Cookie` header. When the field is populated, those headers are
attached to **every dynamic probe** — the data-exposure scan, the security
header audit, and the API schema validator (including the OpenAPI spec fetch) —
and passed to **nuclei** via `-H`. Header values are **redacted** in the echoed
nuclei command so tokens don't land in the log or saved report.

> Implemented with the standard library (a shared header set applied to every
> request, equivalent to a `requests.Session` with default headers) to keep the
> tool dependency-free.

## Compliance & Data Exposure Audits (passive)

Built-in, dependency-free checks that run in-process and stream into the same
output window. They send only plain GET requests — no payloads, no
exploitation — and honor the authorization checkbox and the Stop button.

- **Data exposure scan** — concurrently probes a small, standard list of
  administrative/backup paths (`/.git/HEAD`, `/.env`, `/config.bak`,
  `/backup.sql`, …) relative to the target and flags any that return
  `200 OK`. Redirects are not followed, so a 301/302 to a login page is not
  mistaken for an exposed file. (200s can still be soft-404s — verify flagged
  paths manually.)
- **Security header audit** — inspects the target's response headers and does a
  gap analysis of key data-protection headers (HSTS, Content-Security-Policy,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy),
  including basic validity notes (e.g. HSTS `max-age=0`, CSP `unsafe-inline`).
- **Run both audits** — runs the header audit then the data exposure scan.

### Active API Schema Validator

> ⚠️ **Active check.** Unlike the passive audits above, this sends *mutated*
> requests to the target. Only run it against APIs you are authorized to test.

Maps endpoints from the target's `openapi.json` (or a custom list of routes)
and probes input handling by sending type-mutated and malformed payloads, then
flags responses that leak **raw database errors** or **verbose stack traces** —
a sign of improper input handling.

- **Endpoint source:** give an **OpenAPI URL/path** (blank defaults to
  `<target>/openapi.json`; a local file path also works), or a list of
  **custom routes** (one per line or comma-separated, optional method), e.g.
  `/api/v1/users/1` or `POST /api/v1/items`.
- **Mutations:** path/parameter type changes (integer → string, SQL quote,
  negative, overflow, null) and malformed/wrong-type JSON bodies (truncated
  JSON, trailing comma, non-JSON, wrong root type, type-swapped fields).
- **Detection:** flags `5xx` responses and bodies matching known DB-error or
  stack-trace signatures, with the offending line shown.
- **Bounded & cancellable:** capped at 25 endpoints / 300 requests by default,
  and the Stop button cancels it mid-run.

### Access-control diff (Broken Access Control — OWASP A01)

The highest-signal check for a report: it requests each endpoint **twice — with
the session and without it** — and flags where authorization isn't actually
enforced. Requires a session in the **Custom Session Headers/Cookies** field.

- **critical — `identical-response`:** the endpoint returns the *same* response
  with and without the session — the session is ignored, access control is
  effectively absent.
- **high — `anonymous-access`:** an anonymous caller still gets a `2xx` (with
  different content) — the endpoint should have required auth.
- **not flagged — `enforced`:** anonymous gets `401/403` while the session gets
  `2xx` — working as intended.

Endpoints come from the same OpenAPI/custom-routes inputs as the validator; with
no spec it falls back to the sensitive-path list. Findings appear in a dedicated
**Broken access control** section at the top of the report.

### Privilege-escalation diff (horizontal/vertical escalation)

Compares a **high-privilege** session against a **low-privilege** session to catch
cases where a lesser user reaches privileged data. Fill **both** the primary and
secondary session fields, then click **Privilege-escalation diff**.

- **critical — `privilege-escalation`:** the low-priv session gets the *same*
  response as the high-priv session — a regular user is reading privileged data.
- **medium — `low-priv-access-differs`:** the low-priv session also gets a `2xx`
  but with different content — review for horizontal access / IDOR (may be
  legitimate per-user scoping).
- **not flagged — `enforced`:** the low-priv session gets `401/403`.

Results appear in a dedicated **Privilege escalation** section at the top of the
report.

## Findings report

Findings are collected **live** as tools run — each scanner records structured
findings into a running list shown as **Findings: N** in the control row. This
is independent of the output log, so **Clear output** does not discard findings
and results **accumulate across multiple scans** in a session.

- **Save report…** exports the collected findings spanning nuclei, nikto, the
  data-exposure scan, the security-header audit, and the API schema validator.
  Choose a `.md` filename for Markdown or `.json` for structured JSON (pick the
  extension in the save dialog).
- **Clear findings** resets the collected list (separate from Clear output).
- **Save output…** still saves the full raw log separately.

## Configuration file

The path list, security headers, API mutations, and error signatures are all
editable without touching code. Copy `fssa_config.sample.json` to
`fssa_config.json` (next to `scan_launcher.py`, or point `FSSA_CONFIG` at it) and
edit any of these keys — each one present replaces that default:

| Key | Overrides |
|-----|-----------|
| `sensitive_paths` | data-exposure path list |
| `security_headers` | audited headers (name → description) |
| `api_path_mutations` | `[label, value]` pairs for path/param fuzzing |
| `api_malformed_bodies` | `[label, body]` pairs for JSON body fuzzing |
| `db_error_patterns` | DB-error regex signatures |
| `stack_trace_patterns` | stack-trace regex signatures |

Config loads automatically on launch; use **Reload config** to re-apply after
editing without restarting.

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
