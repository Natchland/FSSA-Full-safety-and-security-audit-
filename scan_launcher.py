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

import os
import queue
import shlex
import shutil
import signal
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


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

        # State for the currently running scan.
        self._proc: subprocess.Popen | None = None
        self._output_q: "queue.Queue[str | None]" = queue.Queue()
        self._scripts_dir = DEFAULT_SCRIPTS_DIR

        self._build_ui()
        self._refresh_tool_status()
        self._poll_output_queue()

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

        self.status_var = tk.StringVar(value="Idle.")
        ttk.Label(control, textvariable=self.status_var).pack(side="right")

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
        if self._proc is not None and self._proc.poll() is None:
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
        if not shutil.which("nuclei"):
            messagebox.showerror("Missing tool", "'nuclei' was not found on PATH.")
            return
        # Standard templates: nuclei ships them and auto-updates on first run.
        self._start(["nuclei", "-u", url], label="nuclei")

    def run_nikto(self) -> None:
        if self._busy():
            return
        url = self._valid_target()
        if not url:
            return
        if not shutil.which("nikto"):
            messagebox.showerror("Missing tool", "'nikto' was not found on PATH.")
            return
        self._start(["nikto", "-h", url], label="nikto")

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

    def _start(self, cmd: list[str], label: str) -> None:
        self._append(f"\n$ {' '.join(shlex.quote(c) for c in cmd)}\n")
        self.status_var.set(f"Running {label}…")
        self._set_running(True)

        # Put the child in its own process group so Stop can kill the whole
        # tree. The mechanism differs between Windows and POSIX.
        if os.name == "nt":
            group_kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            group_kwargs = {"start_new_session": True}

        def worker() -> None:
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    **group_kwargs,
                )
            except OSError as exc:  # pragma: no cover - defensive
                self._output_q.put(f"[error] could not start process: {exc}\n")
                self._output_q.put(None)
                return

            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                self._output_q.put(line)
            self._proc.wait()
            self._output_q.put(f"\n[{label} finished, exit code {self._proc.returncode}]\n")
            self._output_q.put(None)  # sentinel: scan done

        threading.Thread(target=worker, daemon=True).start()

    def stop_scan(self) -> None:
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
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

    def _poll_output_queue(self) -> None:
        try:
            while True:
                item = self._output_q.get_nowait()
                if item is None:
                    self._set_running(False)
                    self.status_var.set("Idle.")
                else:
                    self._append(item)
        except queue.Empty:
            pass
        self.after(100, self._poll_output_queue)

    def _set_running(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        for btn in (self.nuclei_btn, self.nikto_btn, self.custom_btn):
            btn.configure(state=state)
        self.stop_btn.configure(state="normal" if running else "disabled")

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

    def _refresh_tool_status(self) -> None:
        missing = [t for t in ("nuclei", "nikto") if not shutil.which(t)]
        if missing:
            self._append(
                f"[warning] not found on PATH: {', '.join(missing)}. "
                "Install them to enable those scans.\n"
            )


def main() -> None:
    app = ScanLauncher()
    app.mainloop()


if __name__ == "__main__":
    main()
