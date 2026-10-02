"""Fissure desktop GUI (Tkinter).

A presentable front-end over the same Engine used by the CLI: paste a URL,
optionally add auth cookies / login, click Scan. The scan runs on a background
thread (the engine is async → run via asyncio.run in that thread) and streams
progress and findings back to the UI through a thread-safe queue.

Run:      python -m fissure.gui
Package:  see build_exe.py  ->  dist/Fissure.exe
"""

from __future__ import annotations

import asyncio
import queue
import threading
import webbrowser
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from . import __version__
from .engine import Engine
from .targets import ScopeError, TargetError

SEV_COLORS = {
    "critical": "#b00020", "high": "#d9480f", "medium": "#e8590c",
    "low": "#2b8a3e", "info": "#495057",
}


class FissureGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.q: queue.Queue = queue.Queue()
        self.report: dict | None = None
        self.html_path: str | None = None
        self._scanning = False

        root.title(f"Fissure {__version__} — Active Web Vulnerability Scanner")
        root.geometry("880x620")
        root.minsize(760, 520)

        self._build_header()
        self._build_controls()
        self._build_results()
        self._build_statusbar()

        self.root.after(120, self._drain_queue)

    # ---------- layout ----------
    def _build_header(self) -> None:
        bar = tk.Frame(self.root, bg="#12233b", height=58)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Label(bar, text="  🔎  Fissure", bg="#12233b", fg="white",
                 font=("Segoe UI", 16, "bold")).pack(side="left", padx=8)
        tk.Label(bar, text="Active web-application vulnerability scanner · authorized lab use only",
                 bg="#12233b", fg="#9fb3c8", font=("Segoe UI", 9)).pack(side="left", padx=6)

    def _build_controls(self) -> None:
        f = ttk.LabelFrame(self.root, text="Target")
        f.pack(fill="x", padx=12, pady=(12, 6))

        row1 = ttk.Frame(f); row1.pack(fill="x", padx=8, pady=6)
        ttk.Label(row1, text="URL:").pack(side="left")
        self.url_var = tk.StringVar(value="http://localhost:8080/")
        self.url_entry = ttk.Entry(row1, textvariable=self.url_var)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=6)
        self.scan_btn = ttk.Button(row1, text="Scan ▶", command=self.start_scan)
        self.scan_btn.pack(side="left")

        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=(0, 6))
        self.allow_public = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Allow public target (I have written authorization)",
                        variable=self.allow_public).pack(side="left")
        ttk.Label(row2, text="   Crawl depth:").pack(side="left")
        self.depth_var = tk.IntVar(value=1)
        ttk.Spinbox(row2, from_=0, to=4, width=3, textvariable=self.depth_var).pack(side="left")
        ttk.Label(row2, text="   Timeout(s):").pack(side="left")
        self.timeout_var = tk.DoubleVar(value=10.0)
        ttk.Spinbox(row2, from_=2, to=30, width=4, textvariable=self.timeout_var).pack(side="left")

        row3 = ttk.Frame(f); row3.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(row3, text="Cookies:").pack(side="left")
        self.cookie_var = tk.StringVar()
        ttk.Entry(row3, textvariable=self.cookie_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Label(row3, text="e.g. PHPSESSID=abc; security=low", foreground="#889").pack(side="left")

    def _build_results(self) -> None:
        f = ttk.LabelFrame(self.root, text="Findings")
        f.pack(fill="both", expand=True, padx=12, pady=6)

        cols = ("severity", "module", "title", "location")
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=12)
        for c, w in zip(cols, (90, 90, 300, 320)):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        for sev, color in SEV_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)
        sb = ttk.Scrollbar(f, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<<TreeviewSelect>>", self._show_evidence)

        self.evidence = tk.Text(self.root, height=4, wrap="word", bg="#f6f7f9", relief="flat")
        self.evidence.pack(fill="x", padx=12)
        self.evidence.insert("1.0", "Select a finding to see its evidence.")
        self.evidence.configure(state="disabled")

    def _build_statusbar(self) -> None:
        f = ttk.Frame(self.root); f.pack(fill="x", padx=12, pady=8)
        self.progress = ttk.Progressbar(f, mode="determinate", maximum=12)
        self.progress.pack(side="left", fill="x", expand=True)
        self.summary_lbl = ttk.Label(f, text="Idle", font=("Segoe UI", 9, "bold"))
        self.summary_lbl.pack(side="left", padx=10)
        self.html_btn = ttk.Button(f, text="Open HTML report", command=self._open_html, state="disabled")
        self.html_btn.pack(side="left", padx=4)
        self.save_btn = ttk.Button(f, text="Save JSON…", command=self._save_json, state="disabled")
        self.save_btn.pack(side="left")

    # ---------- scan control ----------
    def start_scan(self) -> None:
        if self._scanning:
            return
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Fissure", "Enter a target URL.")
            return
        cookies = self._parse_cookies(self.cookie_var.get())

        out = str(Path.cwd() / "fissure_report.json")
        try:
            engine = Engine(
                url, output=out, timeout=float(self.timeout_var.get()),
                allow_public=self.allow_public.get(), cookies=cookies,
                crawl_depth=int(self.depth_var.get()), html=True,
                progress=lambda stage, detail: self.q.put(("progress", stage, detail)),
            )
        except ScopeError as exc:
            messagebox.showerror("Scope refused", str(exc)); return
        except TargetError as exc:
            messagebox.showerror("Bad target", str(exc)); return

        self._reset_ui_for_scan()
        threading.Thread(target=self._worker, args=(engine,), daemon=True).start()

    def _worker(self, engine: Engine) -> None:
        try:
            report = asyncio.run(engine.run())
            self.q.put(("done", report))
        except Exception as exc:  # surfaced in the UI thread
            self.q.put(("error", f"{exc.__class__.__name__}: {exc}"))

    def _reset_ui_for_scan(self) -> None:
        self._scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning…")
        self.tree.delete(*self.tree.get_children())
        self.html_btn.configure(state="disabled")
        self.save_btn.configure(state="disabled")
        self.progress.configure(value=0)
        self.summary_lbl.configure(text="Starting…")

    # ---------- queue → UI ----------
    def _drain_queue(self) -> None:
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    self._on_progress(msg[1], msg[2])
                elif kind == "done":
                    self._on_done(msg[1])
                elif kind == "error":
                    self._on_error(msg[1])
        except queue.Empty:
            pass
        self.root.after(120, self._drain_queue)

    def _on_progress(self, stage: str, detail: str) -> None:
        labels = {"login": "Logging in…", "crawl": "Crawling…", "crawl_done": f"Crawled: {detail}",
                  "module_start": f"Testing {detail}…", "module_done": None}
        if stage in ("module_start", "module_done"):
            self.progress.step(1)
        text = labels.get(stage)
        if text:
            self.summary_lbl.configure(text=text)

    def _on_done(self, report: dict) -> None:
        self._scanning = False
        self.report = report
        self.html_path = report["outputs"].get("html")
        self.progress.configure(value=self.progress["maximum"])
        s = report["summary"]

        for mod in report["modules"].values():
            for fd in mod["findings"]:
                sev = fd["severity"].lower()
                title = fd["title"] + ("" if fd["confirmed"] else "  (heuristic)")
                self.tree.insert("", "end", tags=(sev,),
                                 values=(fd["severity"].upper(), mod["module"], title, fd["location"]))

        self.summary_lbl.configure(text=f"{s['label']} · {s['score']} pts · {s['total_findings']} findings")
        self.scan_btn.configure(state="normal", text="Scan ▶")
        self.html_btn.configure(state="normal" if self.html_path else "disabled")
        self.save_btn.configure(state="normal")
        if s["total_findings"] == 0:
            messagebox.showinfo("Fissure", "Scan complete — no findings.")

    def _on_error(self, message: str) -> None:
        self._scanning = False
        self.scan_btn.configure(state="normal", text="Scan ▶")
        self.summary_lbl.configure(text="Error")
        messagebox.showerror("Scan failed", message)

    # ---------- helpers ----------
    def _show_evidence(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel or not self.report:
            return
        vals = self.tree.item(sel[0], "values")
        module, title, loc = vals[1], vals[2], vals[3]
        ev = ""
        for fd in self.report["modules"].get(module, {}).get("findings", []):
            if fd["location"] == loc and title.startswith(fd["title"]):
                ev = fd["evidence"]; break
        self.evidence.configure(state="normal")
        self.evidence.delete("1.0", "end")
        self.evidence.insert("1.0", f"{loc}\n\n{ev}")
        self.evidence.configure(state="disabled")

    def _open_html(self) -> None:
        if self.html_path and Path(self.html_path).exists():
            webbrowser.open(Path(self.html_path).resolve().as_uri())

    def _save_json(self) -> None:
        if not self.report:
            return
        import json
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")], initialfile="fissure_report.json")
        if path:
            Path(path).write_text(json.dumps(self.report, indent=2), encoding="utf-8")
            messagebox.showinfo("Fissure", f"Saved to {path}")

    @staticmethod
    def _parse_cookies(raw: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for part in raw.replace(",", ";").split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out


def main() -> None:
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista")  # nicer on Windows; falls back if unavailable
    except tk.TclError:
        pass
    FissureGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
