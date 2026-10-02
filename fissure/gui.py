"""Fissure desktop GUI (Tkinter + ttk, stdlib only).

A polished multi-tab front-end over the same Engine/Agent used by the CLI:

  * Scan          — deterministic active scan (the original single-screen app,
                    reorganized): URL + options, color-coded findings, evidence.
  * AI Agent      — LLM-driven agent run with a live tool-trace log, an
                    authorization gate, findings table and executive summary.
  * Server & Ext  — start/stop the localhost scan service for the browser
                    extension and surface its bearer token.
  * Settings      — API keys (session only), default provider/model and scan
                    defaults that seed the other tabs.

Everything heavy runs on a background thread (Engine/Agent are async -> run via
asyncio.run in that thread) and streams progress/findings back to the Tk main
loop through a thread-safe queue polled with root.after. The Tk main loop is
never blocked.

Run:      python -m fissure.gui
Package:  see build_exe.py  ->  dist/Fissure.exe
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import threading
import webbrowser
from http.server import ThreadingHTTPServer
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from . import __version__
from .engine import Engine
from .targets import ScopeError, TargetError

# AI stack is optional at runtime (SDKs import lazily inside the clients), but the
# pure-Python wrappers import fine here. Guard anyway so a broken env still opens.
try:
    from .ai.agent import Agent
    from .ai.hive import Hive, Budget
    from .ai.llm import AnthropicClient, GeminiClient
    _AI_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - env-dependent
    Agent = Hive = Budget = AnthropicClient = GeminiClient = None  # type: ignore
    _AI_IMPORT_ERROR = f"{exc.__class__.__name__}: {exc}"

from . import server as server_mod

SEV_COLORS = {
    "critical": "#b00020", "high": "#d9480f", "medium": "#e8590c",
    "low": "#2b8a3e", "info": "#495057",
}

NAVY = "#12233b"
SUBTLE = "#9fb3c8"

# provider label -> (cli-style key, default model, env var, client class)
PROVIDERS = {
    "Gemini": ("gemini", "gemini-3.5-flash-lite", "GEMINI_API_KEY", GeminiClient),
    "Anthropic": ("anthropic", "claude-opus-5-5", "ANTHROPIC_API_KEY", AnthropicClient),
}


def parse_cookies(raw: str) -> dict[str, str]:
    """Shared cookie parser: 'PHPSESSID=abc; security=low' -> dict."""
    out: dict[str, str] = {}
    for part in (raw or "").replace(",", ";").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


class FissureGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.q: queue.Queue = queue.Queue()

        # ---- shared/session state ----
        self.scan_report: dict | None = None
        self.scan_html: str | None = None
        self._scanning = False

        self.ai_report: dict | None = None
        self.ai_html: str | None = None
        self._ai_running = False

        self.httpd: ThreadingHTTPServer | None = None
        self.server_thread: threading.Thread | None = None

        root.title(f"Fissure {__version__} - Active Web Vulnerability Scanner")
        root.geometry("920x680")
        root.minsize(820, 600)

        self._init_settings_vars()
        self._build_header()
        self._build_notebook()
        self._build_statusbar()

        self.root.after(120, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ================================================================= settings
    def _init_settings_vars(self) -> None:
        """Session-only configuration shared across tabs (not persisted to disk)."""
        self.gemini_key = tk.StringVar(value=os.environ.get("GEMINI_API_KEY", ""))
        self.anthropic_key = tk.StringVar(value=os.environ.get("ANTHROPIC_API_KEY", ""))
        self.default_provider = tk.StringVar(value="Gemini")
        self.default_gemini_model = tk.StringVar(value=PROVIDERS["Gemini"][1])
        self.default_anthropic_model = tk.StringVar(value=PROVIDERS["Anthropic"][1])
        self.default_depth = tk.IntVar(value=1)
        self.default_timeout = tk.DoubleVar(value=10.0)
        self.default_concurrency = tk.IntVar(value=8)

    def _api_key_for(self, provider_label: str) -> str:
        var = self.gemini_key if provider_label == "Gemini" else self.anthropic_key
        key = var.get().strip()
        if not key:  # env fallback
            key = os.environ.get(PROVIDERS[provider_label][2], "").strip()
        return key

    # =================================================================== layout
    def _build_header(self) -> None:
        bar = tk.Frame(self.root, bg=NAVY, height=58)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Label(bar, text="  \U0001f50e  Fissure", bg=NAVY, fg="white",
                 font=("Segoe UI", 16, "bold")).pack(side="left", padx=8)
        tk.Label(bar, text="Active web-application vulnerability scanner · authorized lab use only",
                 bg=NAVY, fg=SUBTLE, font=("Segoe UI", 9)).pack(side="left", padx=6)

    def _build_notebook(self) -> None:
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(8, 2))
        self.scan_tab = ttk.Frame(self.nb)
        self.ai_tab = ttk.Frame(self.nb)
        self.server_tab = ttk.Frame(self.nb)
        self.settings_tab = ttk.Frame(self.nb)
        self.nb.add(self.scan_tab, text="  Scan  ")
        self.nb.add(self.ai_tab, text="  AI Agent  ")
        self.nb.add(self.server_tab, text="  Server & Extension  ")
        self.nb.add(self.settings_tab, text="  Settings  ")
        self._build_scan_tab()
        self._build_ai_tab()
        self._build_server_tab()
        self._build_settings_tab()

    def _build_statusbar(self) -> None:
        f = ttk.Frame(self.root)
        f.pack(fill="x", padx=12, pady=(2, 8))
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(f, textvariable=self.status_var, font=("Segoe UI", 9)).pack(side="left")
        self.busy = ttk.Progressbar(f, mode="indeterminate", length=160)
        self.busy.pack(side="right")

    # ----------------------------------------------------------------- scan tab
    def _build_scan_tab(self) -> None:
        tab = self.scan_tab
        f = ttk.LabelFrame(tab, text="Target")
        f.pack(fill="x", padx=10, pady=(10, 6))

        row1 = ttk.Frame(f); row1.pack(fill="x", padx=8, pady=6)
        ttk.Label(row1, text="URL:").pack(side="left")
        self.scan_url = tk.StringVar(value="http://localhost:8080/")
        ttk.Entry(row1, textvariable=self.scan_url).pack(side="left", fill="x", expand=True, padx=6)
        self.scan_btn = ttk.Button(row1, text="Scan ▶", command=self.start_scan)
        self.scan_btn.pack(side="left")

        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=(0, 6))
        self.scan_allow_public = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Allow public target (I have written authorization)",
                        variable=self.scan_allow_public).pack(side="left")
        ttk.Label(row2, text="   Depth:").pack(side="left")
        self.scan_depth = tk.IntVar(value=self.default_depth.get())
        ttk.Spinbox(row2, from_=0, to=4, width=3, textvariable=self.scan_depth).pack(side="left")
        ttk.Label(row2, text="   Timeout(s):").pack(side="left")
        self.scan_timeout = tk.DoubleVar(value=self.default_timeout.get())
        ttk.Spinbox(row2, from_=2, to=60, width=4, textvariable=self.scan_timeout).pack(side="left")
        ttk.Label(row2, text="   Concurrency:").pack(side="left")
        self.scan_concurrency = tk.IntVar(value=self.default_concurrency.get())
        ttk.Spinbox(row2, from_=1, to=32, width=4, textvariable=self.scan_concurrency).pack(side="left")

        row3 = ttk.Frame(f); row3.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(row3, text="Cookies:").pack(side="left")
        self.scan_cookie = tk.StringVar()
        ttk.Entry(row3, textvariable=self.scan_cookie).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Label(row3, text="e.g. PHPSESSID=abc; security=low", foreground="#889").pack(side="left")

        res = ttk.LabelFrame(tab, text="Findings")
        res.pack(fill="both", expand=True, padx=10, pady=6)
        self.scan_tree, sb = self._make_findings_tree(res)
        self.scan_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.scan_tree.bind("<<TreeviewSelect>>", self._show_scan_evidence)

        ev = ttk.LabelFrame(tab, text="Evidence")
        ev.pack(fill="x", padx=10, pady=(0, 6))
        self.scan_evidence = tk.Text(ev, height=5, wrap="word", bg="#f6f7f9", relief="flat")
        self.scan_evidence.pack(fill="x", padx=4, pady=4)
        self.scan_evidence.insert("1.0", "Select a finding to see its evidence.")
        self.scan_evidence.configure(state="disabled")

        bar = ttk.Frame(tab); bar.pack(fill="x", padx=10, pady=(0, 10))
        self.scan_progress = ttk.Progressbar(bar, mode="determinate", maximum=12)
        self.scan_progress.pack(side="left", fill="x", expand=True)
        self.scan_summary = ttk.Label(bar, text="Idle", font=("Segoe UI", 9, "bold"))
        self.scan_summary.pack(side="left", padx=10)
        self.scan_html_btn = ttk.Button(bar, text="Open HTML report",
                                        command=lambda: self._open_html(self.scan_html), state="disabled")
        self.scan_html_btn.pack(side="left", padx=4)
        self.scan_save_btn = ttk.Button(bar, text="Save JSON…",
                                        command=lambda: self._save_json(self.scan_report), state="disabled")
        self.scan_save_btn.pack(side="left")

    # ------------------------------------------------------------------- ai tab
    def _build_ai_tab(self) -> None:
        tab = self.ai_tab
        f = ttk.LabelFrame(tab, text="AI agent run")
        f.pack(fill="x", padx=10, pady=(10, 6))

        row1 = ttk.Frame(f); row1.pack(fill="x", padx=8, pady=6)
        ttk.Label(row1, text="URL:").pack(side="left")
        self.ai_url = tk.StringVar(value="http://localhost:8080/")
        ttk.Entry(row1, textvariable=self.ai_url).pack(side="left", fill="x", expand=True, padx=6)
        self.ai_btn = ttk.Button(row1, text="Run AI Scan ▶", command=self.start_ai, state="disabled")
        self.ai_btn.pack(side="left")

        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=(0, 6))
        ttk.Label(row2, text="Provider:").pack(side="left")
        self.ai_provider = tk.StringVar(value=self.default_provider.get())
        prov = ttk.Combobox(row2, textvariable=self.ai_provider, state="readonly",
                            width=11, values=list(PROVIDERS.keys()))
        prov.pack(side="left", padx=(4, 8))
        prov.bind("<<ComboboxSelected>>", self._on_provider_change)
        ttk.Label(row2, text="Model:").pack(side="left")
        self.ai_model = tk.StringVar(value=self.default_gemini_model.get())
        ttk.Entry(row2, textvariable=self.ai_model, width=26).pack(side="left", padx=(4, 8))
        ttk.Label(row2, text="Max steps:").pack(side="left")
        self.ai_max_steps = tk.IntVar(value=40)
        ttk.Spinbox(row2, from_=5, to=200, width=5, textvariable=self.ai_max_steps).pack(side="left")

        row3 = ttk.Frame(f); row3.pack(fill="x", padx=8, pady=(0, 6))
        self.ai_allow_public = tk.BooleanVar(value=False)
        ttk.Checkbutton(row3, text="Allow public target", variable=self.ai_allow_public).pack(side="left")
        ttk.Label(row3, text="   Cookies:").pack(side="left")
        self.ai_cookie = tk.StringVar()
        ttk.Entry(row3, textvariable=self.ai_cookie).pack(side="left", fill="x", expand=True, padx=6)

        row4 = ttk.Frame(f); row4.pack(fill="x", padx=8, pady=(0, 8))
        self.ai_authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(row4, text="I am authorized to test this target (required)",
                        variable=self.ai_authorized, command=self._refresh_ai_btn).pack(side="left")

        self.ai_warn = ttk.Label(tab, text="", foreground="#b00020")
        self.ai_warn.pack(fill="x", padx=12)
        if _AI_IMPORT_ERROR:
            self.ai_warn.configure(text=f"AI stack unavailable: {_AI_IMPORT_ERROR}")

        mid = ttk.Frame(tab)
        mid.pack(fill="both", expand=True, padx=10, pady=4)

        trace_f = ttk.LabelFrame(mid, text="Tool trace")
        trace_f.pack(side="left", fill="both", expand=True, padx=(0, 4))
        self.ai_trace = tk.Text(trace_f, height=12, wrap="word", bg="#0f1b2d", fg="#d7e3f0",
                                relief="flat", font=("Consolas", 9))
        self.ai_trace.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        tsb = ttk.Scrollbar(trace_f, orient="vertical", command=self.ai_trace.yview)
        tsb.pack(side="right", fill="y")
        self.ai_trace.configure(yscrollcommand=tsb.set, state="disabled")

        find_f = ttk.LabelFrame(mid, text="Findings")
        find_f.pack(side="right", fill="both", expand=True, padx=(4, 0))
        self.ai_tree, asb = self._make_findings_tree(find_f, cols=("severity", "title", "location"))
        self.ai_tree.pack(side="left", fill="both", expand=True)
        asb.pack(side="right", fill="y")

        exec_f = ttk.LabelFrame(tab, text="Executive summary")
        exec_f.pack(fill="x", padx=10, pady=(2, 6))
        self.ai_exec = tk.Text(exec_f, height=5, wrap="word", bg="#f6f7f9", relief="flat")
        self.ai_exec.pack(fill="x", padx=4, pady=4)
        self.ai_exec.configure(state="disabled")

        bar = ttk.Frame(tab); bar.pack(fill="x", padx=10, pady=(0, 10))
        self.ai_status = ttk.Label(bar, text="Idle", font=("Segoe UI", 9, "bold"))
        self.ai_status.pack(side="left")
        self.ai_html_btn = ttk.Button(bar, text="Open HTML report",
                                      command=lambda: self._open_html(self.ai_html), state="disabled")
        self.ai_html_btn.pack(side="right", padx=4)
        self.ai_save_btn = ttk.Button(bar, text="Save JSON…",
                                      command=lambda: self._save_json(self.ai_report), state="disabled")
        self.ai_save_btn.pack(side="right")
        self._refresh_ai_btn()

    # --------------------------------------------------------------- server tab
    def _build_server_tab(self) -> None:
        tab = self.server_tab
        f = ttk.LabelFrame(tab, text="Localhost scan service")
        f.pack(fill="x", padx=10, pady=(10, 6))

        row1 = ttk.Frame(f); row1.pack(fill="x", padx=8, pady=8)
        self.server_btn = ttk.Button(row1, text="Start server", command=self.toggle_server)
        self.server_btn.pack(side="left")
        self.server_state = ttk.Label(row1, text="Stopped", font=("Segoe UI", 9, "bold"),
                                      foreground="#b00020")
        self.server_state.pack(side="left", padx=12)

        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=(0, 6))
        ttk.Label(row2, text="URL:").pack(side="left")
        self.server_url = tk.StringVar(value="http://127.0.0.1:8750")
        ttk.Entry(row2, textvariable=self.server_url, state="readonly", width=28).pack(side="left", padx=6)

        row3 = ttk.Frame(f); row3.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(row3, text="Bearer token:").pack(side="left")
        self.server_token = tk.StringVar(value="(start the server to generate)")
        tok = ttk.Entry(row3, textvariable=self.server_token, state="readonly")
        tok.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(row3, text="Copy token", command=self._copy_token).pack(side="left")

        steps = ttk.LabelFrame(tab, text="Load the browser extension")
        steps.pack(fill="both", expand=True, padx=10, pady=6)
        ext_dir = (Path(__file__).resolve().parent.parent / "extension")
        txt = (
            "1. Start the server above.\n"
            "2. Open Chrome and go to  chrome://extensions\n"
            "3. Toggle on  Developer mode  (top-right).\n"
            "4. Click  Load unpacked  and select the extension folder:\n"
            f"       {ext_dir}\n"
            "5. Open the Fissure extension and paste the bearer token shown above.\n"
            "6. Browse to a target you are authorized to test and start a scan from the\n"
            "   extension. Each scan still requires an explicit authorization step.\n"
        )
        t = tk.Text(steps, height=10, wrap="word", bg="#f6f7f9", relief="flat")
        t.pack(fill="both", expand=True, padx=4, pady=4)
        t.insert("1.0", txt)
        t.configure(state="disabled")

    # ------------------------------------------------------------- settings tab
    def _build_settings_tab(self) -> None:
        tab = self.settings_tab
        keys = ttk.LabelFrame(tab, text="API keys (kept in memory for this session only)")
        keys.pack(fill="x", padx=10, pady=(10, 6))

        r1 = ttk.Frame(keys); r1.pack(fill="x", padx=8, pady=6)
        ttk.Label(r1, text="GEMINI_API_KEY:", width=18).pack(side="left")
        ttk.Entry(r1, textvariable=self.gemini_key, show="•").pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(r1, text="Test key", command=lambda: self._test_key("Gemini")).pack(side="left")

        r2 = ttk.Frame(keys); r2.pack(fill="x", padx=8, pady=6)
        ttk.Label(r2, text="ANTHROPIC_API_KEY:", width=18).pack(side="left")
        ttk.Entry(r2, textvariable=self.anthropic_key, show="•").pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(r2, text="Test key", command=lambda: self._test_key("Anthropic")).pack(side="left")

        r3 = ttk.Frame(keys); r3.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(r3, text="Apply keys to this session", command=self._apply_keys).pack(side="left")
        ttk.Label(r3, text="  (also pushed into os.environ; never written to disk)",
                  foreground="#889").pack(side="left")

        defs = ttk.LabelFrame(tab, text="Defaults (seed the Scan and AI tabs when opened)")
        defs.pack(fill="x", padx=10, pady=6)

        d1 = ttk.Frame(defs); d1.pack(fill="x", padx=8, pady=6)
        ttk.Label(d1, text="Default provider:").pack(side="left")
        ttk.Combobox(d1, textvariable=self.default_provider, state="readonly", width=11,
                     values=list(PROVIDERS.keys())).pack(side="left", padx=(4, 12))
        ttk.Label(d1, text="Gemini model:").pack(side="left")
        ttk.Entry(d1, textvariable=self.default_gemini_model, width=24).pack(side="left", padx=4)

        d2 = ttk.Frame(defs); d2.pack(fill="x", padx=8, pady=6)
        ttk.Label(d2, text="Anthropic model:").pack(side="left")
        ttk.Entry(d2, textvariable=self.default_anthropic_model, width=24).pack(side="left", padx=(4, 12))

        d3 = ttk.Frame(defs); d3.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(d3, text="Crawl depth:").pack(side="left")
        ttk.Spinbox(d3, from_=0, to=4, width=3, textvariable=self.default_depth).pack(side="left", padx=(4, 10))
        ttk.Label(d3, text="Timeout(s):").pack(side="left")
        ttk.Spinbox(d3, from_=2, to=60, width=4, textvariable=self.default_timeout).pack(side="left", padx=(4, 10))
        ttk.Label(d3, text="Concurrency:").pack(side="left")
        ttk.Spinbox(d3, from_=1, to=32, width=4, textvariable=self.default_concurrency).pack(side="left", padx=4)

        apply = ttk.Frame(tab); apply.pack(fill="x", padx=10, pady=6)
        ttk.Button(apply, text="Apply defaults to Scan/AI tabs", command=self._apply_defaults).pack(side="left")

        note = ttk.Label(tab, foreground="#555", wraplength=820, justify="left",
                         text=("Keys are held only for this session. 'Apply keys' pushes them into this "
                               "process's environment so the LLM clients and any subprocess can read them; "
                               "nothing is written to disk. Gemini free tier works with "
                               "gemini-3.5-flash-lite (gemini-3.5-flash refuses this task)."))
        note.pack(fill="x", padx=14, pady=(8, 10))

    # ============================================================= findings tree
    def _make_findings_tree(self, parent, cols=("severity", "module", "title", "location")):
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=12)
        widths = {"severity": 90, "module": 90, "title": 280, "location": 300}
        for c in cols:
            tree.heading(c, text=c.title())
            tree.column(c, width=widths.get(c, 140), anchor="w")
        for sev, color in SEV_COLORS.items():
            tree.tag_configure(sev, foreground=color)
        sb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        return tree, sb

    # ============================================================= scan control
    def start_scan(self) -> None:
        if self._scanning:
            return
        url = self.scan_url.get().strip()
        if not url:
            messagebox.showwarning("Fissure", "Enter a target URL.")
            return
        cookies = parse_cookies(self.scan_cookie.get())
        out = str(Path.cwd() / "fissure_report.json")
        try:
            engine = Engine(
                url, output=out, timeout=float(self.scan_timeout.get()),
                allow_public=self.scan_allow_public.get(), cookies=cookies,
                crawl_depth=int(self.scan_depth.get()),
                concurrency=int(self.scan_concurrency.get()), html=True,
                progress=lambda stage, detail: self.q.put(("scan_progress", stage, detail)),
            )
        except ScopeError as exc:
            messagebox.showerror("Scope refused", str(exc)); return
        except TargetError as exc:
            messagebox.showerror("Bad target", str(exc)); return

        self._scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning…")
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.scan_html_btn.configure(state="disabled")
        self.scan_save_btn.configure(state="disabled")
        self.scan_progress.configure(value=0)
        self.scan_summary.configure(text="Starting…")
        self._set_busy(True, "Scanning target…")
        threading.Thread(target=self._scan_worker, args=(engine,), daemon=True).start()

    def _scan_worker(self, engine: Engine) -> None:
        try:
            report = asyncio.run(engine.run())
            self.q.put(("scan_done", report))
        except Exception as exc:
            self.q.put(("scan_error", f"{exc.__class__.__name__}: {exc}"))

    def _on_scan_progress(self, stage: str, detail: str) -> None:
        labels = {"login": "Logging in…", "crawl": "Crawling…",
                  "crawl_done": f"Crawled: {detail}", "module_start": f"Testing {detail}…",
                  "module_done": None}
        if stage in ("module_start", "module_done"):
            self.scan_progress.step(1)
        text = labels.get(stage)
        if text:
            self.scan_summary.configure(text=text)
            self.status_var.set(text)

    def _on_scan_done(self, report: dict) -> None:
        self._scanning = False
        self.scan_report = report
        self.scan_html = report["outputs"].get("html")
        self.scan_progress.configure(value=self.scan_progress["maximum"])
        s = report["summary"]
        for mod in report["modules"].values():
            for fd in mod["findings"]:
                self._insert_finding(self.scan_tree, fd, module=mod["module"])
        self.scan_summary.configure(text=f"{s['label']} · {s['score']} pts · {s['total_findings']} findings")
        self.scan_btn.configure(state="normal", text="Scan ▶")
        self.scan_html_btn.configure(state="normal" if self.scan_html else "disabled")
        self.scan_save_btn.configure(state="normal")
        self._set_busy(False, "Scan complete")
        if s["total_findings"] == 0:
            messagebox.showinfo("Fissure", "Scan complete - no findings.")

    def _on_scan_error(self, message: str) -> None:
        self._scanning = False
        self.scan_btn.configure(state="normal", text="Scan ▶")
        self.scan_summary.configure(text="Error")
        self._set_busy(False, "Scan failed")
        messagebox.showerror("Scan failed", message)

    def _show_scan_evidence(self, _event=None) -> None:
        sel = self.scan_tree.selection()
        if not sel or not self.scan_report:
            return
        vals = self.scan_tree.item(sel[0], "values")
        module, title, loc = vals[1], vals[2], vals[3]
        ev = ""
        for fd in self.scan_report["modules"].get(module, {}).get("findings", []):
            if fd["location"] == loc and title.startswith(fd["title"]):
                ev = fd["evidence"]; break
        self.scan_evidence.configure(state="normal")
        self.scan_evidence.delete("1.0", "end")
        self.scan_evidence.insert("1.0", f"{loc}\n\n{ev}")
        self.scan_evidence.configure(state="disabled")

    # =============================================================== ai control
    def _on_provider_change(self, _event=None) -> None:
        prov = self.ai_provider.get()
        model = (self.default_gemini_model.get() if prov == "Gemini"
                 else self.default_anthropic_model.get())
        self.ai_model.set(model)
        self._refresh_ai_btn()

    def _refresh_ai_btn(self) -> None:
        ok = (not _AI_IMPORT_ERROR) and self.ai_authorized.get() and not self._ai_running
        self.ai_btn.configure(state="normal" if ok else "disabled")

    def start_ai(self) -> None:
        if self._ai_running or _AI_IMPORT_ERROR:
            return
        if not self.ai_authorized.get():
            messagebox.showwarning("Fissure", "You must confirm authorization first.")
            return
        url = self.ai_url.get().strip()
        if not url:
            messagebox.showwarning("Fissure", "Enter a target URL.")
            return
        provider = self.ai_provider.get()
        model = self.ai_model.get().strip() or PROVIDERS[provider][1]
        key = self._api_key_for(provider)
        if not key:
            self.ai_warn.configure(text=f"No API key for {provider}. Add it in the Settings tab.")
            return
        self.ai_warn.configure(text="")
        cookies = parse_cookies(self.ai_cookie.get())
        out = str(Path.cwd() / "fissure_ai_report.json")
        max_steps = int(self.ai_max_steps.get())

        # Pre-validate scope/target on the UI thread so errors surface immediately.
        try:
            client_cls = PROVIDERS[provider][3]
            brain = client_cls(model, tier="brain", api_key=key)
            hive = Hive(brain, budget=Budget(max_steps=max_steps))
            agent = Agent(
                url, hive, allow_public=self.ai_allow_public.get(), cookies=cookies,
                output=out, html=True, sarif=True,
                approval_cb=self._ai_approval_cb,
                progress=lambda stage, detail: self.q.put(("ai_prog", stage, detail)),
            )
        except ScopeError as exc:
            messagebox.showerror("Scope refused", str(exc)); return
        except TargetError as exc:
            messagebox.showerror("Bad target", str(exc)); return
        except Exception as exc:
            messagebox.showerror("AI setup failed", f"{exc.__class__.__name__}: {exc}"); return

        self._ai_running = True
        self._refresh_ai_btn()
        self.ai_btn.configure(text="Running…")
        self.ai_tree.delete(*self.ai_tree.get_children())
        self.ai_html_btn.configure(state="disabled")
        self.ai_save_btn.configure(state="disabled")
        self._set_text(self.ai_exec, "")
        self._clear_trace()
        self._append_trace(f"[start] {provider} / {model}  max_steps={max_steps}")
        self.ai_status.configure(text="Running…")
        self._set_busy(True, "AI agent running…")
        threading.Thread(target=self._ai_worker, args=(agent, out), daemon=True).start()

    def _ai_worker(self, agent, out_path: str) -> None:
        try:
            result = asyncio.run(agent.run())
            report = None
            json_path = (result.get("outputs") or {}).get("json") or out_path
            try:
                report = json.loads(Path(json_path).read_text(encoding="utf-8"))
            except Exception:
                report = None
            self.q.put(("ai_done", result, report))
        except Exception as exc:
            self.q.put(("ai_error", f"{exc.__class__.__name__}: {exc}"))

    def _ai_approval_cb(self, request: dict) -> bool:
        """Called from the worker thread. Marshal a yes/no modal onto the UI thread
        and block until the operator answers (never touch Tk off the main thread)."""
        event = threading.Event()
        box: dict = {}
        self.q.put(("ai_approval", request, box, event))
        event.wait()
        return bool(box.get("result", False))

    def _handle_ai_approval(self, request: dict, box: dict, event: threading.Event) -> None:
        # Runs on the UI thread (from the queue drain).
        try:
            method = request.get("method", "?")
            url = request.get("url", "?")
            intent = request.get("intent", "")
            msg = (f"The AI agent wants to perform a state-changing action:\n\n"
                   f"  {method}  {url}\n"
                   f"  intent: {intent or '(none given)'}\n\n"
                   f"Approve this action?")
            self._append_trace(f"[approval] {method} {url}")
            answer = messagebox.askyesno("Approve state-changing action?", msg, default="no")
            box["result"] = answer
            self._append_trace(f"[approval] -> {'approved' if answer else 'declined'}")
        finally:
            event.set()

    def _on_ai_prog(self, stage: str, detail: str) -> None:
        arrow = {"tool": f"→ {detail}", "login": "login", "crawl": "crawl",
                 "crawl_done": f"crawled {detail}", "module_start": f"module {detail} start",
                 "module_done": f"module {detail} done", "auth_lost": "AUTH LOST - re-authenticating"}
        self._append_trace(arrow.get(stage, f"{stage} {detail}".strip()))
        self.status_var.set(f"AI: {stage} {detail}".strip())

    def _on_ai_done(self, result: dict, report: dict | None) -> None:
        self._ai_running = False
        self.ai_report = report
        self.ai_html = (result.get("outputs") or {}).get("html")
        findings = result.get("findings", 0)
        stop = result.get("stop", "")
        steps = result.get("steps", 0)
        self._append_trace(f"[done] findings={findings} steps={steps} stop={stop}")
        if report:
            for mod in report.get("modules", {}).values():
                for fd in mod["findings"]:
                    self._insert_finding(self.ai_tree, fd, cols=("severity", "title", "location"))
            self._set_text(self.ai_exec, report.get("executive_summary", "") or "(no executive summary)")
        self.ai_status.configure(text=f"Done · {findings} findings · {steps} steps · {stop}")
        self.ai_btn.configure(text="Run AI Scan ▶")
        self.ai_html_btn.configure(state="normal" if self.ai_html else "disabled")
        self.ai_save_btn.configure(state="normal" if report else "disabled")
        self._refresh_ai_btn()
        self._set_busy(False, "AI scan complete")

    def _on_ai_error(self, message: str) -> None:
        self._ai_running = False
        self.ai_btn.configure(text="Run AI Scan ▶")
        self.ai_status.configure(text="Error")
        self._append_trace(f"[error] {message}")
        self._refresh_ai_btn()
        self._set_busy(False, "AI scan failed")
        messagebox.showerror("AI scan failed", message)

    def _clear_trace(self) -> None:
        self.ai_trace.configure(state="normal")
        self.ai_trace.delete("1.0", "end")
        self.ai_trace.configure(state="disabled")

    def _append_trace(self, line: str) -> None:
        self.ai_trace.configure(state="normal")
        self.ai_trace.insert("end", line + "\n")
        self.ai_trace.see("end")
        self.ai_trace.configure(state="disabled")

    # =========================================================== server control
    def toggle_server(self) -> None:
        if self.httpd is None:
            self._start_server()
        else:
            self._stop_server()

    def _start_server(self) -> None:
        try:
            server_mod._REPORT_DIR.mkdir(parents=True, exist_ok=True)
            self.httpd = ThreadingHTTPServer(("127.0.0.1", 8750), server_mod.Handler)
        except OSError as exc:
            messagebox.showerror("Server", f"Could not start on 127.0.0.1:8750\n{exc}")
            self.httpd = None
            return
        self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.server_thread.start()
        self.server_token.set(server_mod.TOKEN)
        self.server_url.set("http://127.0.0.1:8750")
        self.server_btn.configure(text="Stop server")
        self.server_state.configure(text="Running", foreground="#2b8a3e")
        self.status_var.set("Server running on http://127.0.0.1:8750")

    def _stop_server(self) -> None:
        if self.httpd is not None:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
            self.server_thread = None
        self.server_btn.configure(text="Start server")
        self.server_state.configure(text="Stopped", foreground="#b00020")
        self.server_token.set("(start the server to generate)")
        self.status_var.set("Server stopped")

    def _copy_token(self) -> None:
        tok = self.server_token.get()
        if tok and not tok.startswith("("):
            self.root.clipboard_clear()
            self.root.clipboard_append(tok)
            self.status_var.set("Token copied to clipboard")

    # ========================================================== settings actions
    def _apply_keys(self) -> None:
        g, a = self.gemini_key.get().strip(), self.anthropic_key.get().strip()
        if g:
            os.environ["GEMINI_API_KEY"] = g
        if a:
            os.environ["ANTHROPIC_API_KEY"] = a
        self.status_var.set("API keys applied to this session")
        messagebox.showinfo("Fissure", "Keys applied for this session (in-memory + os.environ).")

    def _apply_defaults(self) -> None:
        self.scan_depth.set(self.default_depth.get())
        self.scan_timeout.set(self.default_timeout.get())
        self.scan_concurrency.set(self.default_concurrency.get())
        self.ai_provider.set(self.default_provider.get())
        self._on_provider_change()
        self.status_var.set("Defaults applied to Scan/AI tabs")

    def _test_key(self, provider: str) -> None:
        if _AI_IMPORT_ERROR:
            messagebox.showwarning("Fissure", f"AI stack unavailable: {_AI_IMPORT_ERROR}")
            return
        key = self._api_key_for(provider)
        if not key:
            messagebox.showwarning("Fissure", f"Enter a {provider} key first.")
            return
        self._set_busy(True, f"Testing {provider} key…")
        model = (self.default_gemini_model.get() if provider == "Gemini"
                 else self.default_anthropic_model.get())
        threading.Thread(target=self._test_key_worker, args=(provider, model, key), daemon=True).start()

    def _test_key_worker(self, provider: str, model: str, key: str) -> None:
        try:
            client_cls = PROVIDERS[provider][3]
            client = client_cls(model, tier="brain", api_key=key)
            resp = client.complete(system="Reply with OK.",
                                   messages=[{"role": "user", "content": "ping"}], max_tokens=16)
            ok = resp is not None
            self.q.put(("key_test", provider, ok, resp.text or "(no text)" if ok else ""))
        except Exception as exc:
            self.q.put(("key_test_err", provider, f"{exc.__class__.__name__}: {exc}"))

    # ============================================================= shared helpers
    def _insert_finding(self, tree, fd: dict, module: str | None = None,
                        cols=("severity", "module", "title", "location")) -> None:
        sev = fd["severity"].lower()
        title = fd["title"] + ("" if fd.get("confirmed", True) else "  (heuristic)")
        if "module" in cols:
            values = (fd["severity"].upper(), module or "", title, fd["location"])
        else:
            values = (fd["severity"].upper(), title, fd["location"])
        tree.insert("", "end", tags=(sev,), values=values)

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _set_busy(self, busy: bool, status: str | None = None) -> None:
        if busy:
            self.busy.start(12)
        else:
            self.busy.stop()
        if status is not None:
            self.status_var.set(status)

    def _open_html(self, path: str | None) -> None:
        if path and Path(path).exists():
            webbrowser.open(Path(path).resolve().as_uri())
        else:
            messagebox.showwarning("Fissure", "No HTML report available.")

    def _save_json(self, report: dict | None) -> None:
        if not report:
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")], initialfile="fissure_report.json")
        if path:
            Path(path).write_text(json.dumps(report, indent=2), encoding="utf-8")
            messagebox.showinfo("Fissure", f"Saved to {path}")

    # ================================================================ queue pump
    def _drain_queue(self) -> None:
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "scan_progress":
                    self._on_scan_progress(msg[1], msg[2])
                elif kind == "scan_done":
                    self._on_scan_done(msg[1])
                elif kind == "scan_error":
                    self._on_scan_error(msg[1])
                elif kind == "ai_prog":
                    self._on_ai_prog(msg[1], msg[2])
                elif kind == "ai_done":
                    self._on_ai_done(msg[1], msg[2])
                elif kind == "ai_error":
                    self._on_ai_error(msg[1])
                elif kind == "ai_approval":
                    self._handle_ai_approval(msg[1], msg[2], msg[3])
                elif kind == "key_test":
                    _, provider, ok, text = msg
                    self._set_busy(False, f"{provider} key OK")
                    messagebox.showinfo("Fissure", f"{provider} key works.\nReply: {text[:120]}")
                elif kind == "key_test_err":
                    _, provider, err = msg
                    self._set_busy(False, f"{provider} key failed")
                    messagebox.showerror("Key test failed", f"{provider}: {err}")
        except queue.Empty:
            pass
        self.root.after(120, self._drain_queue)

    def _on_close(self) -> None:
        self._stop_server()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    try:
        style = ttk.Style()
        themes = style.theme_names()
        style.theme_use("vista" if "vista" in themes else style.theme_use())
    except tk.TclError:
        pass
    FissureGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
