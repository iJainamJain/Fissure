"""Fissure desktop GUI (CustomTkinter — modern flat dark UI).

A polished front-end over the same Engine/Agent used by the CLI, organized as a
left vertical navigation sidebar that swaps the main content area between four
sections:

  * Scan          — deterministic active scan: URL + options, color-coded
                    findings, evidence.
  * AI Agent      — LLM-driven agent run with a live tool-trace log, an
                    authorization gate, findings table and executive summary.
  * Server & Ext  — start/stop the localhost scan service for the browser
                    extension and surface its bearer token.
  * Settings      — API keys (session only), default provider/model, scan
                    defaults and an appearance (Dark/Light) toggle.

Everything heavy runs on a background daemon thread (Engine/Agent are async ->
run via asyncio.run in that thread) and streams progress/findings back to the Tk
main loop through a thread-safe queue polled with root.after. The Tk main loop is
never blocked and widgets are only ever touched from the main thread.

The findings table is a ttk.Treeview (CustomTkinter has no table widget) styled
with ttk.Style + the "clam" base theme so dark background/foreground/field colors
actually apply; severity colors remain per-row via tree.tag_configure.

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

import customtkinter as ctk

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

# Severity colors tuned for a dark background.
SEV_COLORS = {
    "critical": "#e5484d", "high": "#f76808", "medium": "#f5a623",
    "low": "#46a758", "info": "#8b98a5",
}

# Accent used for primary call-to-action buttons.
ACCENT = "#2f6df6"
ACCENT_HOVER = "#2457c9"

# Card styling: a rounded panel that reads as a grouped section.
CARD_RADIUS = 12
CARD_PAD = 16
INNER_PAD = 12

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
    def __init__(self, root: ctk.CTk) -> None:
        self.root = root
        self.q: queue.Queue = queue.Queue()

        # ---- shared/session state ----
        self.scan_report: dict | None = None
        self.scan_html: str | None = None
        self._scanning = False
        self._scan_max = 12
        self._scan_steps = 0

        self.ai_report: dict | None = None
        self.ai_html: str | None = None
        self._ai_running = False

        self.httpd: ThreadingHTTPServer | None = None
        self.server_thread: threading.Thread | None = None

        root.title(f"Fissure {__version__} - Active Web Vulnerability Scanner")
        root.geometry("1000x720")
        root.minsize(900, 640)

        self._fonts = {
            "logo": ctk.CTkFont(size=22, weight="bold"),
            "nav": ctk.CTkFont(size=14),
            "card_title": ctk.CTkFont(size=13, weight="bold"),
            "status": ctk.CTkFont(size=12),
            "mono": ctk.CTkFont(family="Consolas", size=12),
            "bold": ctk.CTkFont(size=12, weight="bold"),
        }

        self._init_settings_vars()
        self._style_treeview()

        # root layout: sidebar (col 0) + content (col 1); status bar spans both.
        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_content()
        self._build_statusbar()

        self._build_scan_section(self.sections["scan"])
        self._build_ai_section(self.sections["ai"])
        self._build_server_section(self.sections["server"])
        self._build_settings_section(self.sections["settings"])

        self._select_section("scan")

        self.root.after(120, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ================================================================= settings
    def _init_settings_vars(self) -> None:
        """Session-only configuration shared across sections (never persisted)."""
        self.gemini_key = tk.StringVar(value=os.environ.get("GEMINI_API_KEY", ""))
        self.anthropic_key = tk.StringVar(value=os.environ.get("ANTHROPIC_API_KEY", ""))
        self.default_provider = tk.StringVar(value="Gemini")
        self.default_gemini_model = tk.StringVar(value=PROVIDERS["Gemini"][1])
        self.default_anthropic_model = tk.StringVar(value=PROVIDERS["Anthropic"][1])
        self.default_depth = tk.IntVar(value=1)
        self.default_timeout = tk.DoubleVar(value=10.0)
        self.default_concurrency = tk.IntVar(value=8)
        self.appearance = tk.StringVar(value="Dark")

    def _api_key_for(self, provider_label: str) -> str:
        var = self.gemini_key if provider_label == "Gemini" else self.anthropic_key
        key = var.get().strip()
        if not key:  # env fallback
            key = os.environ.get(PROVIDERS[provider_label][2], "").strip()
        return key

    # =================================================================== ttk style
    def _style_treeview(self) -> None:
        """Style ttk.Treeview to match the dark CTk theme.

        The "clam" base theme is required: the default/vista themes ignore
        Treeview background/fieldbackground, so without clam the table would stay
        white. CTk widgets are canvas-based and unaffected by the ttk theme, and
        we use CTkScrollbar (not ttk) so nothing else is restyled.
        """
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        bg = "#212328"
        sel = "#2f4a73"
        style.configure(
            "Fissure.Treeview",
            background=bg, fieldbackground=bg, foreground="#e6e9ef",
            borderwidth=0, relief="flat", rowheight=26,
        )
        style.configure(
            "Fissure.Treeview.Heading",
            background="#2b2e36", foreground="#c7cdd8",
            borderwidth=0, relief="flat", padding=(8, 6),
        )
        style.map(
            "Fissure.Treeview",
            background=[("selected", sel)],
            foreground=[("selected", "#ffffff")],
        )
        style.map(
            "Fissure.Treeview.Heading",
            background=[("active", "#353943")],
        )
        self._tree_style_ready = True

    # =================================================================== layout
    def _build_sidebar(self) -> None:
        self.sidebar = ctk.CTkFrame(self.root, width=210, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)
        self.sidebar.grid_propagate(False)

        ctk.CTkLabel(self.sidebar, text="\U0001f50e  Fissure",
                     font=self._fonts["logo"]).grid(row=0, column=0, padx=20, pady=(22, 2), sticky="w")
        ctk.CTkLabel(self.sidebar, text=f"v{__version__}",
                     text_color=("#6b7280", "#8b98a5")).grid(row=1, column=0, padx=22, pady=(0, 18), sticky="w")

        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        items = [("scan", "  Scan"), ("ai", "  AI Agent"),
                 ("server", "  Server & Extension"), ("settings", "  Settings")]
        for i, (key, label) in enumerate(items):
            btn = ctk.CTkButton(
                self.sidebar, text=label, anchor="w", height=42,
                corner_radius=8, font=self._fonts["nav"],
                fg_color="transparent", text_color=("#1f2937", "#c7cdd8"),
                hover_color=("#d7dbe3", "#30333c"),
                command=lambda k=key: self._select_section(k),
            )
            btn.grid(row=2 + i, column=0, padx=12, pady=4, sticky="ew")
            self.nav_buttons[key] = btn

        ctk.CTkLabel(self.sidebar, wraplength=180, justify="left",
                     text="Authorized lab use only.\nEach scan needs explicit\nauthorization.",
                     text_color=("#6b7280", "#8b98a5"),
                     font=self._fonts["status"]).grid(row=7, column=0, padx=20, pady=18, sticky="sw")

    def _build_content(self) -> None:
        self.content = ctk.CTkFrame(self.root, corner_radius=0, fg_color="transparent")
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.sections: dict[str, ctk.CTkFrame] = {}
        for key in ("scan", "ai", "server", "settings"):
            frame = ctk.CTkFrame(self.content, corner_radius=0, fg_color="transparent")
            frame.grid(row=0, column=0, sticky="nsew")
            self.sections[key] = frame

    def _build_statusbar(self) -> None:
        bar = ctk.CTkFrame(self.root, height=34, corner_radius=0)
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Idle")
        ctk.CTkLabel(bar, textvariable=self.status_var, font=self._fonts["status"],
                     anchor="w").grid(row=0, column=0, padx=16, pady=4, sticky="w")
        self.busy = ctk.CTkProgressBar(bar, width=180, mode="indeterminate")
        self.busy.grid(row=0, column=1, padx=16, pady=4, sticky="e")
        self.busy.set(0)

    def _select_section(self, key: str) -> None:
        self.sections[key].tkraise()
        for k, btn in self.nav_buttons.items():
            if k == key:
                btn.configure(fg_color=ACCENT, text_color="#ffffff", hover_color=ACCENT_HOVER)
            else:
                btn.configure(fg_color="transparent", text_color=("#1f2937", "#c7cdd8"),
                              hover_color=("#d7dbe3", "#30333c"))

    # ------------------------------------------------------------- card helper
    def _card(self, parent, title: str, **grid):
        """A rounded panel with a bold title; returns the body frame to fill."""
        card = ctk.CTkFrame(parent, corner_radius=CARD_RADIUS)
        card.grid(**grid)
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text=title, font=self._fonts["card_title"],
                     anchor="w").grid(row=0, column=0, padx=INNER_PAD, pady=(INNER_PAD, 4), sticky="w")
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, padx=INNER_PAD, pady=(0, INNER_PAD), sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)
        return card, body

    # ----------------------------------------------------------------- scan tab
    def _build_scan_section(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        _, body = self._card(tab, "Target", row=0, column=0,
                             padx=CARD_PAD, pady=(CARD_PAD, 8), sticky="ew")

        row1 = ctk.CTkFrame(body, fg_color="transparent"); row1.grid(row=0, column=0, sticky="ew", pady=4)
        row1.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(row1, text="URL").grid(row=0, column=0, padx=(0, 8))
        self.scan_url = tk.StringVar(value="http://localhost:8080/")
        ctk.CTkEntry(row1, textvariable=self.scan_url).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        self.scan_btn = ctk.CTkButton(row1, text="Scan  ▶", width=130, command=self.start_scan,
                                      fg_color=ACCENT, hover_color=ACCENT_HOVER)
        self.scan_btn.grid(row=0, column=2)

        row2 = ctk.CTkFrame(body, fg_color="transparent"); row2.grid(row=1, column=0, sticky="ew", pady=4)
        self.scan_allow_public = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(row2, text="Allow public target (I have written authorization)",
                        variable=self.scan_allow_public).pack(side="left")
        ctk.CTkLabel(row2, text="   Depth").pack(side="left")
        self.scan_depth = tk.IntVar(value=self.default_depth.get())
        ctk.CTkEntry(row2, width=50, textvariable=self.scan_depth).pack(side="left", padx=4)
        ctk.CTkLabel(row2, text="   Timeout(s)").pack(side="left")
        self.scan_timeout = tk.DoubleVar(value=self.default_timeout.get())
        ctk.CTkEntry(row2, width=60, textvariable=self.scan_timeout).pack(side="left", padx=4)
        ctk.CTkLabel(row2, text="   Concurrency").pack(side="left")
        self.scan_concurrency = tk.IntVar(value=self.default_concurrency.get())
        ctk.CTkEntry(row2, width=50, textvariable=self.scan_concurrency).pack(side="left", padx=4)

        row3 = ctk.CTkFrame(body, fg_color="transparent"); row3.grid(row=2, column=0, sticky="ew", pady=4)
        row3.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(row3, text="Cookies").grid(row=0, column=0, padx=(0, 8))
        self.scan_cookie = tk.StringVar()
        ctk.CTkEntry(row3, textvariable=self.scan_cookie,
                     placeholder_text="e.g. PHPSESSID=abc; security=low").grid(row=0, column=1, sticky="ew")

        # findings card (expands)
        fcard, fbody = self._card(tab, "Findings", row=1, column=0,
                                  padx=CARD_PAD, pady=8, sticky="nsew")
        fbody.grid_rowconfigure(0, weight=1)
        fbody.grid_columnconfigure(0, weight=1)
        self.scan_tree, sb = self._make_findings_tree(fbody)
        self.scan_tree.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        self.scan_tree.bind("<<TreeviewSelect>>", self._show_scan_evidence)

        _, ebody = self._card(tab, "Evidence", row=2, column=0,
                              padx=CARD_PAD, pady=8, sticky="ew")
        self.scan_evidence = ctk.CTkTextbox(ebody, height=90, wrap="word", font=self._fonts["mono"])
        self.scan_evidence.grid(row=0, column=0, sticky="ew")
        self.scan_evidence.insert("1.0", "Select a finding to see its evidence.")
        self.scan_evidence.configure(state="disabled")

        bar = ctk.CTkFrame(tab, fg_color="transparent"); bar.grid(row=3, column=0, sticky="ew",
                                                                  padx=CARD_PAD, pady=(8, CARD_PAD))
        bar.grid_columnconfigure(0, weight=1)
        self.scan_progress = ctk.CTkProgressBar(bar, mode="determinate")
        self.scan_progress.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self.scan_progress.set(0)
        self.scan_summary = ctk.CTkLabel(bar, text="Idle", font=self._fonts["bold"])
        self.scan_summary.grid(row=0, column=1, padx=10)
        self.scan_html_btn = ctk.CTkButton(bar, text="Open HTML report", width=140,
                                           command=lambda: self._open_html(self.scan_html), state="disabled")
        self.scan_html_btn.grid(row=0, column=2, padx=4)
        self.scan_save_btn = ctk.CTkButton(bar, text="Save JSON…", width=110,
                                           command=lambda: self._save_json(self.scan_report), state="disabled")
        self.scan_save_btn.grid(row=0, column=3, padx=4)

    # ------------------------------------------------------------------- ai tab
    def _build_ai_section(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        _, body = self._card(tab, "AI agent run", row=0, column=0,
                             padx=CARD_PAD, pady=(CARD_PAD, 8), sticky="ew")

        row1 = ctk.CTkFrame(body, fg_color="transparent"); row1.grid(row=0, column=0, sticky="ew", pady=4)
        row1.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(row1, text="URL").grid(row=0, column=0, padx=(0, 8))
        self.ai_url = tk.StringVar(value="http://localhost:8080/")
        ctk.CTkEntry(row1, textvariable=self.ai_url).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        self.ai_btn = ctk.CTkButton(row1, text="Run AI Scan  ▶", width=150, command=self.start_ai,
                                    state="disabled", fg_color=ACCENT, hover_color=ACCENT_HOVER)
        self.ai_btn.grid(row=0, column=2)

        row2 = ctk.CTkFrame(body, fg_color="transparent"); row2.grid(row=1, column=0, sticky="ew", pady=4)
        ctk.CTkLabel(row2, text="Provider").pack(side="left")
        self.ai_provider = tk.StringVar(value=self.default_provider.get())
        ctk.CTkOptionMenu(row2, variable=self.ai_provider, width=120,
                          values=list(PROVIDERS.keys()),
                          command=self._on_provider_change).pack(side="left", padx=(6, 12))
        ctk.CTkLabel(row2, text="Model").pack(side="left")
        self.ai_model = tk.StringVar(value=self.default_gemini_model.get())
        ctk.CTkEntry(row2, textvariable=self.ai_model, width=230).pack(side="left", padx=(6, 12))
        ctk.CTkLabel(row2, text="Max steps").pack(side="left")
        self.ai_max_steps = tk.IntVar(value=40)
        ctk.CTkEntry(row2, width=60, textvariable=self.ai_max_steps).pack(side="left", padx=6)

        row3 = ctk.CTkFrame(body, fg_color="transparent"); row3.grid(row=2, column=0, sticky="ew", pady=4)
        row3.grid_columnconfigure(2, weight=1)
        self.ai_allow_public = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(row3, text="Allow public target",
                        variable=self.ai_allow_public).grid(row=0, column=0, padx=(0, 12))
        ctk.CTkLabel(row3, text="Cookies").grid(row=0, column=1, padx=(0, 8))
        self.ai_cookie = tk.StringVar()
        ctk.CTkEntry(row3, textvariable=self.ai_cookie).grid(row=0, column=2, sticky="ew")

        row4 = ctk.CTkFrame(body, fg_color="transparent"); row4.grid(row=3, column=0, sticky="ew", pady=4)
        self.ai_authorized = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(row4, text="I am authorized to test this target (required)",
                        variable=self.ai_authorized, command=self._refresh_ai_btn).pack(side="left")

        self.ai_warn = ctk.CTkLabel(tab, text="", text_color=SEV_COLORS["critical"], anchor="w")
        self.ai_warn.grid(row=1, column=0, sticky="ew", padx=CARD_PAD)
        if _AI_IMPORT_ERROR:
            self.ai_warn.configure(text=f"AI stack unavailable: {_AI_IMPORT_ERROR}")

        mid = ctk.CTkFrame(tab, fg_color="transparent"); mid.grid(row=2, column=0, sticky="nsew",
                                                                 padx=CARD_PAD, pady=8)
        mid.grid_rowconfigure(0, weight=1)
        mid.grid_columnconfigure(0, weight=1)
        mid.grid_columnconfigure(1, weight=1)

        tcard, tbody = self._card(mid, "Tool trace", row=0, column=0, padx=(0, 6), sticky="nsew")
        tbody.grid_rowconfigure(0, weight=1)
        self.ai_trace = ctk.CTkTextbox(tbody, wrap="word", font=self._fonts["mono"],
                                       fg_color=("#0f1b2d", "#0f1b2d"), text_color="#d7e3f0")
        self.ai_trace.grid(row=0, column=0, sticky="nsew")
        self.ai_trace.configure(state="disabled")

        ncard, nbody = self._card(mid, "Findings", row=0, column=1, padx=(6, 0), sticky="nsew")
        nbody.grid_rowconfigure(0, weight=1)
        nbody.grid_columnconfigure(0, weight=1)
        self.ai_tree, asb = self._make_findings_tree(nbody, cols=("severity", "title", "location"))
        self.ai_tree.grid(row=0, column=0, sticky="nsew")
        asb.grid(row=0, column=1, sticky="ns")

        _, xbody = self._card(tab, "Executive summary", row=3, column=0,
                             padx=CARD_PAD, pady=8, sticky="ew")
        self.ai_exec = ctk.CTkTextbox(xbody, height=90, wrap="word")
        self.ai_exec.grid(row=0, column=0, sticky="ew")
        self.ai_exec.configure(state="disabled")

        bar = ctk.CTkFrame(tab, fg_color="transparent"); bar.grid(row=4, column=0, sticky="ew",
                                                                 padx=CARD_PAD, pady=(8, CARD_PAD))
        bar.grid_columnconfigure(0, weight=1)
        self.ai_status = ctk.CTkLabel(bar, text="Idle", font=self._fonts["bold"], anchor="w")
        self.ai_status.grid(row=0, column=0, sticky="w")
        self.ai_html_btn = ctk.CTkButton(bar, text="Open HTML report", width=140,
                                         command=lambda: self._open_html(self.ai_html), state="disabled")
        self.ai_html_btn.grid(row=0, column=1, padx=4)
        self.ai_save_btn = ctk.CTkButton(bar, text="Save JSON…", width=110,
                                         command=lambda: self._save_json(self.ai_report), state="disabled")
        self.ai_save_btn.grid(row=0, column=2, padx=4)
        self._refresh_ai_btn()

    # --------------------------------------------------------------- server tab
    def _build_server_section(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        _, body = self._card(tab, "Localhost scan service", row=0, column=0,
                             padx=CARD_PAD, pady=(CARD_PAD, 8), sticky="ew")

        row1 = ctk.CTkFrame(body, fg_color="transparent"); row1.grid(row=0, column=0, sticky="ew", pady=4)
        self.server_btn = ctk.CTkButton(row1, text="Start server", width=130, command=self.toggle_server,
                                        fg_color=ACCENT, hover_color=ACCENT_HOVER)
        self.server_btn.pack(side="left")
        self.server_state = ctk.CTkLabel(row1, text="Stopped", font=self._fonts["bold"],
                                         text_color=SEV_COLORS["critical"])
        self.server_state.pack(side="left", padx=14)

        row2 = ctk.CTkFrame(body, fg_color="transparent"); row2.grid(row=1, column=0, sticky="ew", pady=4)
        ctk.CTkLabel(row2, text="URL").pack(side="left", padx=(0, 8))
        self.server_url = tk.StringVar(value="http://127.0.0.1:8750")
        ctk.CTkEntry(row2, textvariable=self.server_url, width=240, state="disabled").pack(side="left")

        row3 = ctk.CTkFrame(body, fg_color="transparent"); row3.grid(row=2, column=0, sticky="ew", pady=4)
        row3.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(row3, text="Bearer token").grid(row=0, column=0, padx=(0, 8))
        self.server_token = tk.StringVar(value="(start the server to generate)")
        ctk.CTkEntry(row3, textvariable=self.server_token, state="disabled").grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ctk.CTkButton(row3, text="Copy token", width=110, command=self._copy_token).grid(row=0, column=2)

        scard, sbody = self._card(tab, "Load the browser extension", row=1, column=0,
                                  padx=CARD_PAD, pady=(8, CARD_PAD), sticky="nsew")
        sbody.grid_rowconfigure(0, weight=1)
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
        steps = ctk.CTkTextbox(sbody, wrap="word")
        steps.grid(row=0, column=0, sticky="nsew")
        steps.insert("1.0", txt)
        steps.configure(state="disabled")

    # ------------------------------------------------------------- settings tab
    def _build_settings_section(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=1)

        _, kbody = self._card(tab, "API keys (kept in memory for this session only)",
                             row=0, column=0, padx=CARD_PAD, pady=(CARD_PAD, 8), sticky="ew")

        r1 = ctk.CTkFrame(kbody, fg_color="transparent"); r1.grid(row=0, column=0, sticky="ew", pady=4)
        r1.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(r1, text="GEMINI_API_KEY", width=150, anchor="w").grid(row=0, column=0)
        ctk.CTkEntry(r1, textvariable=self.gemini_key, show="•").grid(row=0, column=1, sticky="ew", padx=8)
        ctk.CTkButton(r1, text="Test key", width=90,
                      command=lambda: self._test_key("Gemini")).grid(row=0, column=2)

        r2 = ctk.CTkFrame(kbody, fg_color="transparent"); r2.grid(row=1, column=0, sticky="ew", pady=4)
        r2.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(r2, text="ANTHROPIC_API_KEY", width=150, anchor="w").grid(row=0, column=0)
        ctk.CTkEntry(r2, textvariable=self.anthropic_key, show="•").grid(row=0, column=1, sticky="ew", padx=8)
        ctk.CTkButton(r2, text="Test key", width=90,
                      command=lambda: self._test_key("Anthropic")).grid(row=0, column=2)

        r3 = ctk.CTkFrame(kbody, fg_color="transparent"); r3.grid(row=2, column=0, sticky="ew", pady=4)
        ctk.CTkButton(r3, text="Apply keys to this session", command=self._apply_keys,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER).pack(side="left")
        ctk.CTkLabel(r3, text="  (also pushed into os.environ; never written to disk)",
                     text_color=("#6b7280", "#8b98a5")).pack(side="left")

        _, dbody = self._card(tab, "Defaults (seed the Scan and AI tabs when applied)",
                             row=1, column=0, padx=CARD_PAD, pady=8, sticky="ew")

        d1 = ctk.CTkFrame(dbody, fg_color="transparent"); d1.grid(row=0, column=0, sticky="ew", pady=4)
        ctk.CTkLabel(d1, text="Default provider").pack(side="left")
        ctk.CTkOptionMenu(d1, variable=self.default_provider, width=120,
                          values=list(PROVIDERS.keys())).pack(side="left", padx=(6, 16))
        ctk.CTkLabel(d1, text="Gemini model").pack(side="left")
        ctk.CTkEntry(d1, textvariable=self.default_gemini_model, width=220).pack(side="left", padx=6)

        d2 = ctk.CTkFrame(dbody, fg_color="transparent"); d2.grid(row=1, column=0, sticky="ew", pady=4)
        ctk.CTkLabel(d2, text="Anthropic model").pack(side="left")
        ctk.CTkEntry(d2, textvariable=self.default_anthropic_model, width=220).pack(side="left", padx=6)

        d3 = ctk.CTkFrame(dbody, fg_color="transparent"); d3.grid(row=2, column=0, sticky="ew", pady=4)
        ctk.CTkLabel(d3, text="Crawl depth").pack(side="left")
        ctk.CTkEntry(d3, width=50, textvariable=self.default_depth).pack(side="left", padx=(6, 14))
        ctk.CTkLabel(d3, text="Timeout(s)").pack(side="left")
        ctk.CTkEntry(d3, width=60, textvariable=self.default_timeout).pack(side="left", padx=(6, 14))
        ctk.CTkLabel(d3, text="Concurrency").pack(side="left")
        ctk.CTkEntry(d3, width=50, textvariable=self.default_concurrency).pack(side="left", padx=6)

        _, abody = self._card(tab, "Appearance", row=2, column=0, padx=CARD_PAD, pady=8, sticky="ew")
        arow = ctk.CTkFrame(abody, fg_color="transparent"); arow.grid(row=0, column=0, sticky="ew", pady=2)
        ctk.CTkLabel(arow, text="Theme").pack(side="left", padx=(0, 10))
        ctk.CTkSegmentedButton(arow, values=["Dark", "Light"], variable=self.appearance,
                               command=self._on_appearance_change).pack(side="left")
        ctk.CTkButton(arow, text="Apply defaults to Scan/AI tabs", command=self._apply_defaults,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER).pack(side="right")

        note = ctk.CTkLabel(
            tab, text_color=("#555", "#9aa3b2"), wraplength=760, justify="left", anchor="w",
            text=("Keys are held only for this session. 'Apply keys' pushes them into this "
                  "process's environment so the LLM clients and any subprocess can read them; "
                  "nothing is written to disk. Gemini free tier works with "
                  "gemini-3.5-flash-lite (gemini-3.5-flash refuses this task)."))
        note.grid(row=3, column=0, sticky="ew", padx=CARD_PAD + 2, pady=(8, CARD_PAD))

    def _on_appearance_change(self, value: str) -> None:
        ctk.set_appearance_mode(value.lower())

    # ============================================================= findings tree
    def _make_findings_tree(self, parent, cols=("severity", "module", "title", "location")):
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=12,
                            style="Fissure.Treeview")
        widths = {"severity": 90, "module": 90, "title": 280, "location": 300}
        for c in cols:
            tree.heading(c, text=c.title())
            tree.column(c, width=widths.get(c, 140), anchor="w")
        for sev, color in SEV_COLORS.items():
            tree.tag_configure(sev, foreground=color)
        sb = ctk.CTkScrollbar(parent, command=tree.yview)
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
        self._scan_steps = 0
        self.scan_progress.set(0)
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
            self._scan_steps = min(self._scan_steps + 1, self._scan_max)
            self.scan_progress.set(self._scan_steps / self._scan_max)
        text = labels.get(stage)
        if text:
            self.scan_summary.configure(text=text)
            self.status_var.set(text)

    def _on_scan_done(self, report: dict) -> None:
        self._scanning = False
        self.scan_report = report
        self.scan_html = report["outputs"].get("html")
        self.scan_progress.set(1)
        s = report["summary"]
        for mod in report["modules"].values():
            for fd in mod["findings"]:
                self._insert_finding(self.scan_tree, fd, module=mod["module"])
        self.scan_summary.configure(text=f"{s['label']} · {s['score']} pts · {s['total_findings']} findings")
        self.scan_btn.configure(state="normal", text="Scan  ▶")
        self.scan_html_btn.configure(state="normal" if self.scan_html else "disabled")
        self.scan_save_btn.configure(state="normal")
        self._set_busy(False, "Scan complete")
        if s["total_findings"] == 0:
            messagebox.showinfo("Fissure", "Scan complete - no findings.")

    def _on_scan_error(self, message: str) -> None:
        self._scanning = False
        self.scan_btn.configure(state="normal", text="Scan  ▶")
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
    def _on_provider_change(self, _value=None) -> None:
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
        self.ai_btn.configure(text="Run AI Scan  ▶")
        self.ai_html_btn.configure(state="normal" if self.ai_html else "disabled")
        self.ai_save_btn.configure(state="normal" if report else "disabled")
        self._refresh_ai_btn()
        self._set_busy(False, "AI scan complete")

    def _on_ai_error(self, message: str) -> None:
        self._ai_running = False
        self.ai_btn.configure(text="Run AI Scan  ▶")
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
        self.server_state.configure(text="Running", text_color=SEV_COLORS["low"])
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
        self.server_state.configure(text="Stopped", text_color=SEV_COLORS["critical"])
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

    def _set_text(self, widget, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _set_busy(self, busy: bool, status: str | None = None) -> None:
        if busy:
            self.busy.configure(mode="indeterminate")
            self.busy.start()
        else:
            self.busy.stop()
            self.busy.configure(mode="determinate")
            self.busy.set(0)
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
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    FissureGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
