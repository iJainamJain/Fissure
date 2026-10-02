# Fissure — Roadmap / Build List

Two products, built in order:

- **Step 1 — `Fissure`** — the deterministic scanner with *all* non-LLM features (Track 1).
  Ships and demos standalone.
- **Step 2 — `Fissure AI`** — adds a **Claude**-powered pentester agent that orchestrates the
  Fissure toolbelt (Track 2). Built on top of Step 1.

Build Step 1 first — it becomes the toolbelt the agent drives. LLM provider: **Anthropic / Claude**
(tool-use / Agent SDK).

---

## Track 1 — Deterministic scanner (agreed build list)

Ordered by impact ÷ effort. Each maps to the existing architecture
(`Injectable` → module → `ModuleResult`/`Finding` → report).

**Status: Track 1 COMPLETE ✅** (25 tests passing; validated live against DVWA; benchmark F1 = 1.000 on VulnLab).

| # | Feature | Where | Status |
|---|---------|-------|--------|
| 1 | **Capture response headers during crawl** (enabler) | `crawler.py` → `CrawlResult.responses` | ✅ done |
| 2 | **Security headers + cookie flags** (passive, A05) | `modules/headers.py` | ✅ done |
| 3 | **Command injection** (active, A03, time-based) | `modules/cmdi.py` | ✅ done |
| 4 | **Auth robustness** (token login + auto re-login) | `http.py` | ✅ done |
| 5 | **Path traversal / LFI** (active, A01) | `modules/traversal.py` | ✅ done |
| 6 | **Benchmark + precision/recall harness** | `benchmark/score.py`, `ground_truth.json` | ✅ done (ZAP/Nikto compare = documented commands) |
| 7 | **SARIF 2.1.0 export → CI** | `fissure/sarif.py`, `.github/workflows/fissure.yml` | ✅ done (`--sarif`, `--fail-on`) |

**Cross-cutting:** ✅ `cwe`/`cvss` on `Finding` (every module emits a CWE); ✅ `_probe.py::send()` accepts per-request headers (for CORS later).

**Stretch modules (same patterns):** SSTI (`{{7*7}}`→49 bound to a unique marker), Stored XSS (inject via POST → re-fetch → find marker), CORS misconfig, concurrency + rate limiting (`asyncio.Semaphore`; keep time-based checks at low concurrency).

**Deliberately skipped:** SSRF / XXE (need out-of-band callback infra, conflicts with local-only scope), PDF report (HTML already covers it; fights the single-exe story).

---

## Track 2 — AI pentester agent (new direction)

> **Detailed implementation design:** see [docs/FISSURE_AI_DESIGN.md](docs/FISSURE_AI_DESIGN.md)
> (tool schema, orchestrator loop, guardrail layer, memory, LLMClient, browser-extension API,
> file plan, build order). Summary below.

**Core idea:** keep Fissure's deterministic scanner as the reliable engine; put an LLM
*orchestrator* on top that decides what to test next, chains findings, triages, and writes up
results. The LLM does judgement/planning — NOT the byte-level detection the scanner already does
better. (This mirrors PentestGPT's task-tree + the ReAct loop used by CAI/hackingBuddyGPT.)

### Architecture
```
            ┌────────────────────────────────────────────┐
            │  Orchestrator LLM  (ReAct / tool-use loop)  │
            │  system prompt = pentest methodology        │
            │  recon → map → test → confirm → report      │
            └───────────────┬────────────────────────────┘
          tool calls ↓      │ engagement-context file (progress/notes)
   ┌──────────────────────────────────────────────────────────┐
   │  Fissure-as-tools (deterministic, code-enforced guardrails)│
   │  crawl() · sqli() · xss() · cmdi() · traversal() ·         │
   │  http_request(method,url,params,headers) · get_findings()  │
   └──────────────────────────────────────────────────────────┘
```

- **Fissure modules become callable tools.** The agent calls `crawl`, then decides which
  modules to run on which inputs, re-tests, and pivots on results.
- **State representation (the "current state" question):** feed the agent **structured text** —
  the findings JSON, HTTP request/response pairs, and the page's DOM / accessibility tree — NOT
  recurring screenshots. For security reasoning, structured signals are richer, cheaper, and more
  reliable than vision. Reserve screenshots/vision for the few cases that need pixels: confirming a
  rendered XSS `alert()` fired, visually complex SPAs, or multi-step UI flows. Default = text;
  vision = on demand.
- **Guardrails in code, not just the prompt:** scope enforcement, payload denylists, and
  human-in-the-loop approval for anything state-changing must live in the tool layer so the LLM
  cannot be prompt-injected past them.
- **Memory:** a running engagement-context file (PentestGPT-style) + the findings store, so long
  scans survive context limits.
- **Build with:** Anthropic Messages API tool-use or the Claude Agent SDK. (Note: PentestGPT's new
  autonomous pipeline literally requires the Claude Code CLI — a sign this orchestration pattern is
  the current direction.)

### Existing projects — what to borrow (mind the licenses)
| Project | Lang | License | Reuse |
|---------|------|---------|-------|
| **PentestGPT** (GreyDGL) | Python | permissive (MIT) — verify | Task-tree planning, HITL prompt structure, engagement-context file pattern |
| **hackingBuddyGPT** | Python | permissive — verify | Minimal (~50-LOC) LLM agent loop; great reference skeleton |
| **Nebula** | Python | BSD-2-Clause | Recon/note-taking + vuln-analysis prompting |
| **MANTIS** | Python | verify | Multi-agent on smolagents, structured state store |
| **HexStrike AI** | — | verify | MCP server exposing 150+ tools — a possible integration path instead of reimplementing |
| **CAI** (Alias Robotics) | Python | **dual/restrictive + ARCHIVED** | Ideas/architecture ONLY — do **not** copy code |
| **Strix** | — | verify | GitHub-Actions CI integration pattern |

**Licensing rule for "borrow code to save effort":** only copy from MIT/BSD/Apache repos, keep their
notices, and record the source. **Do not** copy from GPL/AGPL (would force relicensing our MIT repo),
from CAI (restrictive + archived), or from any repo whose LICENSE you haven't read. Prefer taking
*ideas/prompts* over pasting code.

### Suggested phasing (status)
1. ✅ Land Track 1 items 1–7.
2. ✅ `LLMClient`/`Hive` + tool registry + orchestrator loop (tool-use ReAct), text-state only — `fissure/ai/`.
3. ✅ Guardrail layer (scope, denylist, state-change approval) + findings store; `fissure-ai` CLI. Offline-tested with a scripted mock model (31 tests total).
4. ✅ Localhost server (`fissure/server.py`) + MV3 browser extension (`extension/`), authorization-gated.
5. ✅ Engagement-memory persistence + resume (`EngagementMemory`, `FindingsStore.save/load`; `--resume`) — idempotent skip of tested inputs.
6. ⬜ Next (needs API key or polish): real `AnthropicClient` run against DVWA, worker-model routing for bulk triage/report prose, vision-on-demand, extension icon + AI mode.

### Model routing — Claude brain + cheap workers (idea: "hive")
Legitimate cost-control pattern, but be precise about where tokens actually go. The
deterministic scanner does detection for **zero LLM tokens**; the orchestrator's tokens go to
*reasoning, planning, and reading tool output*. So use cheap worker models only where an LLM is
genuinely needed on bulk/repetitive work:
- **Context compression** — a cheap model condenses a huge HTTP response / crawl dump to the
  salient facts before it reaches Claude's context (real savings for the brain).
- **Vision** — image/screenshot analysis, only if/when we add it.
- **Bulk triage / report prose** — classify many similar findings, draft boilerplate.
Design: an `LLMClient` interface, default everything to Claude; worker roles pluggable to a cheap
model — **Claude Haiku (keeps it single-provider, simplest) or Gemini Flash**. **Rule:** never spend
an LLM call where deterministic code works — that, not multi-model routing, is the biggest token win.
Caveats: multi-provider = extra keys, failure modes, and sending target data to two vendors.

### Front-end: browser extension + authorization gate (idea: "floating button")
Reframe the "corner overlay button" as a **browser extension + local Fissure service** — same UX,
far more reliable:
- Toolbar button → popup with options ("Scan this page", "Scan with login", "Headers only", later
  "Pentest with AI").
- The extension reads the **active tab URL + DOM directly** (accurate, instant, free) and posts it to
  a **localhost-only** Fissure API. **Do NOT grab the URL via screenshot/OCR** — fragile, lossy,
  token-expensive; pixels are for visual *confirmation* only (did an XSS alert fire?), never as the
  primary state signal.
- **Authorization gate (required, not optional):** the popup forces the user to confirm they're
  authorized to test the target; the server-side scope guard still applies. Only ever act on an
  explicit click — never continuous screen capture. Great responsible-disclosure story for the demo.
- This is the natural front-end for Fissure AI: the extension becomes the agent's UI.
Lighter Step-1 stand-in: a "grab URL from clipboard / current browser" button on the existing GUI.

---

## References
- awesome-ai-pentest (curated): https://github.com/insidetrust/awesome-ai-pentest
- Strix: https://github.com/usestrix/strix
- CAI (archived): https://github.com/aliasrobotics/cai
- PentestGPT (USENIX Security 2024)
- hackingBuddyGPT, Nebula, MANTIS, HexStrike AI (see awesome list)
