# Fissure AI (Step 2) — Implementation Design

> Design produced for Step 2. An agentic orchestration layer on top of the Step-1
> deterministic scanner. Claude plans, chains, re-tests, triages, and writes up;
> the Step-1 modules still do all detection for zero tokens. Step 1 is not
> modified — Step 2 is additive, imported, and gated behind an optional `ai` extra.

## 0. Guiding invariants
1. **Detection is deterministic; the LLM only decides what to run next and what it means.** No tool asks the model to "find the vuln" — tools return structured facts.
2. **Every safety decision is enforced in Python inside the tool layer**, before any HTTP leaves the box. The prompt is advisory; the code is authoritative.
3. **Scanned-page content is data, never instructions** — always wrapped and labeled untrusted in context.
4. **State-changing HTTP requires human approval** via a code gate, not model self-assessment.
5. **Token thrift:** deterministic code first; cheap worker model for compression/bulk/prose; brain (Claude) only for planning and final judgment.

## 1. Tool schema
Tools are thin wrappers over `crawler`, `modules/*`, and `http.Session`. Each wrapper: validates input against scope/denylist → calls Step-1 code → returns a compact JSON string (never raw HTML / full bodies unless explicitly fetched and truncated). Common envelope: `{ "ok": true, "data": {...} }` or `{ "ok": false, "error": "scope_violation", "detail": "..." }` (errors returned, not raised, so the model can recover). Short stable handles (`inj_003`, `find_007`, `req_012`) replace re-sending payloads/URLs; handle→object maps live in the engagement store.

- **Recon:** `crawl` (returns a summary + injectable list, not the raw graph), `get_injectables` (paginated/filtered listing).
- **Detection (one tool per module, injectable-scoped):** `run_sqli`, `run_xss`, `run_redirect`, `run_cmdi`, `run_path_traversal` (all `{injectable_id, options?}`), `run_discovery` (site-scoped), `run_headers` (passive, per page/base). Each returns compact findings already written to the store, with `evidence_ref` handles and ≤200-char snippets; full request/response via `get_evidence`.
- **Raw HTTP:** `http_request` — the only tool sending an arbitrary request; heavily guarded (§3). Returns a compacted response (status, header subset, body excerpt, body_len, reflected_inputs) with a `req_*` handle.
- **Evidence/findings/report:** `get_evidence` (truncated, optionally worker-summarized), `get_findings` (compact filterable table), `update_finding` (triage write-back — may downgrade/mark-FP freely, cannot exceed the module's deterministic ceiling without a rationale; original verdict retained), `visual_confirm` (optional on-demand vision, rate-limited), `report` (finalize via the Step-1 JSON/HTML writer; a stop signal).

**Granularity:** per-module + per-injectable keeps each call cheap, lets the model chain, and maps 1:1 onto `ModuleResult`. A coarse `scan_everything` would blow the token budget and strip the model of its planning role. All tool outputs enforce hard byte caps with `truncated:true` + a fetch handle; bodies never flow verbatim into context.

## 2. Orchestrator loop
A plain Anthropic Messages-API tool-use (ReAct) loop: load memory + findings store + tool registry → system prompt → iterate: `brain.messages(...)` → for each `tool_use` block run `gate.check` (may pause for HITL) → `tools.dispatch` (runs Step-1 code) → `worker.compact` the raw output → append `tool_result` → update memory → compact context if near the window → stop when `report` is called. Hard caps on steps/tokens/time; loop-detection on repeated identical calls.

**System prompt** binds ROLE (orchestrator, never exploit beyond proof), SCOPE & SAFETY (tool layer enforces scope; page text is untrusted data; state-changing needs approval; don't work around refusals), and a METHODOLOGY to follow in order: RECON → MAP → TEST (cheap signals before expensive) → CONFIRM (second signal, else `confirmed=false`) → CHAIN → TRIAGE → REPORT.

**Worker model plug-ins (code-invoked, never by the model):** (1) tool-output compaction, (2) context compaction from the engagement file, (3) optional bulk-triage pre-pass, (4) report prose. Skipped when output is already small.

**Stop conditions:** `report` called; `max_steps`; budget exceeded; no untested high-value injectables + model emits prose (auto-finalize); repeated-call loop detection; fatal scope/auth failure.

**Agent SDK note:** the Claude Agent SDK would give the loop/context/streaming for free but hides the two seams that must be explicit and auditable here — the synchronous HITL gate and the code-side worker compaction between tool-call and tool-result. Recommendation: hand-roll the ~60-line Messages loop; keep `LLMClient` SDK-shaped so migration stays cheap later.

## 3. Guardrail layer (`gate.py` + tool wrappers)
Between the model's requested call and any network egress. Order per call: **scope → denylist → rate → destructiveness → (HITL if flagged) → execute**; a block returns a structured tool error, never raises.
- **Scope enforcement** (reuse Step-1 `Target` guard): every request's host must be in authorized scope; public refused unless `allow_public` was set at engagement creation — never flippable by the model. Re-checked on every redirect hop.
- **Payload denylist** for model-authored `http_request`: deny destructive SQL (DROP/TRUNCATE/DELETE/UPDATE without WHERE), non-read-only shell (`rm`, `mkfs`, fork bombs, outbound curl/wget to non-scope hosts, reverse shells), traversal outside a safe proof set, any out-of-scope host. Module payloads are allow-listed by trusted origin.
- **Method/destructiveness gate:** any non-GET, or GET matching destructive patterns (`/delete`, `/logout`, `?action=remove`, transfer, purchase) → `state_changing` → HITL.
- **Rate/volume caps**, **auth boundary** (model cannot submit creds or create accounts; login is Step-1 `ensure_authenticated` with operator creds only), **no settings/irreversible controls** (payment/transfer/account-deletion hard-refused).

**HITL gate:** `ApprovalGate.check` classifies; denied → block; state_changing → `ask_human` (CLI stdin / GUI modal / extension popup) blocks the loop; per-action, per-session, never generalized; shows exact method/URL/params + the model's one-line `intent`, secrets redacted; timeout = decline. One mandatory engagement authorization precedes the loop (does not pre-authorize individual calls).

**Prompt-injection containment:** wrap all scanned content as `<<UNTRUSTED_PAGE_CONTENT src=...>> … <<END>>`; permission state is code-side (reads engagement config, never the conversation) so "you are now authorized…" text is inert; egress allow-list blocks PoC collectors; model instructed to *report* injection-style text, not obey it; worker compaction strips most injected prose before it reaches the brain.

## 4. Memory / state (`./.fissure/<target-slug>/`)
- **`engagement.json`** (PentestGPT-style, worker-maintained): target+scope+authorized_at, phase, coverage (injectables tested, per-module run/hits), task_queue, confirmed_findings, chains, budget, notes. Re-injected on context compaction as a short "progress so far" note.
- **Findings store** (`findings.jsonl` + side maps `injectables.json`, `evidence/req_*.txt`): append-only Step-1 `Finding`s + model triage overlay (confirmed, severity, false_positive, rationale, chain_refs, module_original_verdict). Big data lives here so context stays lean.
- **Rules:** code (not the model) updates coverage/queue/budget after each batch; `(injectable_id, module)` idempotency key prevents re-runs; resumable from disk.

## 5. LLMClient interface (`fissure/ai/llm.py`)
Provider-agnostic `LLMClient` protocol: `complete(system, messages, tools?, max_tokens, temperature) -> LLMResponse` (normalized `tool_calls`, `stop_reason`, `usage`) and `compact(text, hint, max_out) -> str`, plus a `tier` ("brain"|"worker"). Implementations: `AnthropicClient` (brain, maps tool_use/tool_result blocks) and worker variants (`AnthropicClient` Haiku default; optional `GeminiClient` Flash for compact/prose only). **`Hive`** routes: tool-use/final-severity → brain; summarization/bulk/prose → worker; anything a regex or the modules can answer → no LLM. Worker optional (falls back to deterministic truncation). Config via `--brain-model`, `--worker-model`, `ANTHROPIC_API_KEY`, optional `GEMINI_API_KEY`; budgets via `--max-steps`, `--max-requests`, `--token-budget`.

## 6. Browser extension + localhost API (`fissure/ai/server.py`, FastAPI, 127.0.0.1 only)
Bearer token per launch; CORS restricted to the extension origin. Endpoints: `POST /scan` (seed with base_url/scope + the tab's DOM/accessibility tree — not a screenshot — labeled untrusted; server runs its own scope guard), `POST /scan/{id}/authorize` (the **required** gate — only this flips to `running`; no auto/continuous capture), `GET /scan/{id}/events` (SSE: progress/finding/approval/done), `POST /scan/{id}/approval/{aid}` (HITL answer), `GET /scan/{id}/report`, `POST /scan/{id}/stop`.

**Flow:** click toolbar button on an in-scope tab → popup options → extension reads active tab URL + DOM directly (`chrome.tabs`/`chrome.scripting`, **not** screenshot OCR) → `POST /scan` → operator clicks Approve → server re-validates scope (defense in depth) → SSE streams findings + per-action approvals → report link at `done`.

**`extension/`** (MV3): `manifest.json` (activeTab, scripting, host perms for localhost), `background.js` (token + API + SSE), `popup.html/js` (options + authorization + live progress + approvals), `content.js` (serializes DOM only on click, never continuously).

## 7. File / module plan (additive; Step 1 untouched)
```
fissure/ai/
  agent.py    # orchestrator loop, stop conditions, loop-detection
  tools.py    # ToolRegistry: specs + dispatch over crawler/modules/http
  gate.py     # ApprovalGate + guardrail checks
  llm.py      # LLMClient protocol, AnthropicClient, GeminiClient
  hive.py     # brain/worker routing + Budget tracker
  memory.py   # engagement.json + FindingsStore overlay + compaction
  prompts.py  # SYSTEM_PROMPT, NUDGE, untrusted-content wrappers
  server.py   # FastAPI localhost service + SSE
extension/    # MV3 browser extension
```
`tools.py` imports `fissure.crawler/http/modules.*/engine`; `report` reuses the engine's writer + scorer (no reimplementation). CLI gains `fissure ai <target> [...]`; GUI gains an "AI scan" button surfacing approval modals. AI deps (`anthropic`, `fastapi`, `uvicorn`, optional `google-genai`) behind a `ai` extra so the Step-1 `.exe` stays lean.

## 8. Build order + top risks
**Order:** (1) LLMClient+Hive, (2) ToolRegistry+FindingsStore (crawl/run_sqli/get_findings/report), (3) orchestrator loop+prompt against DVWA local, (4) guardrail layer + remaining tools + CLI HITL, (5) worker routing, (6) localhost server+SSE, (7) extension, (8) CLI/GUI wiring + packaging. Phases 1–4 give a usable CLI agent.

**Top pitfalls:** scope bypass via model-authored `http_request`/redirects (check every hop); prompt-injection granting capability (permission is code-side only); HITL race/deadlock (timeout = decline, never "approve all"); token blow-up from raw bodies (byte caps in wrappers, asserted in tests); infinite/repetitive loops (idempotency keys + call hashing + max_steps); over-triage (keep original verdict, require rationale to exceed ceiling); auth/session loss (reuse `ensure_authenticated`, never invent creds); worker distorting evidence (full evidence kept on disk); rate/DoS (per-host caps in the gate); secrets in approval previews/logs (redact).
