# Fissure — Demo Runbook

A click-by-click script for presenting Fissure (plus copy-paste fallback
commands). Target time: **~7 minutes**. Everything runs locally; nothing needs
the internet except the optional AI run (Gemini).

> **One-line pitch:** *Passive scanners **flag** issues; Fissure **confirms** they're
> exploitable — and an AI agent drives it like a pentester.*

---

## 0. Prep (do this 15 minutes early)

```bash
cd "D:/was lab/fissure"
```

1. **Start the practice target** (no login needed) and leave it running:
   ```bash
   python benchmark/vulnlab.py        # serves http://127.0.0.1:8000
   ```
2. *(Optional, more impressive)* **Start DVWA** (a real vulnerable app):
   ```bash
   docker start dvwa                  # http://localhost:8080  (admin / password)
   ```
3. **Open the app:** double-click `dist/Fissure.exe`. In **Settings**, confirm your
   Gemini API key is saved (tick *Remember on this device* once and it persists).
4. **Pre-generate one AI report now** (safety net if Gemini's free tier throttles
   live — see §B4) and keep the HTML open in a browser tab.
5. **Open browser tabs:** the GitHub repo, `Fissure_Project_Summary.pdf`, and one
   finished HTML report.
6. Increase terminal font size; close unrelated apps.

---

## A. Live demo flow

### 1. Pitch + one-pager (30s)
Show `Fissure_Project_Summary.pdf`. Say the one-liner above. Mention the two
steps: **Fissure** (deterministic scanner) and **Fissure AI** (Claude/Gemini agent
that drives it).

### 2. Deterministic scan — the GUI (90s)
- Open **Fissure.exe** → **Scan** tab.
- URL: `http://127.0.0.1:8000` → **Scan**.
- Findings fill the color-coded table; click one → its **evidence** shows below.
- Click **Open HTML report**.
- Talking point: *"Each finding is **confirmed** — a real DB error, a 5-second
  delay, an unescaped reflection — not just a signature match."*

CLI equivalent (fallback):
```bash
python -m fissure http://127.0.0.1:8000 --html --sarif -o out/demo_scan.json
```

### 3. The AI agent — the headline (2 min)
- **AI Agent** tab → URL `http://127.0.0.1:8000`, Provider **Gemini**, Model
  `gemini-3.5-flash-lite`, tick **"I am authorized to test this target"** → **Run AI Scan**.
- Watch the **live tool-trace**: the model chooses `crawl → run_sqli → run_xss →
  … → report` on its own. Then show its **executive summary** + **Open report**.
- Talking point: *"Detection stays deterministic — zero LLM tokens. The model is
  the **brain** that plans, chains and triages; Fissure's modules are the **hands**.
  Safety (scope, payload denylist, approval for state-changing actions) is enforced
  in **code**, so a prompt-injection on a scanned page can't widen scope."*

CLI equivalent (fallback):
```bash
python -m fissure.ai.cli http://127.0.0.1:8000 --provider gemini ^
  --brain-model gemini-3.5-flash-lite --max-steps 20 --sarif -o out/demo_ai.json
```

### 4. Metrics — measured, not just built (60s)
```bash
python benchmark/score.py
```
Point at **precision / recall / F1 = 1.00 (0 false positives)** against a
ground-truth file. Talking point: *"I didn't just build a scanner — I measured it
against known vulnerabilities, the way you'd evaluate any detector."*

### 5. Reports & CI (45s)
- Show the generated **`.sarif`** file and `.github/workflows/fissure.yml`.
- Talking point: *"SARIF is the standard code-scanning format — this drops straight
  into a GitHub DevSecOps pipeline and can fail a build on a critical finding
  (`--fail-on critical`)."*

### 6. (If time) Extension (30s)
- **Server & Extension** tab → **Start server** → show the bearer token and the
  browser-extension load steps. *"The same scan, launched from a toolbar button on
  the page you're on — behind a mandatory authorization click."*

---

## B. Talking points that score

- **Confirms, not flags** — behavior/content proof (file *contents*, not the echoed
  payload; re-tested time delays).
- **9 detection categories** across OWASP Top 10: SQLi, XSS, command injection,
  path traversal, SSTI, CORS, open redirect, sensitive files, security headers.
- **Three real engineering problems solved** (great for Q&A):
  1. Gemini free-tier **503 spikes** → exponential-backoff retry.
  2. A model that **refused** the task → fixed with honest authorized-testing
     framing (NOT a jailbreak) + model selection.
  3. Gemini 3.x **`thought_signature`** required on multi-turn tool use → captured
     and round-tripped.
- **Guardrails in code, not the prompt.** Scope/denylist/approval live in the tool
  layer and read engagement config, never the conversation.
- **Safe-by-default & authorized.** Public targets refused; DVWA/VulnLab are
  deliberately vulnerable practice apps.
- **45 automated tests**, validated live against DVWA.

---

## C. Likely questions → answers

| Question | Answer |
|---|---|
| Why not just use ZAP / Burp? | Tiny, transparent, auditable; confirms exploitability; adds an AI orchestration layer. Complements them (see the comparison table). |
| How do you avoid false positives? | Confirmation by behavior/content, re-tested timing; benchmark shows 0 FP. |
| Is this legal / safe? | Authorized testing only; local deliberately-vulnerable targets; scope guard refuses public hosts; approval gate for state-changing actions. |
| What does the AI actually do? | Plans, chains findings, re-tests, triages, writes up. Detection is deterministic (zero-token). Brain vs. hands. |
| Did you jailbreak the model? | No. The task is legitimate authorized testing; I gave the model accurate context and picked a model whose policy permits it. |
| What did it cost? | Free — Gemini free tier (gemini-3.5-flash-lite). |

---

## D. If the live demo breaks

- **Gemini 503 / slow** → use the **pre-generated AI report** (§0.4). "Free-tier
  spike; here's a run from earlier."
- **No internet** → the deterministic scan + `benchmark/score.py` run **fully
  offline**; VulnLab needs no network.
- **Anything else** → `pytest -q` (45 passing) proves the whole system works.

---

## E. Hand over

- **GitHub:** https://github.com/iJainamJain/Fissure
- **One-pager:** `Fissure_Project_Summary.pdf`
- **One HTML report** (from §A.2 or §A.3).
