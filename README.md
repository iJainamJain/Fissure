# Fissure — Active Web Application Vulnerability Scanner

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![tests](https://img.shields.io/badge/tests-13%20passing-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

Fissure is a modular Python scanner that **actively tests** a web application
for injectable vulnerabilities. Unlike passive/recon scanners that only read
headers and probe ports, Fissure crawls a target, extracts its query
parameters and form inputs, and fires crafted payloads at each one to confirm:

| Module | Detects | Techniques | CWE |
|---|---|---|---|
| `sqli` | SQL injection | error-based, boolean-based, time-based (blind) | CWE-89 |
| `xss` | Reflected cross-site scripting | unescaped reflection across HTML / attribute / script contexts | CWE-79 |
| `cmdi` | OS command injection | time-based blind (`sleep`/`ping`, non-destructive) | CWE-78 |
| `traversal` | Path traversal / LFI | `../` + encodings; matches file-content signature, not echoed payload | CWE-22 |
| `redirect` | Open redirect | `Location` header + `<meta refresh>` on navigation params | CWE-601 |
| `discovery` | Default files / directory listing | sensitive-path wordlist + autoindex detection | CWE-538/548 |
| `headers` | Security-header & cookie misconfig (passive, OWASP A05) | missing CSP/HSTS/XFO… + HttpOnly/Secure/SameSite | CWE-693… |

Results are scored, labelled (`CLEAN → CRITICAL`), carry **CWE ids**, and are written as
**JSON**, a self-contained **HTML report**, and optional **SARIF 2.1.0** (`--sarif`) for CI /
GitHub code scanning. `--fail-on <severity>` turns Fissure into a build gate.

Authenticated scans are self-managing: Fissure performs a **token-aware form login**
(auto-detects anti-CSRF fields like DVWA's `user_token`) and **re-logs-in automatically** if the
session drops mid-scan.

> ⚠️ **Authorized use only.** Fissure sends real attack payloads. It refuses
> public targets by default and only scans `localhost`/private hosts unless you
> pass `--allow-public`, which stands in for *"I have written permission to test
> this system."* This tool is built for the WAS lab against DVWA and the bundled
> VulnLab target.

---

## Architecture

```
                 ┌──────────┐
   target  ─────►│  Engine  │  scope guard → crawl once → run modules → score → report
                 └────┬─────┘
                      │ Injectable(method, url, param, params)
        ┌─────────────┼───────────────┬───────────────┐
        ▼             ▼               ▼               ▼
     sqli.py       xss.py        redirect.py     discovery.py
        └─────── each returns ModuleResult[ Finding ] ───────┘
                      │
              JSON + HTML report
```

- **`targets.py`** — one canonical `Target`; `local`/`private`/`public` scope classification and enforcement.
- **`crawler.py`** — same-host BFS crawl; harvests query params and form fields as `Injectable`s. Modules test *what is found*, never guessed URLs.
- **`http.py`** — async httpx session with cookie/header auth and optional form login (DVWA needs `PHPSESSID` + `security`).
- **`modules/`** — one file per vulnerability class; each returns explicit `success/partial/failure` status so "clean" is distinguishable from "couldn't test".
- **`reporting.py` / `html_report.py`** — findings, severity→points scoring, and rendering.

Heuristic findings (e.g. boolean-based SQLi) are flagged `confirmed: false` and
marked "confirm manually" in the report, so the tool never over-claims.

## Install

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (source .venv/bin/activate on *nix)
pip install -r requirements.txt
```

## Quick start

Run the bundled deliberately-vulnerable target, then scan it:

```bash
python benchmark/vulnlab.py           # terminal 1 -> http://127.0.0.1:8000
python -m fissure http://127.0.0.1:8000 --html
```

Scan DVWA (log in first so the crawler stays authenticated):

```bash
python -m fissure http://localhost/dvwa/ --html \
  --cookie PHPSESSID=<your-session-id> \
  --cookie security=low
```

Or let Fissure log in for you:

```bash
python -m fissure http://localhost/dvwa/ --html \
  --login-url http://localhost/dvwa/login.php \
  --login-data username=admin --login-data password=password \
  --login-success-text Logout
```

### Useful flags

| Flag | Meaning |
|---|---|
| `--html` | also write `report.html` next to the JSON |
| `--cookie NAME=VALUE` | session cookie (repeatable) |
| `--header NAME=VALUE` | extra request header (repeatable) |
| `--crawl-pages / --crawl-depth / --crawl-delay` | bound and slow the crawl |
| `--allow-public` | permit a public target (**authorization required**) |
| `-o path.json` | report output path |

Exit codes: `0` clean · `1` findings present · `2` bad target / scope refused.

## Desktop app (GUI)

A Tkinter GUI wraps the same engine — paste a URL, add auth cookies if needed,
click **Scan**, watch per-module progress, browse findings, and open the HTML
report:

```bash
python -m fissure.gui
```

### Build a standalone Windows .exe

No Python needed on the demo machine:

```bash
pip install pyinstaller
python build_exe.py          # -> dist/Fissure.exe  (~15 MB, single file)
```

Double-click `dist/Fissure.exe`. Tkinter ships with CPython, so only `httpx`
is bundled.

## Fissure AI (Step 2 — experimental)

A Claude-orchestrated agent that drives the Fissure modules as a toolbelt: it
crawls, decides which module to run on which input, chains and confirms findings,
and writes the report. Detection stays deterministic (zero LLM tokens); the model
only plans and judges. Safety (scope, payload denylist, approval for
state-changing requests) is enforced in the **tool layer**, not the prompt.

```bash
pip install fissure-scan[ai]          # adds the anthropic SDK
export ANTHROPIC_API_KEY=...           # set your key
fissure-ai http://localhost:8080/ --sarif
```

Design: [docs/FISSURE_AI_DESIGN.md](docs/FISSURE_AI_DESIGN.md). The orchestrator
loop, tool registry, and guardrails are covered by offline tests using a scripted
mock model, so the agent is verifiable without any API call.

## Testing

```bash
pip install pytest pytest-asyncio
pytest -q          # 31 tests: scope/auth logic, each module vs live VulnLab, SARIF, and the AI agent loop
```

## Benchmarking

`benchmark/score.py` scores Fissure against VulnLab's known vulnerabilities
(`benchmark/ground_truth.json`) and reports precision / recall / F1:

```bash
python benchmark/score.py
```

Current result on VulnLab: **precision 1.000 · recall 1.000 · F1 1.000** (7/7, 0 FP).
See [`benchmark/README.md`](benchmark/README.md) for the DVWA scorecard and the
OWASP ZAP / Nikto comparison methodology.

## Scope & safety

- Public targets refused unless `--allow-public` is given.
- Time-based SQLi is re-tested before reporting, to reject one-off slow responses.
- VulnLab must never be exposed on a public interface.

## Roadmap

- Stored-XSS (inject on one endpoint, detect on another)
- CSRF-token awareness during form submission
- Authenticated multi-step crawl
- SARIF export for CI

## License

MIT.
