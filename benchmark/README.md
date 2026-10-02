# Benchmarking Fissure

This folder supports the lab write-up: a zero-dependency vulnerable target for
smoke-testing, plus the methodology for comparing Fissure against DVWA (ground
truth) and Nikto (an established scanner).

## 1. VulnLab (bundled, zero-dependency)

`vulnlab.py` is a tiny WSGI app reproducing one instance of each flaw Fissure
detects. Use it to prove the tool works without installing anything.

```bash
python benchmark/vulnlab.py               # http://127.0.0.1:8000
python -m fissure http://127.0.0.1:8000 --html -o out/vulnlab.json
```

**Expected:** 5 findings — error-based SQLi (`/search?q`), error+time-based SQLi
(`/item?id`), reflected XSS (`/search?q`), open redirect (`/go?next`), exposed
`.env`. Risk label **CRITICAL**.

## 2. DVWA (ground truth)

DVWA is the reference vulnerable app for the WAS lab. Because each DVWA
vulnerability page is *known*, it lets you measure Fissure's **true positives**
and **false negatives** per security level.

Setup:
1. Start DVWA (XAMPP or `docker run --rm -p 80:80 vulnerables/web-dvwa`).
2. Log in (`admin` / `password`), set **DVWA Security = low**, create the DB.
3. Grab your `PHPSESSID` from the browser, or use `--login-url` (see main README).

Run:
```bash
python -m fissure "http://localhost/dvwa/vulnerabilities/sqli/" --html \
  --cookie PHPSESSID=<id> --cookie security=low -o out/dvwa_sqli_low.json
python -m fissure "http://localhost/dvwa/vulnerabilities/xss_r/" --html \
  --cookie PHPSESSID=<id> --cookie security=low -o out/dvwa_xss_low.json
```

Repeat at `security=medium` and `security=high` and record whether each known
vulnerability is still detected. Fewer detections at higher levels is the
*correct* result (DVWA adds real filtering) — document it as such.

### Scorecard to fill in

| DVWA page | Level | Known vuln | Fissure detected? | Notes |
|---|---|---|---|---|
| `sqli/` | low | SQLi | | |
| `sqli_blind/` | low | blind SQLi (time-based) | | |
| `xss_r/` | low | reflected XSS | | |
| `xss_r/` | medium | reflected XSS (filtered) | | |
| `sqli/` | high | SQLi (parameterized) | | expect **not** detected |

## 3. Nikto (tool comparison)

Nikto is a passive/misconfiguration scanner — a good contrast because it and
Fissure overlap only partly (default files) and diverge on active injection.

```bash
nikto -h http://localhost/dvwa/ -o out/nikto_dvwa.txt
```

Compare on three axes and put the table in the report:

| Capability | Fissure | Nikto |
|---|---|---|
| Active SQL injection (error/boolean/time) | ✅ | ❌ |
| Reflected XSS via payload reflection | ✅ | ❌ (signature only) |
| Open redirect | ✅ | partial |
| Default/sensitive files | ✅ (short list) | ✅ (large DB) |
| Server/software fingerprinting | ❌ | ✅ |
| Machine-readable JSON + HTML report | ✅ | ✅ (`-Format`) |

**Takeaway for the write-up:** Nikto is broader on misconfiguration and
fingerprinting; Fissure is deeper on *confirming exploitable injection* by
sending payloads and observing the app's reaction — the two are complementary,
which is exactly why active testing was worth building.
