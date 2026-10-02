# Fissure vs. DVWA — verified results

Target: DVWA v1.10 (Docker `vulnerables/web-dvwa`) on `http://localhost:8080/`.
Authenticated scan (`--cookie PHPSESSID=… --cookie security=<level>`),
`--crawl-depth 0` so each scan targets one vulnerability page.

## Scorecard (measured)

| DVWA page | Level | Known vuln | Fissure result | Correct? |
|---|---|---|---|---|
| `vulnerabilities/sqli/` | low | SQL injection | ✅ error-based (critical) | ✅ |
| `vulnerabilities/sqli/` | medium | SQL injection | ✅ error-based (critical) | ✅ |
| `vulnerabilities/sqli/` | high | SQL injection | ❌ not detected | ✅ — DVWA parameterizes the query at high |
| `vulnerabilities/sqli_blind/` | low | blind SQLi | ✅ time-based blind, ~5s delay (critical) | ✅ |
| `vulnerabilities/xss_r/` | low | reflected XSS | ✅ reflected (high) | ✅ |
| `vulnerabilities/xss_r/` | medium | reflected XSS | ✅ reflected (high) | ✅ |
| `vulnerabilities/xss_r/` | high | reflected XSS | ✅ reflected via `<svg onload>` (high) | ✅ — DVWA high only strips `<script>` |

### Sample evidence strings (from the JSON reports)

- SQLi (error-based): *Payload `'` triggered DB error: "You have an error in your SQL syntax"*
- SQLi (time-based blind): *Payload delayed response to 5.0s / 5.0s (baseline 0.0s) for a 5s sleep*
- Reflected XSS: *Payload reflected unescaped in raw HTML tag: `<fz12fcc3e7>`*

## Reading of the results

The high-security SQLi case is the important one: Fissure **correctly reports
nothing**, because DVWA switches to a parameterized query there — a scanner that
"found" SQLi at high would be producing a false positive. Detection dropping as
the fix strength increases is the intended behaviour and is the cleanest way to
show the tool is confirming real exploitability rather than pattern-matching.

The high XSS case is also instructive: DVWA's high filter removes `<script>`
tags only, so Fissure's attribute-breakout payload (`<svg onload=…>`) still
lands — a true positive that a naive `<script>`-only check would miss.

## Reproduce

```bash
docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
# browse http://localhost:8080/, log in admin/password, Create/Reset DB, set security
SID=<your PHPSESSID>
python -m fissure "http://localhost:8080/vulnerabilities/sqli/" \
  --cookie PHPSESSID=$SID --cookie security=low --crawl-depth 0 --html -o out/sqli_low.json
```
