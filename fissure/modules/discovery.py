"""Default-file and directory-listing discovery.

Requests a small wordlist of commonly exposed paths relative to the target
root and flags: reachable admin/config/backup files (HTTP 200), and any
response whose body carries an autoindex "Index of /" banner.
"""

from __future__ import annotations

import re

from ..http import Session
from ..reporting import Finding, ModuleResult
from ..targets import Target

# Kept short and lab-relevant; extend from a file for a fuller scan.
WORDLIST = [
    ".git/HEAD", ".env", "config.php", "config.php.bak", "backup.zip", "backup.sql",
    "db.sql", "phpinfo.php", "info.php", "admin/", "phpmyadmin/", "server-status",
    "robots.txt", ".htaccess", "wp-config.php.bak", "test.php", "uploads/",
]
INDEX_OF_RE = re.compile(r"<title>\s*index of /", re.IGNORECASE)
SENSITIVE = {".git/HEAD", ".env", "config.php.bak", "backup.zip", "backup.sql", "db.sql", "wp-config.php.bak", ".htaccess"}


class DiscoveryScanner:
    module = "discovery"

    def __init__(self, session: Session, target: Target) -> None:
        self.session = session
        self.target = target

    async def scan(self) -> ModuleResult:
        findings: list[Finding] = []
        errors: list[str] = []
        hits = 0

        for path in WORDLIST:
            url = self.target.base_url.rstrip("/") + "/" + path
            try:
                resp = await self.session.client.get(url, follow_redirects=False)
            except Exception as exc:
                errors.append(f"{url}: {exc.__class__.__name__}: {exc}")
                continue

            if resp.status_code == 200:
                hits += 1
                if INDEX_OF_RE.search(resp.text):
                    findings.append(Finding(
                        title="Directory listing enabled",
                        severity="medium",
                        cwe="CWE-548",
                        location=url,
                        evidence="Response body contains an autoindex 'Index of /' listing.",
                        metadata={"status": 200},
                    ))
                elif path in SENSITIVE:
                    findings.append(Finding(
                        title=f"Sensitive file exposed: {path}",
                        severity="high",
                        cwe="CWE-538",
                        location=url,
                        evidence=f"HTTP 200 for a sensitive path ({len(resp.content)} bytes).",
                        metadata={"status": 200, "bytes": len(resp.content)},
                    ))
                else:
                    findings.append(Finding(
                        title=f"Default/known file reachable: {path}",
                        severity="low",
                        cwe="CWE-200",
                        location=url,
                        evidence="HTTP 200.",
                        confirmed=False,
                        metadata={"status": 200},
                    ))

        status = "success" if not errors else "partial"
        summary = f"{len(findings)} path finding(s) from {len(WORDLIST)} probes ({hits} reachable)."
        return ModuleResult(module=self.module, status=status, summary=summary, findings=findings,
                            data={"paths_probed": len(WORDLIST), "reachable": hits}, errors=errors)
