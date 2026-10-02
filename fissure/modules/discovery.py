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

    def __init__(self, session: Session, target: Target, *, concurrency: int = 8) -> None:
        self.session = session
        self.target = target
        self.concurrency = concurrency

    async def scan(self) -> ModuleResult:
        from ..concurrency import map_bounded
        findings: list[Finding] = []
        errors: list[str] = []
        hits = 0

        for finding, err, hit in await map_bounded(WORDLIST, self._probe_path, self.concurrency):
            if err:
                errors.append(err)
            if hit:
                hits += 1
            if finding:
                findings.append(finding)

        status = "success" if not errors else "partial"
        summary = f"{len(findings)} path finding(s) from {len(WORDLIST)} probes ({hits} reachable)."
        return ModuleResult(module=self.module, status=status, summary=summary, findings=findings,
                            data={"paths_probed": len(WORDLIST), "reachable": hits}, errors=errors)

    async def _probe_path(self, path: str) -> tuple[Finding | None, str | None, bool]:
        url = self.target.base_url.rstrip("/") + "/" + path
        try:
            resp = await self.session.client.get(url, follow_redirects=False)
        except Exception as exc:
            return (None, f"{url}: {exc.__class__.__name__}: {exc}", False)
        if resp.status_code != 200:
            return (None, None, False)
        if INDEX_OF_RE.search(resp.text):
            return (Finding(title="Directory listing enabled", severity="medium", cwe="CWE-548",
                            location=url, evidence="Response body contains an autoindex 'Index of /' listing.",
                            metadata={"status": 200}), None, True)
        if path in SENSITIVE:
            return (Finding(title=f"Sensitive file exposed: {path}", severity="high", cwe="CWE-538",
                            location=url, evidence=f"HTTP 200 for a sensitive path ({len(resp.content)} bytes).",
                            metadata={"status": 200, "bytes": len(resp.content)}), None, True)
        return (Finding(title=f"Default/known file reachable: {path}", severity="low", cwe="CWE-200",
                        location=url, evidence="HTTP 200.", confirmed=False,
                        metadata={"status": 200}), None, True)
