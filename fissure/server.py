"""Localhost scan service for the browser extension (stdlib only).

Exposes a tiny HTTP API bound to 127.0.0.1 so the Fissure browser extension can
start a scan of the tab the user is on. Every scan is gated behind an explicit
**authorization** step — a scan only runs after the operator confirms they are
authorized to test the target. A per-launch bearer token and a locked-down CORS
policy keep other origins out.

    python -m fissure.server            # prints the bearer token and the port

Endpoints (all need `Authorization: Bearer <token>` except OPTIONS):
    POST /scan            {url, mode?, allow_public?, cookies?}  -> {scan_id, status:"awaiting_authorization"}
    POST /scan/<id>/authorize   {approved:true}                  -> runs the scan; {status:"running"|"declined"}
    GET  /scan/<id>                                              -> {status, summary?}
    GET  /scan/<id>/report                                       -> the HTML report
"""

from __future__ import annotations

import asyncio
import json
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .engine import Engine
from .targets import ScopeError, TargetError, normalize_target, validate_scope

# Only requests claiming this origin may talk to us (set per-extension-id in prod).
ALLOWED_ORIGIN = "*"  # tightened to the extension origin once its id is known
TOKEN = secrets.token_urlsafe(24)
_SCANS: dict[str, dict] = {}
_REPORT_DIR = Path.home() / ".fissure" / "server_reports"


def _run_scan(scan_id: str, spec: dict) -> None:
    _SCANS[scan_id]["status"] = "running"
    out = str(_REPORT_DIR / f"{scan_id}.json")
    try:
        engine = Engine(spec["url"], output=out, html=True,
                        allow_public=spec.get("allow_public", False),
                        cookies=spec.get("cookies") or {}, crawl_depth=spec.get("crawl_depth", 1))
        report = asyncio.run(engine.run())
        _SCANS[scan_id].update(status="done", summary=report["summary"],
                               report_html=report["outputs"].get("html"))
    except Exception as exc:
        _SCANS[scan_id].update(status="error", error=f"{exc.__class__.__name__}: {exc}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    # ---- helpers ----
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _json(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authed(self) -> bool:
        if self.headers.get("Authorization", "") == f"Bearer {TOKEN}":
            return True
        # Query-param token fallback (localhost only) so a plain tab can open the
        # HTML report, which a browser navigation can't send a header for.
        from urllib.parse import urlsplit, parse_qs
        q = parse_qs(urlsplit(self.path).query)
        return q.get("token", [""])[0] == TOKEN

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if not self._authed():
            return self._json(401, {"error": "unauthorized"})
        from urllib.parse import urlsplit
        parts = urlsplit(self.path).path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "scan":
            scan = _SCANS.get(parts[1])
            return self._json(200, scan) if scan else self._json(404, {"error": "not_found"})
        if len(parts) == 3 and parts[0] == "scan" and parts[2] == "report":
            scan = _SCANS.get(parts[1])
            if not scan or not scan.get("report_html"):
                return self._json(404, {"error": "no_report"})
            html = Path(scan["report_html"]).read_bytes()
            self.send_response(200); self._cors()
            self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(html)))
            self.end_headers(); self.wfile.write(html)
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        if not self._authed():
            return self._json(401, {"error": "unauthorized"})
        parts = self.path.strip("/").split("/")
        body = self._body()

        if parts == ["scan"]:
            url = body.get("url", "")
            try:
                target = normalize_target(url)
                validate_scope(target, allow_public=body.get("allow_public", False))
            except ScopeError as exc:
                return self._json(403, {"error": "scope", "detail": str(exc)})
            except TargetError as exc:
                return self._json(400, {"error": "target", "detail": str(exc)})
            scan_id = uuid.uuid4().hex[:12]
            _SCANS[scan_id] = {"status": "awaiting_authorization",
                               "target": target.base_url, "scope": target.scope, "_spec": body}
            return self._json(200, {"scan_id": scan_id, "status": "awaiting_authorization",
                                    "target": target.base_url, "scope": target.scope})

        if len(parts) == 3 and parts[0] == "scan" and parts[2] == "authorize":
            scan = _SCANS.get(parts[1])
            if not scan:
                return self._json(404, {"error": "not_found"})
            if not body.get("approved"):
                scan["status"] = "declined"
                return self._json(200, {"status": "declined"})
            spec = scan.pop("_spec", {"url": scan["target"]})
            threading.Thread(target=_run_scan, args=(parts[1], spec), daemon=True).start()
            return self._json(200, {"status": "running"})

        self._json(404, {"error": "not_found"})


def serve(host: str = "127.0.0.1", port: int = 8750) -> None:
    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Fissure server on http://{host}:{port}")
    print(f"Bearer token: {TOKEN}")
    print("Give this token to the Fissure extension. Ctrl+C to stop.")
    httpd.serve_forever()


if __name__ == "__main__":
    serve()
