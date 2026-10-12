"""Localhost scan service: auth, the authorization gate, scan flow, scope refusal."""

from __future__ import annotations

import threading
import time
from http.server import ThreadingHTTPServer

import httpx

import fissure.server as srv


def _start():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def _auth():
    return {"Authorization": f"Bearer {srv.TOKEN}"}


def test_requires_bearer_token(vulnlab_url):
    httpd, base = _start()
    try:
        with httpx.Client() as c:
            assert c.post(f"{base}/scan", json={"url": vulnlab_url}).status_code == 401
    finally:
        httpd.shutdown()


def test_full_scan_flow(vulnlab_url):
    httpd, base = _start()
    try:
        with httpx.Client(timeout=40) as c:
            started = c.post(f"{base}/scan", json={"url": vulnlab_url}, headers=_auth()).json()
            assert started["status"] == "awaiting_authorization"
            sid = started["scan_id"]

            # A scan only runs after explicit authorization.
            running = c.post(f"{base}/scan/{sid}/authorize", json={"approved": True}, headers=_auth()).json()
            assert running["status"] == "running"

            status = {}
            for _ in range(80):
                status = c.get(f"{base}/scan/{sid}", headers=_auth()).json()
                if status["status"] in ("done", "error"):
                    break
                time.sleep(0.5)
            assert status["status"] == "done", status
            assert status["summary"]["total_findings"] > 0

            report = c.get(f"{base}/scan/{sid}/report", headers=_auth())
            assert report.status_code == 200 and b"Fissure" in report.content
    finally:
        httpd.shutdown()


def test_decline_does_not_run(vulnlab_url):
    httpd, base = _start()
    try:
        with httpx.Client() as c:
            sid = c.post(f"{base}/scan", json={"url": vulnlab_url}, headers=_auth()).json()["scan_id"]
            r = c.post(f"{base}/scan/{sid}/authorize", json={"approved": False}, headers=_auth()).json()
            assert r["status"] == "declined"
    finally:
        httpd.shutdown()


def test_ping_and_token_need_no_auth():
    # The extension bootstraps via /ping and /token without a bearer token.
    httpd, base = _start()
    try:
        with httpx.Client() as c:
            assert c.get(f"{base}/ping").json()["running"] is True
            assert c.get(f"{base}/token").json()["token"] == srv.TOKEN
    finally:
        httpd.shutdown()


def test_cors_only_for_extension_origin():
    httpd, base = _start()
    try:
        with httpx.Client() as c:
            web = c.get(f"{base}/ping", headers={"Origin": "https://evil.example"})
            assert "access-control-allow-origin" not in {k.lower() for k in web.headers}
            ext = c.get(f"{base}/ping", headers={"Origin": "chrome-extension://abc"})
            assert ext.headers.get("access-control-allow-origin") == "chrome-extension://abc"
    finally:
        httpd.shutdown()


def test_public_target_refused():
    httpd, base = _start()
    try:
        with httpx.Client() as c:
            r = c.post(f"{base}/scan", json={"url": "http://example.com"}, headers=_auth())
            assert r.status_code == 403
    finally:
        httpd.shutdown()
