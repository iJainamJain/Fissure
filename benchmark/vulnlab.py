"""VulnLab — a tiny, intentionally vulnerable WSGI app.

Zero dependencies (pure WSGI, stdlib only). It exists so Fissure can be run
end-to-end without needing DVWA installed, and so the automated tests have a
deterministic target that reproduces each flaw class:

    GET /search?q=       reflected XSS (echoes q unescaped) + error-based SQLi
    GET /item?id=        error-based + time-based (SLEEP) + boolean-based SQLi
    GET /go?next=        open redirect
    GET /.env            sensitive-file exposure

Run standalone:  python benchmark/vulnlab.py  ->  http://127.0.0.1:8000
NEVER expose this on a public interface.
"""

from __future__ import annotations

import html
import re
import secrets
import time
from http.cookies import SimpleCookie
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, unquote
from wsgiref.simple_server import WSGIServer, make_server


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Multi-threaded WSGI server so concurrent scanner requests aren't serialized."""
    daemon_threads = True

# In-memory auth state for the login demo (/login, /secret).
_ISSUED_TOKENS: set[str] = set()
_VALID_SESSIONS: set[str] = set()

HOME = (
    "<html><body><h1>VulnLab</h1>"
    '<a href="/search?q=hello">search</a> '
    '<a href="/item?id=1">item</a> '
    '<a href="/go?next=/home">go</a> '
    '<a href="/ping?host=127.0.0.1">ping</a> '
    '<a href="/view?file=readme.txt">view</a> '
    '<a href="/render?name=guest">render</a> '
    '<a href="/api">api</a>'
    "</body></html>"
)


def _text(start, body: str, status: str = "200 OK", extra_headers=None):
    data = body.encode()
    headers = [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(data)))]
    if extra_headers:
        headers.extend(extra_headers)
    start(status, headers)
    return [data]


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    qs = parse_qs(environ.get("QUERY_STRING", ""))

    if path == "/":
        return _text(start_response, HOME)

    if path == "/search":
        q = qs.get("q", [""])[0]
        if "'" in q or '"' in q:  # error-based SQLi leak
            return _text(start_response,
                         f"<p>You have an error in your SQL syntax near '{html.escape(q)}'</p>",
                         status="500 Internal Server Error")
        # reflected XSS: q echoed with no encoding
        return _text(start_response, f"<html><body>Results for {q}</body></html>")

    if path == "/item":
        id_ = qs.get("id", [""])[0]
        if re.search(r"sleep\((\d+)\)", id_, re.IGNORECASE):
            secs = int(re.search(r"sleep\((\d+)\)", id_, re.IGNORECASE).group(1))
            time.sleep(min(secs, 6))
            return _text(start_response, "<p>ok</p>")
        if "'" in id_:  # error-based
            return _text(start_response, "<p>SQLite error: unrecognized token</p>", status="500 Internal Server Error")
        # boolean-based: TRUE returns a long row, FALSE returns an empty result
        if "1'='1" in id_:
            return _text(start_response, "<p>" + "row-data " * 50 + "</p>")
        if "1'='2" in id_:
            return _text(start_response, "<p></p>")
        return _text(start_response, f"<p>item {html.escape(id_)}</p>")

    if path == "/go":
        nxt = qs.get("next", [""])[0]
        return _text(start_response, "", status="302 Found", extra_headers=[("Location", nxt)])

    if path == "/ping":
        host = qs.get("host", ["127.0.0.1"])[0]
        # Simulated OS command injection: a shell sleep/ping delay actually sleeps.
        m = re.search(r"sleep\s+(\d+)", host, re.IGNORECASE) or re.search(r"ping\s+-n\s+(\d+)", host, re.IGNORECASE)
        if m:
            secs = int(m.group(1))
            if "ping" in host.lower():
                secs -= 1  # ping -n N ≈ N-1 seconds of delay
            time.sleep(min(max(secs, 0), 8))
            return _text(start_response, "<pre>ping complete</pre>")
        return _text(start_response, f"<pre>PING {html.escape(host)}: 64 bytes</pre>")

    if path == "/view":
        fname = qs.get("file", [""])[0]
        decoded = unquote(fname).replace("\\", "/").lower()
        # Simulated path traversal / LFI: traversal to a known system file reads it.
        if "etc/passwd" in decoded:
            return _text(start_response, "root:x:0:0:root:/root:/bin/bash\n"
                                         "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
        if "win.ini" in decoded:
            return _text(start_response, "[fonts]\n[extensions]\n; for 16-bit app support\n")
        return _text(start_response, f"<pre>contents of {html.escape(fname)}</pre>")

    if path == "/render":
        name = qs.get("name", [""])[0]
        # Simulated template engine: evaluate arithmetic inside {{ }} or { } delimiters.
        # Output is HTML-escaped first, so this models SSTI without also being XSS.
        rendered = html.escape(name)
        rendered = re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}",
                          lambda m: str(int(m.group(1)) * int(m.group(2))), rendered)
        rendered = re.sub(r"\{\s*(\d+)\s*\*\s*(\d+)\s*\}",
                          lambda m: str(int(m.group(1)) * int(m.group(2))), rendered)
        return _text(start_response, f"<p>Hello {rendered}</p>")

    if path == "/api":
        # Simulated vulnerable CORS: reflects the request Origin and allows credentials.
        origin = environ.get("HTTP_ORIGIN", "")
        return _text(start_response, '{"ok": true}', status="200 OK", extra_headers=[
            ("Access-Control-Allow-Origin", origin or "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ])

    if path == "/.env":
        return _text(start_response, "DB_PASSWORD=supersecret\nAPI_KEY=abc123")

    # --- Login demo: anti-CSRF token + a session-protected page ---
    if path == "/login":
        if environ.get("REQUEST_METHOD") == "POST":
            body = _read_body(environ)
            form = parse_qs(body)
            token = form.get("user_token", [""])[0]
            user = form.get("username", [""])[0]
            pw = form.get("password", [""])[0]
            if token in _ISSUED_TOKENS and user == "admin" and pw == "password":
                _ISSUED_TOKENS.discard(token)
                sid = secrets.token_hex(8)
                _VALID_SESSIONS.add(sid)
                return _text(start_response, "<p>Welcome admin</p>", status="200 OK",
                             extra_headers=[("Set-Cookie", f"FISSESSION={sid}; Path=/")])
            return _text(start_response, "<p>Login failed</p>", status="200 OK")
        token = secrets.token_hex(8)
        _ISSUED_TOKENS.add(token)
        return _text(start_response,
                     "<form method='POST' action='/login'>"
                     f"<input type='hidden' name='user_token' value='{token}'>"
                     "<input name='username'><input type='password' name='password'>"
                     "<input type='submit' name='Login' value='Login'></form>")

    if path == "/secret":
        if _session_id(environ) in _VALID_SESSIONS:
            q = qs.get("q", [""])[0]
            return _text(start_response, f"<html><body>secret area, you searched {q}</body></html>")
        return _text(start_response, "", status="302 Found", extra_headers=[("Location", "/login")])

    return _text(start_response, "<p>not found</p>", status="404 Not Found")


def _read_body(environ) -> str:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length <= 0:
        return ""
    return environ["wsgi.input"].read(length).decode("utf-8", "replace")


def _session_id(environ) -> str:
    cookie = SimpleCookie(environ.get("HTTP_COOKIE", ""))
    morsel = cookie.get("FISSESSION")
    return morsel.value if morsel else ""


if __name__ == "__main__":
    with make_server("127.0.0.1", 8000, app, server_class=ThreadingWSGIServer) as server:
        print("VulnLab on http://127.0.0.1:8000  (Ctrl+C to stop)")
        server.serve_forever()
