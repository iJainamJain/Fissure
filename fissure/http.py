"""Thin async HTTP session used by every module.

Wraps httpx with the auth material a lab target usually needs:
- arbitrary cookies (DVWA relies on a ``PHPSESSID`` plus a ``security`` cookie),
- custom headers,
- a real form login that is **anti-CSRF-token aware** (fetches the login page,
  extracts a hidden token such as DVWA's ``user_token``, and submits it), and
- **automatic re-login** when the session drops mid-scan, so a long scan does
  not silently turn every later finding into a false negative.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

# Hidden fields that look like anti-CSRF tokens, for auto-detection on login pages.
_TOKEN_NAME_RE = re.compile(r"(user_token|csrf[-_]?token|authenticity_token|_csrf|_token|csrfmiddlewaretoken)", re.I)


def _extract_hidden_token(html: str, field_name: str | None) -> tuple[str, str] | None:
    """Return (name, value) of a hidden token input, or None.

    If ``field_name`` is given, match that exact name; otherwise auto-detect a
    hidden input whose name looks like a CSRF token.
    """
    for tag in re.findall(r"<input\b[^>]*>", html, re.I):
        # Handle both single- and double-quoted attributes (DVWA uses single quotes).
        attrs = {m[0]: (m[2] or m[3]) for m in re.findall(r"""(\w[\w-]*)\s*=\s*("([^"]*)"|'([^']*)')""", tag)}
        name = attrs.get("name", "")
        if not name or "value" not in attrs:
            continue
        if field_name is not None:
            if name == field_name:
                return name, attrs["value"]
        elif _TOKEN_NAME_RE.search(name):
            return name, attrs["value"]
    return None


def _looks_logged_out(resp: httpx.Response) -> bool:
    if resp.status_code in (401, 403):
        return True
    if 300 <= resp.status_code < 400:
        return "login" in resp.headers.get("location", "").lower()
    return False


@dataclass
class Session:
    timeout: float = 10.0
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    verify_tls: bool = False  # lab targets often use self-signed certs
    max_relogin: int = 3
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)
    _login_cfg: dict | None = field(default=None, init=False, repr=False)
    _relogins: int = field(default=0, init=False, repr=False)

    async def __aenter__(self) -> "Session":
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_tls,
            follow_redirects=False,  # modules decide when to follow (open-redirect needs raw 3xx)
            headers={"User-Agent": "Fissure/0.1 (authorized lab scan)", **self.headers},
            cookies=self.cookies,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Session used outside 'async with'.")
        return self._client

    async def login(
        self,
        url: str,
        data: dict[str, str],
        *,
        token_field: str | None = None,
        auto_token: bool = True,
        success_text: str | None = None,
    ) -> bool:
        """Perform a form login, handling an anti-CSRF token if the form has one.

        On success, remembers the configuration so the session can transparently
        re-authenticate later (see :meth:`ensure_authenticated`). Returns whether
        the login looks successful.
        """
        post_data = dict(data)
        if token_field or auto_token:
            try:
                page = await self.client.get(url, follow_redirects=True)
                found = _extract_hidden_token(page.text, token_field)
                if found:
                    post_data[found[0]] = found[1]
            except httpx.HTTPError:
                pass  # proceed without a token; the POST will simply fail if one was required

        resp = await self.client.post(url, data=post_data, follow_redirects=True)
        ok = (success_text in resp.text) if success_text is not None else resp.status_code < 400
        if ok:
            self._login_cfg = {"url": url, "data": data, "token_field": token_field,
                               "auto_token": auto_token, "success_text": success_text}
        return ok

    # Backwards-compatible alias.
    async def form_login(self, url: str, data: dict[str, str], *, success_text: str | None = None) -> bool:
        return await self.login(url, data, success_text=success_text)

    async def ensure_authenticated(self, probe_url: str) -> bool:
        """If we logged in and the session has since dropped, log in again.

        No-op (returns True) when no form login was ever performed — e.g. a
        cookie-only scan, where there are no credentials to re-authenticate with.
        Capped at ``max_relogin`` attempts to avoid loops.
        """
        if not self._login_cfg:
            return True
        try:
            resp = await self.client.get(probe_url, follow_redirects=False)
        except httpx.HTTPError:
            return True  # can't probe; let the caller proceed and surface its own error
        if not _looks_logged_out(resp):
            return True
        if self._relogins >= self.max_relogin:
            return False
        self._relogins += 1
        cfg = self._login_cfg
        return await self.login(cfg["url"], cfg["data"], token_field=cfg["token_field"],
                                auto_token=cfg["auto_token"], success_text=cfg["success_text"])
