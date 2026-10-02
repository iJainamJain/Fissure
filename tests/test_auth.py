"""Auth robustness: token-aware form login + auto re-login on session expiry."""

from __future__ import annotations

from fissure.http import Session, _extract_hidden_token


def test_extract_hidden_token_autodetect():
    html = '<input type="hidden" name="user_token" value="abc123"><input name="username">'
    assert _extract_hidden_token(html, None) == ("user_token", "abc123")


def test_extract_hidden_token_explicit_name():
    html = '<input type="hidden" name="csrfmiddlewaretoken" value="zzz">'
    assert _extract_hidden_token(html, "csrfmiddlewaretoken") == ("csrfmiddlewaretoken", "zzz")


async def test_token_login_succeeds(vulnlab_url):
    async with Session() as s:
        ok = await s.login(f"{vulnlab_url}/login",
                           {"username": "admin", "password": "password"},
                           success_text="Welcome admin")
        assert ok
        # Authenticated page is reachable.
        r = await s.client.get(f"{vulnlab_url}/secret?q=1", follow_redirects=False)
        assert r.status_code == 200


async def test_login_fails_with_bad_password(vulnlab_url):
    async with Session() as s:
        ok = await s.login(f"{vulnlab_url}/login",
                           {"username": "admin", "password": "wrong"},
                           success_text="Welcome admin")
        assert not ok


async def test_auto_relogin_after_session_drop(vulnlab_url):
    async with Session() as s:
        assert await s.login(f"{vulnlab_url}/login",
                             {"username": "admin", "password": "password"},
                             success_text="Welcome admin")
        # Simulate the session expiring mid-scan.
        s.client.cookies.clear()
        dropped = await s.client.get(f"{vulnlab_url}/secret", follow_redirects=False)
        assert dropped.status_code == 302  # logged out now

        # ensure_authenticated should detect it and transparently log back in.
        assert await s.ensure_authenticated(f"{vulnlab_url}/secret")
        restored = await s.client.get(f"{vulnlab_url}/secret?q=1", follow_redirects=False)
        assert restored.status_code == 200


async def test_ensure_authenticated_noop_without_login(vulnlab_url):
    # Cookie-only scans never logged in, so there is nothing to re-auth.
    async with Session() as s:
        assert await s.ensure_authenticated(f"{vulnlab_url}/secret")
