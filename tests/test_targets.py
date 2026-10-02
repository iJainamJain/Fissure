import pytest

from fissure.targets import ScopeError, TargetError, normalize_target, validate_scope


def test_localhost_defaults_to_http():
    t = normalize_target("localhost/dvwa/")
    assert t.scheme == "http"
    assert t.scope == "local"
    assert t.base_url == "http://localhost/dvwa/".rstrip("/") or t.base_url.startswith("http://localhost")


def test_public_host_defaults_to_https_and_is_public():
    t = normalize_target("example.com")
    assert t.scheme == "https"
    assert t.scope == "public"


def test_private_ip_classified_private():
    t = normalize_target("192.168.1.10:8080")
    assert t.scope == "private"
    assert t.port == 8080


def test_public_scope_refused_without_flag():
    t = normalize_target("example.com")
    with pytest.raises(ScopeError):
        validate_scope(t, allow_public=False)
    validate_scope(t, allow_public=True)  # allowed with the opt-in


def test_local_scope_always_allowed():
    validate_scope(normalize_target("127.0.0.1"), allow_public=False)


def test_empty_target_rejected():
    with pytest.raises(TargetError):
        normalize_target("")
