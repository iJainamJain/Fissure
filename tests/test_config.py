"""On-device config persistence (keys + prefs)."""

from __future__ import annotations

import importlib


def test_config_round_trip(tmp_path, monkeypatch):
    import fissure.config as cfg
    importlib.reload(cfg)
    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cfg, "CONFIG_PATH", tmp_path / "config.json")

    cfg.save_config({"gemini_api_key": "secret", "appearance": "Light", "remember_keys": True})
    loaded = cfg.load_config()
    assert loaded["gemini_api_key"] == "secret"
    assert loaded["appearance"] == "Light"

    cfg.clear_secrets()
    after = cfg.load_config()
    assert "gemini_api_key" not in after        # secret removed
    assert after["appearance"] == "Light"       # non-secret pref kept
    assert after["remember_keys"] is False


def test_load_missing_config_is_empty(tmp_path, monkeypatch):
    import fissure.config as cfg
    monkeypatch.setattr(cfg, "CONFIG_PATH", tmp_path / "nope.json")
    assert cfg.load_config() == {}
