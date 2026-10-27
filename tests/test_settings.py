"""ai-perimeter.yaml: off unless configured, cloud only when allowed."""

from __future__ import annotations

import pytest

from ai_perimeter.client import ConfigError
from ai_perimeter.settings import load_settings, parse_settings

KEY = "sk-test-0123456789abcdef"


def test_a_missing_file_means_off(tmp_path):
    assert load_settings(tmp_path / "none.yaml").enabled is False


@pytest.mark.parametrize("text", ["", "enabled: false\n", "provider: meta\n"])
def test_not_enabled_means_off(tmp_path, text):
    path = tmp_path / "ai.yaml"
    path.write_text(text)
    settings = load_settings(path)
    assert settings.enabled is False and settings.provider is None


def test_a_local_provider(tmp_path):
    path = tmp_path / "ai.yaml"
    path.write_text("enabled: true\nmodel: muse-glimmer\n")
    s = load_settings(path)
    assert s.enabled and s.provider.name == "local" and not s.provider.cloud


@pytest.mark.parametrize("raw, match", [
    ({"enabled": True, "allow_clowd": True}, "unknown key"),
    ({"enabled": "yes"}, "true or false"),
    ({"enabled": True, "allow_cloud": 1}, "true or false"),
    ({"enabled": True, "model": 5}, "must be a string"),
    ({"enabled": True, "provider": "meta"}, "allow_cloud"),
    ([1, 2], "mapping"),
])
def test_bad_settings_are_refused(raw, match):
    with pytest.raises(ConfigError, match=match):
        parse_settings(raw)


def test_invalid_yaml_is_refused(tmp_path):
    path = tmp_path / "ai.yaml"
    path.write_text("enabled: [\n")
    with pytest.raises(ConfigError, match="YAML"):
        load_settings(path)


def test_the_systemd_credential_is_the_key(tmp_path, monkeypatch):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "api_key").write_text(KEY)
    (creds / "api_key").chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    s = parse_settings({"enabled": True, "provider": "baseten", "allow_cloud": True,
                        "api_key_file": "/somewhere/else"})
    assert s.provider.api_key_file == creds / "api_key"


def test_an_empty_credential_means_no_key(tmp_path, monkeypatch):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "api_key").write_text("")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    s = parse_settings({"enabled": True, "model": "muse-glimmer"})
    assert s.provider.api_key_file is None
