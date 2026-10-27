"""The AI-Perimeter's own settings file, ``/etc/fr_os/ai-perimeter.yaml``.

A file of its own rather than a key in FR_OS's ``config.yaml``: the
``fr-ai-assist`` service must not be able to read ``config.yaml`` (it holds
the ZTNA password hash, the metrics token and the WireGuard peers), so what
the service needs is kept apart, and the model only ever gets the redacted
config the webUI sends it.

The AI-Perimeter is **off unless configured** (security-lessons I1, K7): a
missing file, or one without ``enabled: true``, means no model is called.
A cloud provider additionally needs ``allow_cloud: true`` (G11).

The API key is not in this file. Under systemd it comes from the unit's
``LoadCredential=api_key:...`` (``$CREDENTIALS_DIRECTORY/api_key``): the
key file stays root's, mode 0600, and systemd hands the service a private
copy only it can read. Outside systemd (a development run) the file named
by ``api_key_file`` is used.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .client import ConfigError, ProviderSettings

DEFAULT_PATH = Path("/etc/fr_os/ai-perimeter.yaml")
#: The name of the systemd credential that holds the API key.
CREDENTIAL_NAME = "api_key"

_KEYS = frozenset({"enabled", "provider", "base_url", "model", "allow_cloud",
                   "timeout", "api_key_file"})
MAX_FILE_BYTES = 16 * 1024


@dataclass(frozen=True)
class Settings:
    enabled: bool
    provider: ProviderSettings | None


def _credential_key_file() -> Path | None:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        return None
    path = Path(directory) / CREDENTIAL_NAME
    # The installer leaves an empty key file so LoadCredential= always has
    # a source; empty means "no key" (a local model needs none).
    try:
        return path if path.stat().st_size > 0 else None
    except FileNotFoundError:
        return None


def parse_settings(raw: Any) -> Settings:
    """Validate the parsed YAML. Unknown keys are refused, not ignored, so a
    typo like ``allow_clowd`` can't silently leave a setting at its default."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("ai-perimeter.yaml must be a mapping")
    unknown = sorted(str(k) for k in set(raw) - _KEYS)
    if unknown:
        raise ConfigError(f"unknown key(s) in ai-perimeter.yaml: {', '.join(unknown)}")
    enabled = raw.get("enabled", False)
    allow_cloud = raw.get("allow_cloud", False)
    for key, value in (("enabled", enabled), ("allow_cloud", allow_cloud)):
        if not isinstance(value, bool):
            raise ConfigError(f"{key} must be true or false")
    if not enabled:
        return Settings(enabled=False, provider=None)
    for key in ("provider", "base_url", "model", "api_key_file"):
        if key in raw and not isinstance(raw[key], str):
            raise ConfigError(f"{key} must be a string")
    key_file = _credential_key_file() or raw.get("api_key_file")
    provider = ProviderSettings.build(
        raw.get("provider", "local"),
        base_url=raw.get("base_url"),
        model=raw.get("model"),
        api_key_file=key_file,
        allow_cloud=allow_cloud,
        timeout=raw.get("timeout", 120),
    )
    return Settings(enabled=True, provider=provider)


def load_settings(path: str | os.PathLike[str] = DEFAULT_PATH) -> Settings:
    """Read the settings file; a missing file means the AI-Perimeter is off."""
    p = Path(path)
    try:
        with p.open("rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return Settings(enabled=False, provider=None)
    if len(data) > MAX_FILE_BYTES:
        raise ConfigError(f"{p} is too large")
    try:
        raw = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{p} is not valid YAML") from exc
    return parse_settings(raw)
