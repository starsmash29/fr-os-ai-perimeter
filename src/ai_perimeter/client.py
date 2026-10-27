"""One small client for every model provider the AI-Perimeter can use.

Ollama / llama.cpp (local), Baseten (Muse Spark Open) and the Meta Model API
(Muse Spark) all speak the OpenAI Chat Completions format
(``POST <base_url>/chat/completions`` with a bearer token), so one client
covers all three. It is written with the standard library only: the router
gets no new dependency.

Why it is this strict:

- **Local by default (security-lessons G11).** A provider whose host is not a
  loopback or private address is a cloud call. It needs ``allow_cloud`` and
  HTTPS; plain HTTP is only accepted to a local address.
- **The key never leaves its file except in the Authorization header.** It is
  read from a file only its owner can read (``~/.config/fr_os/``), never from
  the config; redirects are refused so the header can't follow one to another
  host; and error messages are scrubbed of it.
- **The model's answer is untrusted input.** The response is size-capped and
  parsed defensively; what it *says* is checked later by the validator, the
  rule linter and the deny list, never here.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Answers bigger than this are refused, not truncated: a truncated JSON
#: proposal is worse than none.
MAX_RESPONSE_BYTES = 1024 * 1024
#: The prompt (system + user + evidence) the client will send at most.
MAX_REQUEST_BYTES = 256 * 1024
MAX_KEY_BYTES = 4096
DEFAULT_TIMEOUT = 120.0
#: The longest the service waits for one answer (the eval may allow more).
MAX_TIMEOUT = 600.0

_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_KEY_RE = re.compile(r"[\x21-\x7e]{8,}\Z")
_ROLES = frozenset({"system", "user", "assistant"})
_THINK_RE = re.compile(r"\A\s*<think>(.*?)</think>\s*", re.DOTALL)

_CONFIG_DIR = Path("~/.config/fr_os")

#: Known providers. ``local`` has no default model: the Ollama tag is
#: whatever the admin pulled.
PRESETS: dict[str, dict[str, Any]] = {
    "local": {
        "base_url": "http://127.0.0.1:11434/v1",
        "model": None,
        "api_key_file": None,
    },
    "baseten": {
        "base_url": "https://inference.baseten.co/v1",
        # The hackathon key only works with this exact model id.
        "model": "meta-models/muse-spark-open-1026",
        "api_key_file": _CONFIG_DIR / "baseten_api_key",
    },
    "meta": {
        "base_url": "https://api.meta.ai/v1",
        "model": "muse-spark-1.3",
        "api_key_file": _CONFIG_DIR / "meta_api_key",
    },
}


class ConfigError(ValueError):
    """The provider settings are not acceptable."""


class ProviderError(RuntimeError):
    """The provider could not be reached or gave an unusable answer."""


class Unreachable(ProviderError):
    """Nothing answered at the provider's address (refused, no route, no
    such host): unlike a timeout, nothing is running there to wait for."""


def _is_local_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # A name could resolve anywhere; only literal addresses count as
        # local, so a DNS answer can't turn a cloud call into a "local" one.
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


def _check_base_url(base_url: str, allow_cloud: bool) -> tuple[str, bool]:
    """Return the normalised URL and whether it is a cloud provider."""
    if not isinstance(base_url, str) or not base_url:
        raise ConfigError("base_url must be a URL")
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        raise ConfigError("base_url must be http:// or https://")
    if parts.username is not None or parts.password is not None:
        raise ConfigError("base_url must not carry credentials; use api_key_file")
    if parts.query or parts.fragment:
        raise ConfigError("base_url must not have a query or fragment")
    host = parts.hostname
    if not host:
        raise ConfigError("base_url has no host")
    try:
        parts.port
    except ValueError as exc:
        raise ConfigError("base_url has an invalid port") from exc
    cloud = not _is_local_host(host)
    if cloud and not allow_cloud:
        raise ConfigError(
            f"{host} is not a local address; a cloud provider must be enabled "
            "with allow_cloud (it is off by default, security-lessons G11)")
    if cloud and parts.scheme != "https":
        raise ConfigError("a cloud provider must use https://")
    return base_url.rstrip("/"), cloud


def read_api_key(path: str | os.PathLike[str]) -> str:
    """Read an API key from a file that only its owner can read."""
    p = Path(path).expanduser()
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError as exc:
        raise ConfigError(f"API key file {p} does not exist") from exc
    except OSError as exc:
        raise ConfigError(f"API key file {p} can't be opened ({exc.strerror})") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"API key file {p} is not a regular file")
        if st.st_mode & 0o077:
            raise ConfigError(
                f"API key file {p} is readable by others; run: chmod 600 {p}")
        if st.st_uid != os.geteuid():
            raise ConfigError(f"API key file {p} is not owned by this user")
        data = os.read(fd, MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_KEY_BYTES:
        raise ConfigError(f"API key file {p} is too large to be a key")
    try:
        key = data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ConfigError(f"API key file {p} is not a plain-text key") from exc
    if not _KEY_RE.match(key):
        raise ConfigError(f"API key file {p} does not hold a single key")
    return key


@dataclass(frozen=True)
class ProviderSettings:
    """Where the client sends requests. Built with :meth:`build`."""

    name: str
    base_url: str
    model: str
    cloud: bool
    api_key_file: Path | None = None
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def build(cls, name: str, *, base_url: str | None = None,
              model: str | None = None,
              api_key_file: str | os.PathLike[str] | None = None,
              allow_cloud: bool = False,
              timeout: float = DEFAULT_TIMEOUT,
              max_timeout: float = MAX_TIMEOUT) -> "ProviderSettings":
        """Validate settings, filling unset values from :data:`PRESETS`.

        ``max_timeout`` is for the evaluation only: a local model on a
        consumer PC may need longer than the service ever waits for an
        admin's proposal."""
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ConfigError("provider name must be a short lowercase word")
        preset = PRESETS.get(name, {})
        base_url = base_url if base_url is not None else preset.get("base_url")
        if base_url is None:
            raise ConfigError(f"provider {name!r} needs a base_url")
        url, cloud = _check_base_url(base_url, allow_cloud)
        model = model if model is not None else preset.get("model")
        if not isinstance(model, str) or not _MODEL_RE.match(model):
            raise ConfigError(f"provider {name!r} needs a valid model id")
        key_file = (api_key_file if api_key_file is not None
                    else preset.get("api_key_file"))
        if cloud and key_file is None:
            raise ConfigError(f"cloud provider {name!r} needs an api_key_file")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
                or not 1 <= timeout <= max_timeout:
            raise ConfigError(f"timeout must be 1-{max_timeout:g} seconds")
        return cls(name=name, base_url=url, model=model, cloud=cloud,
                   api_key_file=Path(key_file).expanduser() if key_file else None,
                   timeout=float(timeout))


@dataclass(frozen=True)
class ChatResult:
    text: str
    reasoning: str = ""
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # The Authorization header must not follow a redirect elsewhere.
        raise ProviderError(f"the provider answered with a redirect (HTTP {code})")


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [p.get("text") for p in content
                 if isinstance(p, dict) and p.get("type") in (None, "text")
                 and isinstance(p.get("text"), str)]
        return "".join(parts)
    return ""


def _check_messages(messages: list[dict[str, str]]) -> None:
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty list")
    for m in messages:
        if not isinstance(m, dict) or set(m) != {"role", "content"}:
            raise ValueError("each message has exactly a role and a content")
        if m["role"] not in _ROLES or not isinstance(m["content"], str):
            raise ValueError("message role must be system/user/assistant, content a string")


class ChatClient:
    """Send chat requests to one provider."""

    def __init__(self, settings: ProviderSettings):
        self.settings = settings
        # Read once, so a broken key file fails at start, not mid-request.
        self._key = (read_api_key(settings.api_key_file)
                     if settings.api_key_file else None)
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
        if not settings.cloud:
            # A local model must not be reached through a proxy (and the
            # prompt must not leave the LAN through one).
            handlers.append(urllib.request.ProxyHandler({}))
        else:
            handlers.append(urllib.request.HTTPSHandler(
                context=ssl.create_default_context()))
        self._opener = urllib.request.build_opener(*handlers)

    def _scrub(self, text: str) -> str:
        if self._key:
            text = text.replace(self._key, "[redacted]")
        return text[:300]

    def chat(self, messages: list[dict[str, str]], *, max_tokens: int = 1024,
             temperature: float | None = None,
             json_mode: bool = False) -> ChatResult:
        _check_messages(messages)
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) \
                or not 1 <= max_tokens <= 32768:
            raise ValueError("max_tokens must be 1-32768")
        body: dict[str, Any] = {
            "model": self.settings.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if temperature is not None:
            body["temperature"] = float(temperature)
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        data = json.dumps(body).encode("utf-8")
        if len(data) > MAX_REQUEST_BYTES:
            raise ValueError("the request is too large")
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        req = urllib.request.Request(
            self.settings.base_url + "/chat/completions",
            data=data, headers=headers, method="POST")
        raw = self._send(req)
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError(
                f"{self.settings.name}: the answer is not JSON") from exc
        return self._parse(payload)

    def _send(self, req: urllib.request.Request) -> bytes:
        name = self.settings.name
        try:
            with self._opener.open(req, timeout=self.settings.timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                err = json.loads(exc.read(4096) or b"{}")
                if isinstance(err, dict):
                    e = err.get("error", err)
                    detail = e.get("message", "") if isinstance(e, dict) else str(e)
            except (ValueError, OSError):
                pass
            msg = f"{name}: HTTP {exc.code}"
            if detail:
                msg += f": {self._scrub(str(detail))}"
            raise ProviderError(msg) from None
        except (TimeoutError, socket.timeout):
            raise ProviderError(f"{name}: no answer within "
                                f"{self.settings.timeout:g} s") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise ProviderError(f"{name}: no answer within "
                                    f"{self.settings.timeout:g} s") from None
            raise Unreachable(
                f"{name}: can't reach the provider "
                f"({self._scrub(str(exc.reason))})") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProviderError(f"{name}: the answer is too large")
        return raw

    def _parse(self, payload: Any) -> ChatResult:
        name = self.settings.name
        try:
            message = payload["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise ProviderError(f"{name}: the answer has no message") from None
        if not isinstance(message, dict):
            raise ProviderError(f"{name}: the answer has no message")
        text = _content_text(message.get("content"))
        reasoning = message.get("reasoning_content") or message.get("reasoning") or ""
        if not isinstance(reasoning, str):
            reasoning = ""
        # Reasoning models served without a separate field put it in front.
        m = _THINK_RE.match(text)
        if m:
            reasoning = reasoning or m.group(1).strip()
            text = text[m.end():]
        usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
        usage = {k: v for k, v in usage.items()
                 if isinstance(v, int) and not isinstance(v, bool)}
        model = payload.get("model") if isinstance(payload.get("model"), str) else ""
        return ChatResult(text=text.strip(), reasoning=reasoning.strip(),
                          model=model, usage=usage)
