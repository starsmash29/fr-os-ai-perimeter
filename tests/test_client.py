"""The provider client against a real local HTTP server (no mocks).

The server speaks the Chat Completions format the way Ollama, Baseten and the
Meta Model API do; each test sets what it answers and checks what it got.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ai_perimeter import cli
from ai_perimeter.client import (
    MAX_RESPONSE_BYTES,
    ChatClient,
    ConfigError,
    ProviderError,
    ProviderSettings,
    read_api_key,
)

KEY = "sk-test-0123456789abcdef"


def _completion(content, **message):
    return {
        "model": "muse-test",
        "choices": [{"index": 0, "message": {"role": "assistant",
                                             "content": content, **message}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7},
    }


class FakeProvider:
    """A Chat Completions endpoint on 127.0.0.1 that records requests."""

    def __init__(self):
        self.requests: list[dict] = []
        self.status = 200
        self.body: bytes | dict = _completion("hello")
        self.headers: dict[str, str] = {}
        self.delay = 0.0
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                provider.requests.append({
                    "path": self.path,
                    "headers": dict(self.headers),
                    "json": json.loads(self.rfile.read(length) or b"null"),
                })
                if provider.delay:
                    time.sleep(provider.delay)
                body = provider.body
                if isinstance(body, dict):
                    body = json.dumps(body).encode()
                try:
                    self.send_response(provider.status)
                    for k, v in provider.headers.items():
                        self.send_header(k, v)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def provider():
    p = FakeProvider()
    yield p
    p.close()


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "api_key"
    path.write_text(KEY + "\n")
    path.chmod(0o600)
    return path


def _client(provider, **kw):
    kw.setdefault("model", "muse-glimmer")
    return ChatClient(ProviderSettings.build("local", base_url=provider.url, **kw))


# --- requests and answers ---------------------------------------------------

def test_a_chat_sends_the_model_and_messages_and_returns_the_answer(provider):
    result = _client(provider).chat(
        [{"role": "system", "content": "be brief"},
         {"role": "user", "content": "hi"}], max_tokens=64)
    assert result.text == "hello"
    assert result.model == "muse-test"
    assert result.usage == {"prompt_tokens": 5, "completion_tokens": 7}
    [req] = provider.requests
    assert req["path"] == "/v1/chat/completions"
    assert req["json"]["model"] == "muse-glimmer"
    assert req["json"]["max_tokens"] == 64
    assert req["json"]["stream"] is False
    assert req["json"]["messages"][1] == {"role": "user", "content": "hi"}
    # No key configured: no Authorization header at all.
    assert "Authorization" not in req["headers"]


def test_the_key_goes_only_in_the_authorization_header(provider, key_file):
    _client(provider, api_key_file=key_file).chat([{"role": "user", "content": "x"}])
    [req] = provider.requests
    assert req["headers"]["Authorization"] == f"Bearer {KEY}"
    assert KEY not in json.dumps(req["json"])


def test_json_mode_asks_for_a_json_object(provider):
    _client(provider).chat([{"role": "user", "content": "x"}], json_mode=True)
    assert provider.requests[0]["json"]["response_format"] == {"type": "json_object"}


def test_a_separate_reasoning_field_is_kept_apart_from_the_answer(provider):
    provider.body = _completion("the answer", reasoning_content="I thought")
    result = _client(provider).chat([{"role": "user", "content": "x"}])
    assert (result.text, result.reasoning) == ("the answer", "I thought")


def test_inline_think_tags_are_split_off(provider):
    provider.body = _completion("<think>\nstep 1\n</think>\n\nthe answer")
    result = _client(provider).chat([{"role": "user", "content": "x"}])
    assert (result.text, result.reasoning) == ("the answer", "step 1")


def test_content_given_as_parts_is_joined(provider):
    provider.body = _completion([{"type": "text", "text": "a"},
                                 {"type": "image_url", "image_url": {}},
                                 {"type": "text", "text": "b"}])
    assert _client(provider).chat([{"role": "user", "content": "x"}]).text == "ab"


# --- failures ---------------------------------------------------------------

def test_an_http_error_is_reported_without_the_key(provider, key_file):
    # A provider that echoes the request's credentials in its error.
    provider.status = 401
    provider.body = {"error": {"message": f"invalid key {KEY}"}}
    with pytest.raises(ProviderError) as exc:
        _client(provider, api_key_file=key_file).chat([{"role": "user", "content": "x"}])
    assert "HTTP 401" in str(exc.value)
    assert KEY not in str(exc.value)
    assert "[redacted]" in str(exc.value)


def test_a_redirect_is_not_followed(provider, key_file):
    other = FakeProvider()
    try:
        provider.status = 307
        provider.headers = {"Location": other.url + "/chat/completions"}
        provider.body = b""
        with pytest.raises(ProviderError, match="redirect"):
            _client(provider, api_key_file=key_file).chat(
                [{"role": "user", "content": "x"}])
        assert other.requests == []
    finally:
        other.close()


def test_an_oversized_answer_is_refused(provider):
    provider.body = b"x" * (MAX_RESPONSE_BYTES + 10)
    with pytest.raises(ProviderError, match="too large"):
        _client(provider).chat([{"role": "user", "content": "x"}])


def test_an_answer_that_is_not_json_is_refused(provider):
    provider.body = b"<html>gateway error</html>"
    with pytest.raises(ProviderError, match="not JSON"):
        _client(provider).chat([{"role": "user", "content": "x"}])


def test_an_answer_without_a_message_is_refused(provider):
    provider.body = {"choices": []}
    with pytest.raises(ProviderError, match="no message"):
        _client(provider).chat([{"role": "user", "content": "x"}])


def test_a_slow_provider_times_out(provider):
    provider.delay = 3
    with pytest.raises(ProviderError, match="no answer within"):
        _client(provider, timeout=1).chat([{"role": "user", "content": "x"}])


def test_an_unreachable_provider_is_reported(provider):
    url = provider.url
    provider.close()
    with pytest.raises(ProviderError, match="can't reach"):
        ChatClient(ProviderSettings.build("local", base_url=url, model="m")).chat(
            [{"role": "user", "content": "x"}])
    provider.close = lambda: None


def test_a_local_provider_is_never_reached_through_a_proxy(provider, monkeypatch):
    # A proxy that does not exist: using it would fail the request.
    for var in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    for var in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(var, raising=False)
    assert _client(provider).chat([{"role": "user", "content": "x"}]).text == "hello"


@pytest.mark.parametrize("messages", [
    [],
    [{"role": "tool", "content": "x"}],
    [{"role": "user", "content": 5}],
    [{"role": "user", "content": "x", "name": "extra"}],
])
def test_malformed_messages_are_refused_before_sending(provider, messages):
    with pytest.raises(ValueError):
        _client(provider).chat(messages)
    assert provider.requests == []


# --- settings (security-lessons G11) ----------------------------------------

def test_presets_fill_in_the_known_providers(key_file):
    s = ProviderSettings.build("baseten", allow_cloud=True, api_key_file=key_file)
    assert s.base_url == "https://inference.baseten.co/v1"
    assert s.model == "meta-models/muse-spark-open-1026"
    assert s.cloud
    m = ProviderSettings.build("meta", allow_cloud=True, api_key_file=key_file)
    assert (m.base_url, m.model) == ("https://api.meta.ai/v1", "muse-spark-1.3")


def test_a_cloud_provider_is_off_unless_allowed():
    with pytest.raises(ConfigError, match="allow_cloud"):
        ProviderSettings.build("baseten")
    with pytest.raises(ConfigError, match="allow_cloud"):
        ProviderSettings.build("custom", base_url="https://llm.example.com/v1", model="m")


def test_a_cloud_provider_needs_https_and_a_key(key_file):
    with pytest.raises(ConfigError, match="https"):
        ProviderSettings.build("custom", base_url="http://llm.example.com/v1",
                               model="m", allow_cloud=True, api_key_file=key_file)
    with pytest.raises(ConfigError, match="api_key_file"):
        ProviderSettings.build("custom", base_url="https://llm.example.com/v1",
                               model="m", allow_cloud=True)


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434/v1",
                                 "http://192.168.1.20:8080/v1",
                                 "http://[fd00::5]:11434/v1",
                                 "http://localhost:11434/v1"])
def test_local_and_lan_addresses_need_no_opt_in(url):
    assert not ProviderSettings.build("local", base_url=url, model="m").cloud


@pytest.mark.parametrize("url", [
    "ftp://127.0.0.1/v1",
    "http://user:pass@127.0.0.1/v1",
    "http://127.0.0.1/v1?x=1",
    "http://127.0.0.1:99999/v1",
    "http:///v1",
])
def test_bad_base_urls_are_refused(url):
    with pytest.raises(ConfigError):
        ProviderSettings.build("local", base_url=url, model="m")


@pytest.mark.parametrize("model", [None, "", "muse\nglimmer", "muse glimmer", "-x", "m" * 200])
def test_bad_model_ids_are_refused(model):
    with pytest.raises(ConfigError, match="model"):
        ProviderSettings.build("local", base_url="http://127.0.0.1/v1", model=model)


@pytest.mark.parametrize("name", ["", "Local", "a b", "x" * 40, "ok\n"])
def test_bad_provider_names_are_refused(name):
    with pytest.raises(ConfigError):
        ProviderSettings.build(name, base_url="http://127.0.0.1/v1", model="m")


# --- the key file ------------------------------------------------------------

def test_the_key_file_is_read_and_trimmed(key_file):
    assert read_api_key(key_file) == KEY


def test_a_key_file_others_can_read_is_refused(key_file):
    key_file.chmod(0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        read_api_key(key_file)


def test_a_symlinked_key_file_is_refused(key_file, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(key_file)
    with pytest.raises(ConfigError):
        read_api_key(link)


@pytest.mark.parametrize("content", ["", "short", "two words-here", "a" * 5000])
def test_a_key_file_without_one_key_is_refused(tmp_path, content):
    path = tmp_path / "k"
    path.write_text(content)
    path.chmod(0o600)
    with pytest.raises(ConfigError):
        read_api_key(path)


def test_a_missing_key_file_fails_when_the_client_starts(tmp_path, provider):
    settings = ProviderSettings.build("local", base_url=provider.url, model="m",
                                      api_key_file=tmp_path / "nope")
    with pytest.raises(ConfigError, match="does not exist"):
        ChatClient(settings)


# --- the CLI ------------------------------------------------------------------

def test_the_cli_prints_the_answer(provider, capsys):
    provider.body = _completion("<think>hmm</think>pong")
    rc = cli.main(["--provider", "local", "--base-url", provider.url,
                   "--model", "muse-glimmer", "--show-reasoning", "ping"])
    out, err = capsys.readouterr()
    assert rc == 0
    assert "hmm" in out and out.rstrip().endswith("pong")
    assert "7 tokens" in err


def test_the_cli_refuses_a_cloud_provider_without_the_flag(capsys):
    assert cli.main(["--provider", "meta", "hi"]) == 1
    assert "allow_cloud" in capsys.readouterr().err
