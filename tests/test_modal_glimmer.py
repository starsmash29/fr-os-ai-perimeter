"""deploy/modal/glimmer.py: Glimmer on a Modal GPU, behind an API key.

Modal itself is not installed for the tests (and the app must not reach
the internet from CI), so a small stand-in records what the script asks
Modal for. The client side is real: the README's settings go through the
service's own settings parser.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import types
from pathlib import Path

import pytest

from ai_perimeter.client import PRESETS
from ai_perimeter.settings import parse_settings

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "deploy" / "modal" / "glimmer.py"
GUIDE = ROOT / "deploy" / "modal" / "README.md"


class _Recorder:
    """Stands in for the ``modal`` module: every decorator and factory
    records its arguments and hands the function back unchanged."""

    def __init__(self) -> None:
        self.functions: dict[str, dict] = {}
        self.secrets: list[str] = []
        self.web: dict = {}
        self.concurrent: dict = {}

    def module(self) -> types.ModuleType:
        rec = self
        m = types.ModuleType("modal")

        class App:
            def __init__(self, name):
                self.name = name

            def function(self, **kw):
                def wrap(fn):
                    rec.functions[fn.__name__] = kw
                    return fn
                return wrap

        class Volume:
            @staticmethod
            def from_name(name, create_if_missing=False):
                vol = types.SimpleNamespace(name=name, commit=lambda: None)
                return vol

        class Image:
            @staticmethod
            def from_registry(ref, add_python=None):
                img = types.SimpleNamespace(ref=ref, add_python=add_python)
                img.entrypoint = lambda args: img
                return img

        class Secret:
            @staticmethod
            def from_name(name):
                rec.secrets.append(name)
                return name

        def concurrent(**kw):
            rec.concurrent = kw
            return lambda fn: fn

        def web_server(**kw):
            rec.web = kw
            return lambda fn: fn

        m.App, m.Volume, m.Image, m.Secret = App, Volume, Image, Secret
        m.concurrent, m.web_server = concurrent, web_server
        return m


@pytest.fixture
def glimmer(monkeypatch):
    rec = _Recorder()
    monkeypatch.setitem(sys.modules, "modal", rec.module())
    spec = importlib.util.spec_from_file_location("modal_glimmer", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, rec


def test_it_asks_modal_for_one_l40s_that_scales_to_zero(glimmer):
    module, rec = glimmer
    serve = rec.functions["serve"]
    assert serve["gpu"] == "L40S"
    assert serve["scaledown_window"] == 300
    assert serve["secrets"] == ["fr-os-glimmer-key"]
    assert rec.web == {"port": 8080, "startup_timeout": 900}
    # The download needs no GPU and no key.
    assert "gpu" not in rec.functions["download"]
    assert "secrets" not in rec.functions["download"]


def test_the_inputs_are_pinned(glimmer):
    module, _ = glimmer
    assert re.fullmatch(r"ghcr\.io/ggml-org/llama\.cpp@sha256:[0-9a-f]{64}", module.LLAMA_IMAGE)
    assert re.fullmatch(r"[0-9a-f]{40}", module.HF_REVISION)
    assert re.fullmatch(r"[0-9a-f]{64}", module.GGUF_SHA256)
    assert module.gguf_url() == (
        "https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF/resolve/"
        f"{module.HF_REVISION}/Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf")


def test_the_key_is_never_on_the_command_line(glimmer):
    module, _ = glimmer
    argv = module.server_command("/weights/m.gguf")
    assert argv[0] == "/app/llama-server"
    assert not any("key" in a.lower() for a in argv)
    assert argv[argv.index("--alias") + 1] == "muse-glimmer"
    assert argv[argv.index("--reasoning-budget") + 1] == "0"  # as evaluated
    assert "--no-webui" in argv


def test_no_key_no_server(glimmer, monkeypatch):
    module, _ = glimmer
    started = []
    monkeypatch.setattr(module.subprocess, "Popen", lambda argv: started.append(argv))
    monkeypatch.delenv("LLAMA_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="LLAMA_API_KEY"):
        module.serve()
    monkeypatch.setenv("LLAMA_API_KEY", "")
    with pytest.raises(RuntimeError):
        module.serve()
    assert started == []
    monkeypatch.setenv("LLAMA_API_KEY", "not-a-real-key")
    module.serve()
    assert started == [module.server_command(
        "/weights/Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf")]


def test_the_guides_settings_are_a_cloud_provider_with_a_key_file():
    """The YAML in deploy/modal/README.md, through the service's parser:
    an HTTPS Modal URL is cloud, so it needs allow_cloud and a key file."""
    yaml = pytest.importorskip("yaml")
    block = re.search(r"```yaml\n(.*?)```", GUIDE.read_text(), re.S).group(1)
    raw = yaml.safe_load(block.replace("<workspace>", "kolos-demo"))
    provider = parse_settings(raw).provider
    assert provider.cloud is True
    assert provider.model == "muse-glimmer"
    assert provider.base_url == "https://kolos-demo--fr-os-glimmer-serve.modal.run/v1"
    assert provider.api_key_file == Path("~/.config/fr_os/modal_glimmer_api_key").expanduser()
    with pytest.raises(ValueError):
        parse_settings({**raw, "allow_cloud": False})
    assert "modal" not in PRESETS  # nothing points at Modal unless configured


def test_no_secret_is_checked_in():
    for path in (SCRIPT, GUIDE):
        text = path.read_text()
        assert not re.search(r"LLAMA_API_KEY\s*=\s*['\"]?[A-Za-z0-9_-]{16,}", text)
        # Modal's token id and secret prefixes.
        assert not re.search(r"\b(ak|as)-[A-Za-z0-9]{10,}", text)
