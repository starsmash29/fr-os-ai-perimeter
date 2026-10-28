"""deploy/modal/README.md: Muse Glimmer as a Modal Dedicated Endpoint.

Nothing from this repository runs on Modal; what the guide must get right
is the client side. Its settings go through the service's own parser: a
Modal URL is HTTPS on a public host, so it is a cloud provider that needs
``allow_cloud`` and a key file (security-lessons G11).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ai_perimeter.client import PRESETS
from ai_perimeter.settings import parse_settings

GUIDE = Path(__file__).resolve().parent.parent / "deploy" / "modal" / "README.md"


def _settings_block() -> dict:
    yaml = pytest.importorskip("yaml")
    block = re.search(r"```yaml\n(.*?)```", GUIDE.read_text(), re.S).group(1)
    return yaml.safe_load(block.replace("<workspace>", "example-workspace"))


def test_the_guides_settings_are_a_cloud_provider_with_a_key_file():
    provider = parse_settings(_settings_block()).provider
    assert provider.cloud is True
    assert provider.model == "muse-glimmer"
    assert provider.base_url == (
        "https://example-workspace--ep-muse-glimmer-server.us-west.modal.direct/v1")
    assert provider.api_key_file == Path("~/.config/fr_os/modal_glimmer_api_key").expanduser()


def test_without_cloud_opt_in_the_guides_settings_are_refused():
    with pytest.raises(ValueError):
        parse_settings({**_settings_block(), "allow_cloud": False})


def test_nothing_points_at_modal_unless_configured():
    assert "modal" not in PRESETS


def test_the_guide_keeps_the_token_out_of_chat_history_and_the_repo():
    text = GUIDE.read_text()
    assert "read -rs" in text and "umask 077" in text
    # No token-shaped string (Modal's token ids and secrets start ak-/as-).
    assert not re.search(r"\b(ak|as)-[A-Za-z0-9]{10,}", text)
