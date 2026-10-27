"""A4 on the AI-Perimeter screen: the flagged devices, "Explain", and the
suggested change handed to the request box. FR_OS's real webUI, the real
fr-ai-assist socket and a real HTTP "model", as in test_webui.py; the
sensor files are test_incident.py's.
"""

from __future__ import annotations

import html
import json

import pytest

from test_client import _completion
from test_incident import INJECTION, TABLET_IP, TABLET_MAC, answer, sources, tool  # noqa: F401
from test_orchestrator import KIDS_NIGHT
from test_webui import env, login, post, proposal_id, provider  # noqa: F401 (fixtures)


@pytest.fixture
def screen(env, sources):  # noqa: F811
    env["app"].state.ai_perimeter_sources = sources
    return env


def test_the_screen_lists_the_tablet(screen):
    page = login(screen).get("/ai-perimeter")
    assert page.status_code == 200
    assert "What did the router see?" in page.text
    assert "kids-tablet" in page.text and TABLET_IP in page.text
    assert "ChatGPT / OpenAI" in page.text and "ai service" in page.text
    assert f'name="ip" value="{TABLET_IP}"' in page.text


def test_the_config_names_the_device_when_the_inventory_does_not(screen, sources):
    sources.devices.write_text(json.dumps({"devices": []}))
    page = login(screen).get("/ai-perimeter")
    assert "kids-tablet" in page.text  # dhcp.lan.reservations in the demo config


def test_explain_then_propose_the_suggested_change(screen):
    client = login(screen)
    screen["provider"].queue = [tool("ai_usage"), answer()]
    page = post(client, "/ai-perimeter/explain", {"ip": TABLET_IP})
    assert page.status_code == 200
    text = html.unescape(page.text)
    assert "Kids&#39; tablet used ChatGPT late at night" in page.text
    assert f"From 23:00 kids-tablet ({TABLET_IP}) looked up ChatGPT" in text
    assert "NIS2 Art. 21(2)(b): incident handling" in text
    assert "NIST SP 800-53 SI-4" in text
    # The suggestion lands in the request box, with the real name.
    assert f"Cut kids-tablet ({TABLET_IP}) off the internet from 22:00 to 06:00</textarea>" in text
    # The model never saw who the device is.
    sent = json.dumps([r["json"] for r in screen["provider"].requests])
    for secret in (TABLET_IP, TABLET_MAC, "kids-tablet"):
        assert secret not in sent

    # The admin proposes it: the ordinary path, checks and all.
    screen["provider"].body = _completion(json.dumps(KIDS_NIGHT))
    proposed = post(client, "/ai-perimeter/propose",
                    {"intent": "Cut kids-tablet off the internet from 22:00 to 06:00"})
    assert "kids-tablet-night" in proposed.text and proposal_id(proposed.text)


def test_a_refused_explanation_says_why(screen):
    screen["provider"].queue = [answer(evidence=["ai-9"])]
    page = post(login(screen), "/ai-perimeter/explain", {"ip": TABLET_IP})
    assert "No explanation" in page.text and "does not exist: ai-9" in page.text
    assert "</textarea>" in page.text and "Cut kids-tablet" not in page.text


def test_the_explanation_is_escaped(screen):
    screen["provider"].queue = [answer(title="<script>alert(1)</script>",
                                       summary=f"<img src=x> {INJECTION}")]
    page = post(login(screen), "/ai-perimeter/explain", {"ip": TABLET_IP})
    assert "<script>alert(1)" not in page.text and "&lt;script&gt;" in page.text
    assert "<img src=x>" not in page.text


def test_an_unknown_device_is_not_sent_to_the_model(screen):
    page = post(login(screen), "/ai-perimeter/explain", {"ip": "192.168.10.99"})
    assert "No explanation: no sensor reported this device" in page.text
    assert screen["provider"].requests == []


def test_a_viewer_sees_the_list_but_cant_explain(screen):
    viewer = login(screen, "guest", "viewerpass-01")
    page = viewer.get("/ai-perimeter")
    assert "kids-tablet" in page.text and 'action="/ai-perimeter/explain"' not in page.text
    assert post(viewer, "/ai-perimeter/explain", {"ip": TABLET_IP}).status_code == 403
    assert post(login(screen), "/ai-perimeter/explain", {"ip": TABLET_IP}, csrf=False).status_code == 403
    assert screen["provider"].requests == []
