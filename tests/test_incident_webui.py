"""A4 on the AI-Perimeter screen: the flagged devices, "Explain", and the
suggested change handed to the request box. FR_OS's real webUI, the real
fr-ai-assist socket and a real HTTP "model", as in test_webui.py; the
sensor files are test_incident.py's.
"""

from __future__ import annotations

import html
import json
import subprocess
import sys
from pathlib import Path

import pytest

from ai_perimeter.incident.evidence import Sources

from test_client import _completion
from test_incident import NOW, INJECTION, TABLET_IP, TABLET_MAC, answer, sources, tool  # noqa: F401
from test_orchestrator import KIDS_NIGHT
from test_webui import env, login, post, proposal_id, provider  # noqa: F401 (fixtures)


@pytest.fixture
def screen(env, sources):  # noqa: F811
    env["app"].state.ai_perimeter_sources = sources
    env["app"].state.ai_perimeter_clock = lambda: NOW
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
    # The suggestion lands in the request box with the real name: proposing
    # it goes to the propose model, which must know which device it means.
    box = text.split("<textarea")[1].split("</textarea>")[0].split(">", 1)[1]
    assert box == f"Cut kids-tablet ({TABLET_IP}) off the internet from 22:00 to 06:00"
    # The model never saw who the device is.
    sent = json.dumps([r["json"] for r in screen["provider"].requests])
    for secret in (TABLET_IP, TABLET_MAC, "kids-tablet"):
        assert secret not in sent

    # The admin proposes it: the ordinary path, checks and all.
    # The box's own text, as rendered (review2 F2, corrected): a pseudonym
    # here would reach the propose model naming no device it can find.
    screen["provider"].requests.clear()
    screen["provider"].body = _completion(json.dumps(KIDS_NIGHT))
    proposed = post(client, "/ai-perimeter/propose", {"intent": box})
    assert "kids-tablet-night" in proposed.text and proposal_id(proposed.text)
    asked = json.dumps([r["json"] for r in screen["provider"].requests])
    assert "kids-tablet" in asked and "device-1" not in asked


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


# --- the demo scenario (demo/shadow_ai, A4-3) -------------------------------------------------

DEMO = Path(__file__).resolve().parent.parent / "demo" / "shadow_ai" / "make_sensor_files.py"
DEMO_NOW = 1793230800.0  # the script's default: Wednesday 2026-10-28 23:40 UTC


def test_the_demo_scenario_end_to_end(env, tmp_path):  # noqa: F811
    """The video's path on the demo sensor files: the tablet is listed, the
    model reads the evidence and explains it, the card carries the NIS2 and
    NIST references, and the suggestion lands in the request box."""
    out = tmp_path / "sensors"
    subprocess.run([sys.executable, str(DEMO), "--out", str(out), "--now", str(DEMO_NOW)],
                   check=True, capture_output=True)
    env["app"].state.ai_perimeter_sources = Sources(
        ids=out / "ai_ids_state.json", appid=out / "appid_usage.json",
        tls=out / "tls_fingerprints.json", devices=out / "iot_inventory.json",
        dns=out / "queries.log", sni=out / "sni_events.jsonl")
    env["app"].state.ai_perimeter_clock = lambda: DEMO_NOW
    client = login(env)
    page = client.get("/ai-perimeter")
    assert "kids-tablet" in page.text and "ChatGPT / OpenAI" in page.text
    assert "living-room-tv" not in page.text  # streaming and one odd lookup: not flagged

    env["provider"].queue = [tool("ai_usage"), tool("tls_fingerprints"), tool("ids_events"),
                             answer(evidence=["ai-1", "tls-1", "ids-1"])]
    page = post(client, "/ai-perimeter/explain", {"ip": TABLET_IP})
    text = html.unescape(page.text)
    assert "NIS2 Art. 23: reporting obligations" in text
    assert "<code>tls-1</code>" in page.text and "chatgpt.com" in text
    assert f"Cut kids-tablet ({TABLET_IP}) off the internet" in text
    sent = json.dumps([r["json"] for r in env["provider"].requests])
    assert TABLET_IP not in sent and TABLET_MAC not in sent and "kids-tablet" not in sent


# --- the office scenario (fictional HSML, fictional Azarus Group) ------------------------------

OFFICE_NOW = 1793004000.0  # the script's office default: Monday 2026-10-26 08:40 UTC
LAPTOP_IP, LAPTOP_MAC = "192.168.10.40", "02:00:00:00:10:04"
NAS_IP, NAS_MAC = "192.168.10.30", "02:00:00:00:10:03"


def _office(env, tmp_path):  # noqa: F811
    out = tmp_path / "office"
    subprocess.run([sys.executable, str(DEMO), "--out", str(out), "--scenario", "office"],
                   check=True, capture_output=True)
    env["app"].state.ai_perimeter_sources = Sources(
        ids=out / "ai_ids_state.json", appid=out / "appid_usage.json",
        tls=out / "tls_fingerprints.json", devices=out / "iot_inventory.json",
        dns=out / "queries.log", sni=out / "sni_events.jsonl")
    env["app"].state.ai_perimeter_clock = lambda: OFFICE_NOW
    return login(env)


def test_the_office_scenario_end_to_end(env, tmp_path):  # noqa: F811
    """The SMB scene of the video: the engineer's laptop and the design file
    server are listed, the reception PC is not. A model that underrates the
    blocklisted loader is overruled -- the severity is high because the
    evidence alone says so -- and the card carries the NIS2 24-hour note.
    The threat feed's label reaches the model as evidence (it may cite it);
    who the device is does not."""
    client = _office(env, tmp_path)
    page = client.get("/ai-perimeter")
    assert "design-laptop" in page.text and NAS_IP in page.text
    assert "reception-pc" not in page.text  # ordinary lookups: not flagged

    env["provider"].queue = [
        tool("tls_fingerprints"), tool("ids_events"),
        answer(title="Laptop ran a loader the threat feed knows", severity="medium",
               summary="device-1 connected with a TLS client the feed lists as an "
                       "Azarus Group loader and its threat-domain lookups were blocked.",
               evidence=["tls-1", "ids-1"],
               suggested_intent="Cut device-1 off the internet")]
    page = post(client, "/ai-perimeter/explain", {"ip": LAPTOP_IP})
    text = html.unescape(page.text)
    assert ">high</span>" in text
    assert "The severity was raised to what the evidence alone shows." in text
    assert "early warning to the CSIRT within 24 hours" in text
    assert "<code>tls-1</code>" in page.text and "update-cdn-checker.example" in text
    assert f"Cut design-laptop ({LAPTOP_IP}) off the internet</textarea>" in text
    sent = json.dumps([r["json"] for r in env["provider"].requests])
    assert "Azarus Group loader" in sent  # the feed's label is evidence
    for secret in (LAPTOP_IP, LAPTOP_MAC, "design-laptop"):
        assert secret not in sent


def test_the_office_file_server_reads_as_dga_and_scan(env, tmp_path):  # noqa: F811
    """The second device of the scene: the model reads the AI IDS event and
    the DNS summary, both carrying what FR_OS's own engine counted."""
    client = _office(env, tmp_path)
    env["provider"].queue = [
        tool("ids_events"), tool("dns_summary"),
        answer(title="File server scans and looks up generated names", severity="high",
               summary="device-1 opened 9 connections a second to new hosts and looked "
                       "up 30 random-looking names that do not exist.",
               evidence=["ids-1", "dns-1"],
               suggested_intent="Cut device-1 off the internet")]
    page = post(client, "/ai-perimeter/explain", {"ip": NAS_IP})
    text = html.unescape(page.text)
    assert ">high</span>" in text
    assert "The severity was raised" not in text
    assert f"Cut nas ({NAS_IP}) off the internet</textarea>" in text
    sent = json.dumps([r["json"] for r in env["provider"].requests])
    assert "DGA-like NXDOMAIN lookups" in sent and "destination-scan pattern" in sent
    for secret in (NAS_IP, NAS_MAC):
        assert secret not in sent


def test_the_office_laptop_cites_the_kernels_sni_drops(env, tmp_path):  # noqa: F811
    """The eBPF/XDP layer in the scene: the loader's retries were dropped in
    the kernel, and the model can read and cite those drops (sni-1). The
    destination address stays out of the request, and the reception PC's
    "pass" line is no evidence at all."""
    client = _office(env, tmp_path)
    env["provider"].queue = [
        tool("tls_fingerprints"), tool("sni_blocks"),
        answer(title="Laptop's loader was stopped in the kernel", severity="high",
               summary="device-1 ran a TLS client the feed lists as an Azarus Group "
                       "loader; the XDP filter dropped its four connections.",
               evidence=["tls-1", "sni-1"],
               suggested_intent="Cut device-1 off the internet")]
    page = post(client, "/ai-perimeter/explain", {"ip": LAPTOP_IP})
    text = html.unescape(page.text)
    assert "<code>sni-1</code>" in page.text
    assert "The severity was raised" not in text
    sent = json.dumps([r["json"] for r in env["provider"].requests])
    assert '"server_name": "update-cdn-checker.example"' in sent.replace('\\"', '"')
    assert '"dropped": 4' in sent.replace('\\"', '"')
    assert "kernel eBPF/XDP filter" in sent
    for secret in (LAPTOP_IP, LAPTOP_MAC, "design-laptop", "203.0.113.10",
                   "office-portal.example"):
        assert secret not in sent


def test_a_corrupt_catalog_still_renders_the_page(screen, sources, monkeypatch):
    """Review2 C11: the suspects page renders (200) with a corrupt catalog,
    degraded to the built-in AI services."""
    from frfw.appid import CatalogError

    def boom():
        raise CatalogError("signature catalog must be an object")

    monkeypatch.setattr("ai_perimeter.incident.evidence.load_catalog", boom)
    page = login(screen).get("/ai-perimeter")
    assert page.status_code == 200
    assert "What did the router see?" in page.text
    assert "kids-tablet" in page.text


def test_bidi_controls_are_stripped_from_names_and_sensor_text(screen, sources):
    """Review2 C19: a U+202E in a device name, a sensor reason and the
    model's own title/summary reaches neither the model payload nor the
    rendered page; the text itself still shows."""
    sources.devices.write_text(json.dumps({"devices": [
        {"mac": TABLET_MAC, "ip": TABLET_IP, "hostname": "kid\u202es-tablet",
         "category": "tablet"}]}))
    ids = json.loads(sources.ids.read_text())
    ids[0]["reasons"].append("talking to evil\u202e.example")
    sources.ids.write_text(json.dumps(ids))
    screen["provider"].queue = [tool("ids_events"),
                                answer(title="Hi\u202ethere",
                                       summary="device-1\u202e did things at night.")]
    page = post(login(screen), "/ai-perimeter/explain", {"ip": TABLET_IP})
    assert page.status_code == 200
    assert "\u202e" not in page.text
    sent = json.dumps([r["json"] for r in screen["provider"].requests])
    assert "\u202e" not in sent
    assert "evil.example" in sent
    text = html.unescape(page.text)
    assert "kids-tablet" in text and "Hithere" in text


def test_the_suggested_intent_names_the_device_for_the_propose_model():
    """Review2 F2, corrected: the pseudonym guards the evidence the
    explaining model reads; the suggested change is for the propose path,
    whose model sees the config's reservations and must be told which
    device is meant, so the box gets the real name, bidi-stripped."""
    from ai_perimeter.webui.routes import _explanation
    view = _explanation(
        {"status": "ready", "title": "t", "severity": "low", "summary": "s",
         "evidence": [], "suggested_intent": "Cut device-1\u202e off the internet"},
        {"sections": {"ai_usage": []}},
        {"device-1": f"kids-tablet ({TABLET_IP})"})
    assert view["suggested_intent"] == f"Cut kids-tablet ({TABLET_IP}) off the internet"
    assert "suggested_intent_shown" not in view
