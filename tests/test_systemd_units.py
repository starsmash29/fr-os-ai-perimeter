"""security-lessons A1, I1: fr-ai-assist runs unprivileged in a full sandbox.

The same checks FR_OS makes of its own units (FR_OS
tests/test_systemd_sandbox.py), plus what is particular to this service: a
dynamic account, no capability, and a socket only the webUI can reach.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SYSTEMD = Path(__file__).resolve().parent.parent / "systemd"


def section(name: str, wanted: str) -> dict[str, list[str]]:
    current, out = None, {}
    for raw in (SYSTEMD / name).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            current = line
            continue
        if current == wanted:
            key, _, value = line.partition("=")
            out.setdefault(key, []).append(value)
    return out


def one(settings, key):
    values = settings.get(key)
    return values[-1] if values else None


SANDBOX = {
    # FR_OS's EVERYWHERE and STRICT sets.
    "NoNewPrivileges": "yes",
    "ProtectHome": "yes",
    "ProtectKernelLogs": "yes",
    "ProtectClock": "yes",
    "RestrictNamespaces": "yes",
    "RestrictRealtime": "yes",
    "RestrictSUIDSGID": "yes",
    "LockPersonality": "yes",
    "SystemCallArchitectures": "native",
    "PrivateDevices": "yes",
    "ProtectKernelModules": "yes",
    "ProtectControlGroups": "yes",
    "ProtectHostname": "yes",
    "MemoryDenyWriteExecute": "yes",
    "SystemCallErrorNumber": "EPERM",
    # And more, for a service that holds nothing privileged.
    "ProtectSystem": "strict",
    "ProtectKernelTunables": "yes",
    "PrivateTmp": "yes",
    "ProtectProc": "invisible",
    "DynamicUser": "yes",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
}


@pytest.mark.parametrize("key, value", sorted(SANDBOX.items()))
def test_the_service_is_sandboxed(key, value):
    assert one(section("fr-ai-assist.service", "[Service]"), key) == value


def test_the_service_runs_as_no_fixed_account():
    s = section("fr-ai-assist.service", "[Service]")
    assert "User" not in s and "Group" not in s and "SupplementaryGroups" not in s


def test_the_service_has_no_netlink_or_raw_sockets():
    families = one(section("fr-ai-assist.service", "[Service]"),
                   "RestrictAddressFamilies").split()
    assert sorted(families) == ["AF_INET", "AF_INET6", "AF_UNIX"]


def test_the_service_never_writes_outside_its_sandbox():
    s = section("fr-ai-assist.service", "[Service]")
    assert "ReadWritePaths" not in s and "StateDirectory" not in s


def test_the_key_comes_as_a_credential_not_a_readable_file():
    s = section("fr-ai-assist.service", "[Service]")
    assert one(s, "LoadCredential") == "api_key:/etc/fr_os/ai-perimeter/api_key"


def test_the_service_is_off_without_its_settings():
    unit = section("fr-ai-assist.service", "[Unit]")
    assert one(unit, "ConditionPathExists") == "/etc/fr_os/ai-perimeter.yaml"


def test_only_the_webui_can_connect():
    s = section("fr-ai-assist.socket", "[Socket]")
    assert one(s, "SocketMode") == "0660"
    assert one(s, "SocketUser") == "root"
    assert one(s, "SocketGroup") == "fr_os-webui"
    assert one(s, "ListenStream") == "/run/fr_os-ai/assist.sock"


@pytest.mark.skipif(not shutil.which("systemd-analyze"), reason="needs systemd-analyze")
def test_systemd_scores_the_exposure_low():
    out = subprocess.run(
        ["systemd-analyze", "security", "--offline=yes", "--threshold=20",
         str(SYSTEMD / "fr-ai-assist.service")],
        capture_output=True, text=True, check=False)
    line = [l for l in out.stdout.splitlines() if "Overall exposure level" in l]
    assert line, out.stdout + out.stderr
    score = float(line[0].split("level for fr-ai-assist.service:")[1].split()[0])
    assert score <= 2.0, line[0]


# --- the drop-in for FR_OS's fr-webui.service --------------------------------

DROPIN = "fr-webui.service.d/ai-perimeter.conf"


def test_the_webui_dropin_only_changes_the_command():
    """It starts fr-webui-ai instead of fr-webui and nothing else: FR_OS's
    account and sandbox for the webUI stay as FR_OS wrote them (A1, I1)."""
    s = section(DROPIN, "[Service]")
    assert s == {"ExecStart": ["", "fr-webui-ai"]}
    assert section(DROPIN, "[Unit]") == {} and section(DROPIN, "[Install]") == {}


def test_fr_webui_ai_is_a_console_script():
    import tomllib

    pyproject = tomllib.loads((SYSTEMD.parent / "pyproject.toml").read_text())
    assert pyproject["project"]["scripts"]["fr-webui-ai"] == "ai_perimeter.webui.server:main"


# --- fr-ai-upload.service: the opt-in upload-bytes collector ------------------
#
# security-lessons A1, I1: it runs as FR_OS's sensor account (the helper
# already allows that uid the read-only conntrack_sample command) in the
# same sandbox as fr-ai-assist, with no network of its own.

UPLOAD = "fr-ai-upload.service"

UPLOAD_SANDBOX = {
    **{k: v for k, v in SANDBOX.items() if k != "DynamicUser"},
    "User": "fr_os-sensor",
    # Review F1: the totals are group-readable under FR_OS's shared group.
    "Group": "fr_os-feeds",
    "StateDirectory": "fr_os-ai-perimeter",
    "StateDirectoryMode": "0750",
    "IPAddressDeny": "any",
    "UMask": "0027",
}


@pytest.mark.parametrize("key, value", sorted(UPLOAD_SANDBOX.items()))
def test_the_upload_collector_is_sandboxed(key, value):
    assert one(section(UPLOAD, "[Service]"), key) == value


def test_the_upload_collector_has_no_dynamic_account():
    assert "DynamicUser" not in section(UPLOAD, "[Service]")


def test_the_upload_collector_shares_through_the_feeds_group():
    """Review F1: the webUI reads the totals through FR_OS's shared group
    (fr_os-feeds) -- never by putting the sensor account in the webUI's
    group (FR_OS SEC-11)."""
    s = section(UPLOAD, "[Service]")
    assert one(s, "Group") == "fr_os-feeds"
    assert one(s, "User") == "fr_os-sensor"
    assert "SupplementaryGroups" not in s


def test_the_upload_collector_reaches_only_the_helper_socket():
    s = section(UPLOAD, "[Service]")
    assert one(s, "RestrictAddressFamilies").split() == ["AF_UNIX"]
    # No PrivateNetwork: the collector must reach the helper's socket, so the
    # namespace stays; IPAddressDeny keeps it from any IP address instead.
    assert "PrivateNetwork" not in s


def test_the_upload_collector_is_off_unless_accounting_is_on():
    unit = section(UPLOAD, "[Unit]")
    assert one(unit, "ConditionPathExists") == "/etc/sysctl.d/60-ai-perimeter.conf"


def test_fr_ai_upload_is_a_console_script():
    import tomllib

    pyproject = tomllib.loads((SYSTEMD.parent / "pyproject.toml").read_text())
    scripts = pyproject["project"]["scripts"]
    assert scripts["fr-ai-upload"] == "ai_perimeter.upload.collector:main"
    s = section(UPLOAD, "[Service]")
    assert one(s, "ExecStart") == "fr-ai-upload"


@pytest.mark.skipif(not shutil.which("systemd-analyze"), reason="needs systemd-analyze")
def test_systemd_scores_the_upload_exposure_low():
    out = subprocess.run(
        ["systemd-analyze", "security", "--offline=yes", "--threshold=20",
         str(SYSTEMD / UPLOAD)],
        capture_output=True, text=True, check=False)
    line = [l for l in out.stdout.splitlines() if "Overall exposure level" in l]
    assert line, out.stdout + out.stderr
    score = float(line[0].split("level for fr-ai-upload.service:")[1].split()[0])
    assert score <= 2.0, line[0]
