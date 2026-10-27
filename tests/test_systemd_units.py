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
