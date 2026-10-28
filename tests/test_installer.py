"""installer/: the bundle and install.sh.

What can be checked without an FR_OS router is checked here; the install
itself, on a real systemd, is the `install` job in
.github/workflows/tests.yml (install twice, the socket's owner and mode,
who can reach fr-ai-assist, FR_OS's integrity check, uninstall).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "installer"
SCRIPTS = [INSTALLER / "install.sh", INSTALLER / "make-bundle.sh",
           ROOT / "tests" / "integration" / "systemd-install.sh"]


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_shellcheck(script):
    if shutil.which("shellcheck") is None:
        pytest.fail("shellcheck is needed (AGENTS.md: shell scripts pass shellcheck)")
    subprocess.run(["shellcheck", str(script)], check=True)


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_scripts_are_executable_and_strict(script):
    assert os.access(script, os.X_OK)
    assert "\nset -eu\n" in script.read_text()


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp("dist")
    result = subprocess.run([str(INSTALLER / "make-bundle.sh"), str(out)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    tarball = Path(result.stdout.strip().splitlines()[-1])
    unpacked = tmp_path_factory.mktemp("unpacked")
    with tarfile.open(tarball) as tar:
        tar.extractall(unpacked, filter="data")
    return tarball, next(unpacked.iterdir())


def test_the_bundle_holds_the_wheel_units_and_sums(bundle):
    tarball, root = bundle
    files = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    wheel = [f for f in files if f.endswith(".whl")]
    assert len(wheel) == 1
    assert files == sorted(["SHA256SUMS", "install.sh", wheel[0], "systemd/fr-ai-assist.service",
                            "systemd/fr-ai-assist.socket", "systemd/fr-ai-upload.service",
                            "systemd/fr-webui.service.d/ai-perimeter.conf",
                            "patches/conntrack-bytes.patch"])
    subprocess.run(["sha256sum", "--strict", "-c", "SHA256SUMS"], cwd=root, check=True,
                   capture_output=True)
    listed = {line.split("  ", 1)[1] for line in (root / "SHA256SUMS").read_text().splitlines()}
    assert listed == set(files) - {"SHA256SUMS"}
    assert (root / "install.sh").read_bytes() == (INSTALLER / "install.sh").read_bytes()
    assert tarball.with_name(tarball.name + ".sha256").exists()


def test_the_wheel_has_the_templates_and_commands(bundle):
    _tarball, root = bundle
    with zipfile.ZipFile(next(root.glob("*.whl"))) as whl:
        names = whl.namelist()
        entry_points = whl.read(next(n for n in names if n.endswith("entry_points.txt"))).decode()
    assert "ai_perimeter/webui/templates/ai_perimeter.html" in names
    for command in ("fr-ai-assist", "fr-ai-upload", "fr-webui-ai"):
        assert f"{command} = " in entry_points


def test_a_changed_bundle_is_refused(bundle, tmp_path):
    """install.sh checks SHA256SUMS first, before anything else."""
    _tarball, root = bundle
    copy = tmp_path / "bundle"
    shutil.copytree(root, copy)
    unit = copy / "systemd" / "fr-ai-assist.service"
    unit.write_text(unit.read_text().replace("NoNewPrivileges=yes", "NoNewPrivileges=no"))
    sums = subprocess.run(["sha256sum", "--strict", "-c", "SHA256SUMS"], cwd=copy,
                          capture_output=True, text=True)
    assert sums.returncode != 0
    result = subprocess.run([str(copy / "install.sh")], capture_output=True, text=True)
    assert result.returncode == 1
    assert "does not match SHA256SUMS" in result.stderr


def test_outside_fr_os_nothing_is_installed(bundle):
    """A whole bundle, but no FR_OS (or no root): it stops before changing
    anything."""
    _tarball, root = bundle
    result = subprocess.run([str(root / "install.sh")], capture_output=True, text=True)
    assert result.returncode == 1
    assert "run as root" in result.stderr or "not an FR_OS router" in result.stderr


def test_help_and_unknown_arguments():
    help_ = subprocess.run([str(INSTALLER / "install.sh"), "--help"], capture_output=True, text=True)
    assert help_.returncode == 0 and "--uninstall" in help_.stdout and "--purge" in help_.stdout
    assert "--with-upload-bytes" in help_.stdout
    bad = subprocess.run([str(INSTALLER / "install.sh"), "--yes-please"], capture_output=True, text=True)
    assert bad.returncode == 2


def test_with_upload_bytes_outside_fr_os_nothing_is_installed(bundle):
    """With the flag but no FR_OS (or no root): it stops before changing
    anything, like a plain install."""
    _tarball, root = bundle
    result = subprocess.run([str(root / "install.sh"), "--with-upload-bytes"],
                            capture_output=True, text=True)
    assert result.returncode == 1
    assert "run as root" in result.stderr or "not an FR_OS router" in result.stderr


def test_the_bundled_patch_is_the_integration_patch(bundle):
    """The patch install.sh applies is the marked integration patch."""
    _tarball, root = bundle
    bundled = (root / "patches" / "conntrack-bytes.patch").read_bytes()
    assert bundled == (ROOT / "integration" / "fr_os" / "conntrack-bytes.patch").read_bytes()
